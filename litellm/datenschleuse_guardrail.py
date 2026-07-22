"""Datenschleuse — eigene Custom-Guardrail-Klasse fuer LiteLLM.

Zweck
-----
Ersetzt den eingebauten ``guardrail: presidio`` von LiteLLM. Der eingebaute
Guardrail buffert bei Streaming-Responses den KOMPLETTEN Antworttext, bevor er
Platzhalter zurueck auf Klartext mapped -> Time-to-first-Token geht verloren,
Streaming fuehlt sich an wie non-streaming.

Diese Klasse haelt stattdessen nur einen kleinen **Sliding-Window-Tail-Puffer**,
sodass echtes Token-Streaming erhalten bleibt, waehrend ueber Chunk-Grenzen
gesplittete Platzhalter trotzdem korrekt erkannt und ersetzt werden.

Architektur-Entscheidungen (siehe ISA.md, Decision 2026-07-22 custom-guardrail)
-------------------------------------------------------------------------------
1. Selbststaendige Klasse. Wir verlassen uns NICHT auf LiteLLMs internes
   Presidio-Guardrail-Metadata-Schema (Key-Name dort nicht offiziell
   dokumentiert). Stattdessen rufen wir Presidio Analyzer SELBST per REST auf
   und verwalten unser EIGENES Platzhalter->Klartext-Mapping in einem eigenen
   Metadata-Key ``request_data["metadata"]["datenschleuse_reid_map"]``.

2. Wir bauen die Maskierung SELBST aus den Analyzer-Ergebnissen, statt den
   Presidio-**Anonymizer**-Service zu benutzen. Grund (verifiziert gegen die
   Presidio-Anonymizer-API): der Standard-``replace``-Operator liefert fuer
   jede Entitaet den generischen Platzhalter ``<PERSON>`` — bei zwei
   verschiedenen Personen also ZWEIMAL ``<PERSON>``. Damit ist eine eindeutige
   Rueck-Zuordnung Platzhalter->Klartext unmoeglich (Re-Identification wuerde
   den falschen Wert einsetzen oder scheitern). Presidio kann ueber die
   REST-API keine durchnummerierten, eindeutigen Platzhalter erzeugen (der
   ``custom``-Operator braucht ein Lambda, das nicht JSON-serialisierbar ist).
   Deshalb erzeugen wir eindeutige Platzhalter ``<ENTITY_TYPE_N>`` selbst.
   Das gibt uns zusaetzlich volle Kontrolle ueber das Platzhalter-Format —
   worauf die Sliding-Window-Logik direkt aufbaut. Der Analyzer (echte
   Presidio-Abhaengigkeit) wird weiterhin genutzt.

3. Fail-closed ueberall: schlaegt die PII-Erkennung fehl (Presidio nicht
   erreichbar / Fehlerantwort), wird der Request GEBLOCKT statt unmaskiert
   durchgelassen. Das ist bestehende Projekt-Konvention (CLAUDE.md).

Sicherheits-Rationale zu Streaming (Fail-closed vs. UX)
-------------------------------------------------------
- Fehler beim MASKIEREN (pre_call) -> Request blocken (sonst PII-Leck).
- Fehler beim RE-IDENTIFIZIEREN (post_call) -> Platzhalter stehen lassen. Das
  ist KEIN Leck (Platzhalter enthalten keine PII), nur eine degradierte UX.
  Deshalb wird post_call defensiv abgefangen und blockt NICHT.
"""

from __future__ import annotations

import copy
import os
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

# httpx ist im offiziellen LiteLLM-Image bereits vorhanden (LiteLLM-Dependency)
# und wird fuer die Presidio-REST-Calls genutzt.
import httpx


# ---------------------------------------------------------------------------
# Basisklasse: in Produktion die echte LiteLLM-CustomGuardrail, im Test-/
# Standalone-Betrieb (litellm nicht installiert) ein leichter Shim, damit die
# reine Re-Identification-Logik ohne LiteLLM-Installation getestet werden kann.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - abhaengig von der Laufzeitumgebung
    from litellm.integrations.custom_guardrail import CustomGuardrail as _GuardrailBase
    _LITELLM_AVAILABLE = True
except Exception:  # pragma: no cover
    _LITELLM_AVAILABLE = False

    class _GuardrailBase:  # minimaler Shim nur fuer Tests / Standalone
        def __init__(self, **kwargs: Any) -> None:
            self.guardrail_name = kwargs.get("guardrail_name", "datenschleuse-reid")


# Key, unter dem wir unser eigenes Platzhalter->Klartext-Mapping ablegen.
REID_MAP_KEY = "datenschleuse_reid_map"

# Sicherheitsmarge (in Zeichen) auf die laengste bekannte Platzhalter-Laenge.
# Siehe ReidStreamProcessor fuer die Begruendung.
DEFAULT_PLACEHOLDER_MARGIN = 10


class DatenschleuseBlocked(Exception):
    """Wird geworfen, wenn fail-closed greift. LiteLLM behandelt eine im
    pre_call-Hook geworfene Exception als Guardrail-Block -> Request wird
    NICHT ans LLM weitergereicht (kein unmaskiertes PII verlaesst das System)."""


# ===========================================================================
# Reine, framework-freie Logik (keine LiteLLM-/Presidio-Abhaengigkeit).
# Genau dieser Teil ist unit-testbar ohne laufenden Container.
# ===========================================================================
def reidentify_full(text: str, mapping: Dict[str, str]) -> str:
    """Ersetzt in ``text`` alle bekannten Platzhalter durch ihre Klartextwerte.

    Fuer den Non-Streaming-Fall: es gibt kein Chunking-Problem, also einfach
    global ersetzen. Laengste Platzhalter zuerst, damit ``<PERSON_1>`` nicht
    faelschlich INNERHALB von ``<PERSON_10>`` matcht.
    """
    if not mapping or not text:
        return text
    for placeholder in sorted(mapping, key=len, reverse=True):
        if placeholder in text:
            text = text.replace(placeholder, mapping[placeholder])
    return text


class Masker:
    """Baut aus Presidio-Analyzer-Ergebnissen den maskierten Text UND das
    eindeutige Platzhalter->Klartext-Mapping.

    Wird ueber mehrere Nachrichten hinweg wiederverwendet, damit derselbe
    Klartextwert (z.B. ein Name in System- UND User-Message) denselben
    Platzhalter bekommt und Platzhalter request-weit eindeutig sind.
    """

    def __init__(self) -> None:
        # Klartext-(Typ,Wert) -> Platzhalter, damit Duplikate denselben
        # Platzhalter teilen.
        self._value_to_placeholder: Dict[Tuple[str, str], str] = {}
        # Zaehler pro Entitaetstyp fuer die Durchnummerierung.
        self._counters: Dict[str, int] = {}
        # Ergebnis-Mapping Platzhalter -> Klartext (das, was gestreamt
        # re-identifiziert wird).
        self.reid_map: Dict[str, str] = {}

    def mask(self, text: str, entities: List[Dict[str, Any]]) -> str:
        """Maskiert ``text`` anhand der Analyzer-Entities und aktualisiert das
        Mapping. Gibt den maskierten Text zurueck.

        ``entities``: Liste von Dicts mit mindestens ``entity_type``, ``start``,
        ``end`` (Presidio-``/analyze``-Response-Format).
        """
        if not text or not entities:
            return text

        kept = self._resolve_overlaps(entities, len(text))

        # 1) Platzhalter vergeben in aufsteigender Startposition -> stabile,
        #    deterministische Nummerierung (<TYPE_0>, <TYPE_1>, ...).
        for ent in sorted(kept, key=lambda e: e["start"]):
            original = text[ent["start"]:ent["end"]]
            self._placeholder_for(ent["entity_type"], original)

        # 2) Ersetzen in ABSTEIGENDER Startposition, damit die Indizes der noch
        #    nicht ersetzten Spans gueltig bleiben.
        for ent in sorted(kept, key=lambda e: e["start"], reverse=True):
            original = text[ent["start"]:ent["end"]]
            placeholder = self._placeholder_for(ent["entity_type"], original)
            text = text[:ent["start"]] + placeholder + text[ent["end"]:]

        return text

    def _placeholder_for(self, entity_type: str, original: str) -> str:
        key = (entity_type, original)
        placeholder = self._value_to_placeholder.get(key)
        if placeholder is None:
            n = self._counters.get(entity_type, 0)
            placeholder = f"<{entity_type}_{n}>"
            self._counters[entity_type] = n + 1
            self._value_to_placeholder[key] = placeholder
            self.reid_map[placeholder] = original
        return placeholder

    @staticmethod
    def _resolve_overlaps(entities: List[Dict[str, Any]], text_len: int) -> List[Dict[str, Any]]:
        """Presidio kann ueberlappende Treffer liefern (z.B. PERSON und
        LOCATION auf demselben Span). Wir behalten pro Position den Treffer mit
        dem hoechsten Score und lassen ueberlappende, schwaechere fallen.
        """
        valid = [
            e for e in entities
            if isinstance(e.get("start"), int)
            and isinstance(e.get("end"), int)
            and 0 <= e["start"] < e["end"] <= text_len
            and e.get("entity_type")
        ]
        # Hoher Score zuerst, dann laengerer Span, dann fruehere Position.
        valid.sort(key=lambda e: (-float(e.get("score", 0.0)), -(e["end"] - e["start"]), e["start"]))
        kept: List[Dict[str, Any]] = []
        for e in valid:
            if any(not (e["end"] <= k["start"] or e["start"] >= k["end"]) for k in kept):
                continue  # ueberlappt einen bereits behaltenen, staerkeren Treffer
            kept.append(e)
        return kept


class ReidStreamProcessor:
    """Sliding-Window-Re-Identification fuer Streaming-Chunks.

    Problem: ein Platzhalter wie ``<PERSON_1>`` kann ueber zwei SSE-Chunks
    gesplittet ankommen (z.B. ``<PERS`` | ``ON_1>``). Wir duerfen keinen Text
    emittieren, der der ANFANG eines noch nicht vollstaendig angekommenen
    Platzhalters sein koennte.

    Loesung: wir puffern nur einen kleinen Tail. Fensterlaenge ``window`` =
    laengster bekannter Platzhalter + Sicherheitsmarge. Wir emittieren pro
    Chunk alles AUSSER den letzten ``window - 1`` Zeichen.

    Warum ``window - 1``? Der laengste Platzhalter hat ``max_len`` Zeichen. Ein
    Platzhalter, der NICHT vollstaendig im Puffer steht, hat weniger als
    ``max_len`` Zeichen -> sein Anfang liegt zwangslaeufig innerhalb der letzten
    ``max_len - 1`` Zeichen. Halten wir diese zurueck, kann nie ein
    Platzhalter-Anfang faelschlich als normaler Text emittiert werden. Die
    Marge (+10) ist defensiver Puffer gegen Off-by-one und kuenftig laengere
    Platzhalter — mehr zurueckzuhalten ist immer sicher, kostet nur minimal
    Latenz.
    """

    def __init__(self, mapping: Dict[str, str], margin: int = DEFAULT_PLACEHOLDER_MARGIN) -> None:
        self.mapping = mapping or {}
        # Laengste Platzhalter zuerst ersetzen (<PERSON_1> vs. <PERSON_10>).
        self._keys = sorted(self.mapping, key=len, reverse=True)
        max_len = max((len(k) for k in self.mapping), default=0)
        self.window = (max_len + margin) if max_len else 0
        self.buffer = ""

    def feed(self, delta: str) -> str:
        """Nimmt ein Text-Delta an und gibt den JETZT sicher emittierbaren Text
        zurueck (kann leer sein)."""
        if not self.mapping:
            # Keine Platzhalter -> nichts zu re-identifizieren, unveraendert und
            # ungepuffert durchreichen (voller Streaming-Speed).
            return delta or ""
        if delta:
            self.buffer += delta
        self.buffer = self._replace_complete(self.buffer)

        hold = self.window - 1  # potenzieller Platzhalter-Anfang -> zurueckhalten
        if len(self.buffer) > hold:
            cut = len(self.buffer) - hold
            emit, self.buffer = self.buffer[:cut], self.buffer[cut:]
            return emit
        return ""

    def flush(self) -> str:
        """Am Stream-Ende: kompletten Rest-Puffer (final ersetzt) ausgeben,
        damit kein Text verloren geht — auch wenn er kuerzer als das Fenster
        ist."""
        rest = self._replace_complete(self.buffer)
        self.buffer = ""
        return rest

    def _replace_complete(self, s: str) -> str:
        for k in self._keys:
            if k in s:
                s = s.replace(k, self.mapping[k])
        return s


# ===========================================================================
# LiteLLM-Adapter: verbindet die reine Logik oben mit den LiteLLM-Hooks.
# ===========================================================================
class DatenschleuseGuardrail(_GuardrailBase):
    """Custom Guardrail: maskiert PII vor dem LLM (pre_call) und
    re-identifiziert die Antwort streaming-sicher (post_call)."""

    def __init__(
        self,
        presidio_analyzer_url: Optional[str] = None,
        language: str = "de",
        score_threshold: float = 0.0,
        placeholder_margin: int = DEFAULT_PLACEHOLDER_MARGIN,
        request_timeout: float = 10.0,
        **kwargs: Any,
    ) -> None:
        # Analyzer-URL: Prioritaet Argument > ENV > Docker-Default.
        self.analyzer_url = (
            presidio_analyzer_url
            or os.getenv("PRESIDIO_ANALYZER_API_BASE")
            or "http://presidio-analyzer:3000"
        ).rstrip("/")
        # Manche Config-/ENV-Wege liefern die Werte via kwargs nach — defensiv.
        self.language = kwargs.pop("presidio_language", None) or language
        self.score_threshold = float(kwargs.pop("presidio_score_threshold", score_threshold) or 0.0)
        self.placeholder_margin = int(placeholder_margin)
        self.request_timeout = float(request_timeout)
        super().__init__(**kwargs)

    # ---- Presidio Analyzer (echte externe Abhaengigkeit) ------------------
    async def _analyze(self, text: str) -> List[Dict[str, Any]]:
        """Ruft Presidio Analyzer ``/analyze`` auf. Fail-closed: jeder Fehler
        (Netzwerk, HTTP >= 400, ungueltige Antwort) wird zu DatenschleuseBlocked
        eskaliert, damit KEIN unmaskierter Text durchgeht."""
        if not text or not text.strip():
            return []
        payload: Dict[str, Any] = {"text": text, "language": self.language}
        if self.score_threshold > 0:
            payload["score_threshold"] = self.score_threshold
        try:
            async with httpx.AsyncClient(timeout=self.request_timeout) as client:
                resp = await client.post(f"{self.analyzer_url}/analyze", json=payload)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, list):
                raise ValueError(f"unerwartete Analyzer-Antwort: {type(data)!r}")
            return data
        except DatenschleuseBlocked:
            raise
        except Exception as exc:  # fail-closed
            raise DatenschleuseBlocked(
                f"Presidio Analyzer nicht erreichbar/fehlerhaft ({exc}); "
                f"Request blockiert (fail-closed, kein unmaskiertes PII)."
            ) from exc

    # ---- Pre-Call: PII maskieren ------------------------------------------
    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict:
        """Maskiert PII in allen Chat-Messages und legt das Re-Id-Mapping in
        den Metadaten ab. Nur fuer Chat-/Text-Completions relevant."""
        if call_type not in ("completion", "text_completion", "acompletion", None):
            return data

        messages = data.get("messages")
        masker = Masker()

        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                content = msg.get("content")
                if isinstance(content, str):
                    entities = await self._analyze(content)
                    msg["content"] = masker.mask(content, entities)
                elif isinstance(content, list):
                    # Multimodal: nur Text-Parts maskieren.
                    for part in content:
                        if (
                            isinstance(part, dict)
                            and part.get("type") == "text"
                            and isinstance(part.get("text"), str)
                        ):
                            entities = await self._analyze(part["text"])
                            part["text"] = masker.mask(part["text"], entities)

        # Mapping im EIGENEN Metadata-Key ablegen (nicht LiteLLMs Interna).
        metadata = data.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
            data["metadata"] = metadata
        metadata[REID_MAP_KEY] = masker.reid_map
        return data

    # ---- Post-Call Streaming: streaming-sichere Re-Identification ---------
    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict,
    ) -> AsyncGenerator[Any, None]:
        """Ersetzt Platzhalter in Streaming-Chunks mit einem Sliding-Window,
        sodass echtes Token-Streaming erhalten bleibt."""
        reid_map = self._read_reid_map(request_data)
        processor = ReidStreamProcessor(reid_map, margin=self.placeholder_margin)

        last_content_chunk = None
        try:
            async for chunk in response:
                content = self._extract_delta(chunk)
                if content is None:
                    # Chunk ohne Text-Delta (role-only, finish_reason, usage) ->
                    # unveraendert durchreichen.
                    yield chunk
                    continue
                emit = processor.feed(content)
                # delta.content wird auf den sicher emittierbaren Teil gesetzt
                # (kann "" sein) — Chunk bleibt ein gueltiges ModelResponseStream.
                self._set_delta(chunk, emit)
                last_content_chunk = chunk
                yield chunk
        finally:
            # Rest-Puffer am Stream-Ende ausgeben, damit kein Text verloren geht.
            tail = processor.flush()
            if tail and last_content_chunk is not None:
                # Struktur eines echten Content-Chunks klonen (versionsagnostisch,
                # ohne LiteLLM-Typen konstruieren zu muessen) und Rest anhaengen.
                final_chunk = copy.deepcopy(last_content_chunk)
                self._set_delta(final_chunk, tail)
                self._clear_finish_reason(final_chunk)
                yield final_chunk

    # ---- Post-Call Non-Streaming: einfacher Voll-Ersatz -------------------
    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: Any,
        response: Any,
    ) -> Any:
        """Re-Identification fuer nicht-gestreamte Responses. Kein
        Sliding-Window noetig (kein Chunking). Fehler hier sind KEIN Leck
        (Platzhalter bleiben stehen) -> nicht fail-closed blocken."""
        reid_map = self._read_reid_map(data)
        if not reid_map:
            return response
        try:
            choices = getattr(response, "choices", None)
            if choices is None and isinstance(response, dict):
                choices = response.get("choices")
            for choice in choices or []:
                message = getattr(choice, "message", None)
                if message is None and isinstance(choice, dict):
                    message = choice.get("message")
                if message is None:
                    continue
                content = getattr(message, "content", None)
                if content is None and isinstance(message, dict):
                    content = message.get("content")
                if isinstance(content, str):
                    new_content = reidentify_full(content, reid_map)
                    if isinstance(message, dict):
                        message["content"] = new_content
                    else:
                        message.content = new_content
        except Exception:
            # Bewusst still: Platzhalter im Output sind sicher (kein PII-Leck).
            return response
        return response

    # ---- Metadata-/Chunk-Helfer -------------------------------------------
    @staticmethod
    def _read_reid_map(request_data: Any) -> Dict[str, str]:
        """Liest das Re-Id-Mapping robust aus den Request-Metadaten.

        LiteLLM propagiert Metadaten je nach Version unter ``metadata`` oder
        ``litellm_metadata`` — beide werden geprueft. Genaue Propagation ist
        gegen die laufende LiteLLM-Version zu verifizieren.
        """
        if not isinstance(request_data, dict):
            return {}
        for meta_key in ("metadata", "litellm_metadata"):
            meta = request_data.get(meta_key)
            if isinstance(meta, dict) and isinstance(meta.get(REID_MAP_KEY), dict):
                return meta[REID_MAP_KEY]
        # Fallback: direkt im request_data (manche Codepfade flatten Metadaten).
        if isinstance(request_data.get(REID_MAP_KEY), dict):
            return request_data[REID_MAP_KEY]
        return {}

    @staticmethod
    def _extract_delta(chunk: Any) -> Optional[str]:
        """Holt ``choices[0].delta.content`` aus einem Chunk. Gibt None zurueck,
        wenn kein Text-Delta vorhanden ist (dann Chunk unveraendert lassen)."""
        try:
            choices = getattr(chunk, "choices", None)
            if choices is None and isinstance(chunk, dict):
                choices = chunk.get("choices")
            if not choices:
                return None
            first = choices[0]
            delta = getattr(first, "delta", None)
            if delta is None and isinstance(first, dict):
                delta = first.get("delta")
            if delta is None:
                return None
            content = getattr(delta, "content", None)
            if content is None and isinstance(delta, dict):
                content = delta.get("content")
            return content if isinstance(content, str) else None
        except Exception:
            return None

    @staticmethod
    def _set_delta(chunk: Any, value: str) -> None:
        """Setzt ``choices[0].delta.content`` auf ``value``."""
        choices = getattr(chunk, "choices", None)
        if choices is None and isinstance(chunk, dict):
            choices = chunk.get("choices")
        if not choices:
            return
        first = choices[0]
        delta = getattr(first, "delta", None)
        if delta is None and isinstance(first, dict):
            delta = first.get("delta")
        if delta is None:
            return
        if isinstance(delta, dict):
            delta["content"] = value
        else:
            delta.content = value

    @staticmethod
    def _clear_finish_reason(chunk: Any) -> None:
        """Setzt finish_reason des geklonten Final-Chunks auf None (der Chunk,
        den wir klonen, war ein Mitten-im-Stream-Chunk und soll den Stream nicht
        vorzeitig beenden)."""
        choices = getattr(chunk, "choices", None)
        if choices is None and isinstance(chunk, dict):
            choices = chunk.get("choices")
        if not choices:
            return
        first = choices[0]
        if isinstance(first, dict):
            first["finish_reason"] = None
        elif hasattr(first, "finish_reason"):
            first.finish_reason = None
