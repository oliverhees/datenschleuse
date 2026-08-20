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

import base64
import contextvars
import copy
import hashlib
import hmac
import json
import logging
import os
import re
from typing import Any, AsyncGenerator, Dict, List, NamedTuple, Optional, Tuple

# httpx ist im offiziellen LiteLLM-Image bereits vorhanden (LiteLLM-Dependency)
# und wird fuer die Presidio-REST-Calls genutzt.
import httpx

# Reine Quasi-Identifier-Logik (keine Fremd-Abhaengigkeit, immer importierbar).
# Der zustandsbehaftete, verschluesselte Store (qi_state) wird erst LAZY im
# Konstruktor importiert -- nur wenn das QI-Feature aktiv ist -- damit dieses
# Modul weiterhin ohne `cryptography` standalone importier-/testbar bleibt.
import qi_generalization as qig

# Schutzklassen-Modell (Community-Feedback, siehe ISA.md Decision 2026-07-23):
# 3-Stufen-Sensitivitaetsklassifizierung VOR jeder Maskierung. Stufe 3 ist eine
# HARTE Code-Garantie (nie Cloud, auch nicht anonymisiert), keine Konfigurations-
# option -- deshalb IMMER aktiv, anders als der optionale QI-Layer. Reine Logik,
# keine LiteLLM-/Presidio-Laufzeitabhaengigkeit (nur PyYAML zum Config-Laden).
import sensitivity_classifier as sc


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
        #: Nachbau von litellms PRE_CALL_EXECUTED_GUARDRAILS_KEY
        #: (integrations/custom_guardrail.py). Der Shim muss die
        #: Marker-Semantik tragen, sonst testet der Deployment-Pfad eine
        #: Mechanik, die es in Produktion so nicht gibt.
        _EXECUTED_KEY = "pre_call_executed_guardrails"

        def __init__(self, **kwargs: Any) -> None:
            self.guardrail_name = kwargs.get("guardrail_name", "datenschleuse-reid")

        def _pre_call_marker(self) -> Optional[str]:
            name = getattr(self, "guardrail_name", None)
            return f"pre_call_executed:{name}" if name else None

        def mark_pre_call_hook_ran(self, data: Dict[str, Any]) -> None:
            marker = self._pre_call_marker()
            if marker is None:
                return
            for meta_key in ("metadata", "litellm_metadata"):
                meta = data.get(meta_key)
                if isinstance(meta, dict):
                    executed = meta.get(self._EXECUTED_KEY)
                    if isinstance(executed, list):
                        if marker not in executed:
                            executed.append(marker)
                    else:
                        meta[self._EXECUTED_KEY] = [marker]
                    return
            data["metadata"] = {self._EXECUTED_KEY: [marker]}

        def _pre_call_hook_already_ran(self, data: Dict[str, Any]) -> bool:
            marker = self._pre_call_marker()
            if marker is None:
                return False
            for meta_key in ("metadata", "litellm_metadata"):
                meta = data.get(meta_key)
                if isinstance(meta, dict):
                    executed = meta.get(self._EXECUTED_KEY)
                    if isinstance(executed, list) and marker in executed:
                        return True
            return False

        async def async_pre_call_deployment_hook(
            self, kwargs: Dict[str, Any], call_type: Any
        ) -> Optional[dict]:
            """Nachbau der Vorbedingungen aus
            integrations/custom_guardrail.py:641-676."""
            if not isinstance(kwargs.get("guardrails"), list):
                return kwargs
            if self._pre_call_hook_already_ran(kwargs):
                return kwargs
            roh = getattr(call_type, "value", call_type)
            if roh not in ("completion", "acompletion"):
                return kwargs
            return await self.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=kwargs, call_type=roh
            )


# Key, unter dem wir unser eigenes Platzhalter->Klartext-Mapping ablegen.
REID_MAP_KEY = "datenschleuse_reid_map"

# ===========================================================================
# Re-Id-Mapping: versiegelter Transport (DATENSCHLE-69, Security-F4)
# ===========================================================================
# Das Mapping ist die vollstaendige Zuordnung Platzhalter -> ORIGINALWERT und
# damit das dichteste PII-Objekt im ganzen Request -- dichter als der Payload,
# weil es die Werte ohne umgebenden Text auflistet.
#
# Es lag bisher als Klartext-dict in ``metadata``. ``metadata`` ist aber KEIN
# privater Kanal: litellm reicht es an seine Logging-Callbacks weiter
# (StandardLoggingPayload, langfuse, s3, datadog ...). Damit stand die
# Klartext-Tabelle im Log -- gegen Gesetz 5 und gegen die Zusage in
# CLAUDE.md: "Mapping verschluesselt + lokal + TTL".
#
# WARUM DAS AUCH DEN SNAPSHOT-BEFUND (F1) SCHLIESST: litellms
# Logging-Schnappschuss ist eine FLACHE Kopie und haelt dieselbe
# ``metadata``-Referenz. Alles, was wir dort hineinlegen, steht sofort auch
# im Schnappschuss -- egal, wie sorgfaeltig der Neubau ihn behandelt. Man
# kann das Symptom behandeln (beim Neubau flach kopieren und den Key
# herausnehmen); dann bleibt der Kanal zu den Callbacks offen. Oder man legt
# den Klartext gar nicht erst hinein. Das hier ist die zweite Variante.
#
# VORBILD: ``QiStateStore`` (litellm/qi_state.py) macht dasselbe fuer den
# QI-Session-State -- Fernet, lokaler Schluessel, TTL.
#
# BEWUSST KEIN STORE: der QI-State ist sessionuebergreifend und braucht
# deshalb SQLite. Das Re-Id-Mapping ist REQUEST-gebunden -- es lebt vom
# pre_call bis zum Ende der (ggf. gestreamten) Antwort und wird danach nie
# wieder gebraucht. Ein Store waere hier zusaetzliche Mechanik mit eigener
# Ablauf- und Aufraeum-Logik, also eine neue Fehlerquelle. Das versiegelte
# Token reist im Request selbst mit; Fernet traegt den Zeitstempel in sich
# und prueft die TTL beim Oeffnen. Nichts zum Aufraeumen, nichts, was
# volllaufen kann.
REID_KEY_ENV = "DATENSCHLEUSE_REID_KEY"
REID_TTL_ENV = "DATENSCHLEUSE_REID_TTL"

#: Lebensdauer eines versiegelten Mappings. Grosszuegig genug fuer lange
#: Streaming-Antworten, kurz genug, dass ein abgefangenes Token nicht
#: dauerhaft brauchbar ist. Deutlich kuerzer als die 24 h des QI-States --
#: das Mapping wird nur waehrend EINER Antwort gebraucht.
DEFAULT_REID_TTL_SECONDS = 60 * 60  # 1 h

_REID_FERNET = None
_REID_TTL = None


def configure_reid_crypto():
    """Prueft und uebernimmt die Re-Id-Krypto-Konfiguration. Beim START.

    Wird vom Konstruktor der Guardrail aufgerufen -- ein fehlerhafter
    Schluessel oder eine unsinnige TTL bricht damit den Start ab, statt bei
    jedem Request zu werfen (bzw. still jede Re-Identifikation abzuschalten).

    Ohne gesetzten Schluessel wird EINMALIG einer erzeugt. Das bleibt die
    bewusste Vorgabe -- das Mapping ist request-gebunden und muss keinen
    Neustart ueberleben. Es darf nur kein UNBEMERKTER Zustand sein, deshalb
    die Warnung: ein Neustart entwertet offene Mappings, und mehrere Worker
    teilen keinen Schluessel. Beides faellt sonst erst im Betrieb auf, als
    scheinbar zufaelliges Fehlschlagen der Re-Identifikation.
    """
    global _REID_FERNET, _REID_TTL

    # --- TTL zuerst: rein rechnerisch, braucht kein cryptography ---------
    roh_ttl = os.getenv(REID_TTL_ENV)
    if roh_ttl is None or roh_ttl == "":
        _REID_TTL = DEFAULT_REID_TTL_SECONDS
    else:
        try:
            ttl = int(roh_ttl)
        except (TypeError, ValueError):
            raise DatenschleuseConfigError(
                f"{REID_TTL_ENV} ist keine ganze Zahl. Erwartet wird eine "
                "Lebensdauer in Sekunden (z.B. 3600). Ein stiller Rueckfall "
                "auf die Vorgabe waere gefaehrlicher als der Abbruch: ein "
                "Tippfehler wuerde unbemerkt etwas anderes tun."
            )
        if ttl <= 0:
            raise DatenschleuseConfigError(
                f"{REID_TTL_ENV} muss groesser als 0 sein (war: {ttl}). Ein "
                "Wert <= 0 schaltet die Re-Identifikation faktisch ab -- "
                "jede Antwort behielte ihre Platzhalter, ohne eine einzige "
                "Meldung. Anmerkung: 0 wirkt bei Fernet ausserdem NICHT wie "
                "'sofort abgelaufen' (verglichen wird zeitstempel + ttl < "
                "jetzt), meint also etwas anderes als es tut."
            )
        _REID_TTL = ttl

    # --- Schluessel ------------------------------------------------------
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise DatenschleuseConfigError(
            "Das Paket 'cryptography' fehlt. Es ist eine harte "
            "Laufzeit-Abhaengigkeit (siehe requirements-guardrail.txt): ohne "
            "es kann das Re-Id-Mapping nicht verschluesselt transportiert "
            "werden, und unverschluesselt laeuft es nicht (fail-closed)."
        ) from exc

    roh_key = os.getenv(REID_KEY_ENV)
    if roh_key:
        try:
            _REID_FERNET = Fernet(
                roh_key.encode() if isinstance(roh_key, str) else roh_key
            )
        except Exception as exc:
            raise DatenschleuseConfigError(
                f"{REID_KEY_ENV} ist kein gueltiger Fernet-Key (erwartet 32 "
                f"url-safe base64 Bytes): {exc}. Erzeugen mit: python -c "
                '"from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            ) from exc
    else:
        _REID_FERNET = Fernet(Fernet.generate_key())
        _LOG.warning(
            "%s ist nicht gesetzt -- es wird ein PROZESSLOKALER Schluessel "
            "fuer das Re-Id-Mapping erzeugt. Folgen: ein Neustart entwertet "
            "alle offenen Mappings, und mehrere Worker teilen keinen "
            "Schluessel (die Re-Identifikation schlaegt dann scheinbar "
            "zufaellig fehl). Fuer den Einzelprozess-Betrieb ist das die "
            "sicherere Wahl -- ein altes Log bleibt endgueltig unaufloesbar. "
            "Wer mehrere Worker faehrt, setzt %s.",
            REID_KEY_ENV,
            REID_KEY_ENV,
        )


def _reid_fernet():
    """Der Fernet-Schluessel fuer das Mapping -- lazy und prozesslokal.

    Schluesselherkunft, in dieser Reihenfolge:

    1. ``DATENSCHLEUSE_REID_KEY``, falls der Betreiber ihn setzt.
    2. Sonst: EINMALIG beim ersten Gebrauch erzeugt, nur im Prozess-Speicher.

    Warum ein erzeugter Schluessel hier die richtige Vorgabe ist und kein
    fail-closed wie beim QI-Store: das Mapping muss NICHT ueber einen
    Neustart hinweg lesbar sein. Ein prozesslokaler Zufallsschluessel ist
    fuer request-gebundene Daten sogar die STAERKERE Eigenschaft -- ein Log,
    das nach einem Neustart gelesen wird, ist endgueltig nicht mehr
    aufloesbar. Und er kostet den Betreiber keine Schluesselverwaltung fuer
    etwas, das eine Stunde lebt.

    Der Import ist lazy, damit das Modul ohne ``cryptography`` importierbar
    bleibt (die Test-Suite laeuft ohne litellm; das Paket selbst ist in
    requirements-guardrail.txt eine harte Laufzeit-Abhaengigkeit). Fehlt es
    zur Laufzeit, schlaegt das Versiegeln fehl und der Request blockt --
    fail-closed, kein unverschluesselter Weiterbetrieb.
    """
    if _REID_FERNET is None:
        # Direktnutzung ohne Guardrail-Instanz (Tests, Hilfsskripte).
        configure_reid_crypto()
    return _REID_FERNET


def _reid_ttl_seconds() -> int:
    """Die validierte TTL. Geprueft wurde beim START (configure_reid_crypto)
    -- hier wird nicht mehr geraten."""
    if _REID_TTL is None:
        configure_reid_crypto()
    return _REID_TTL


def seal_reid_map(reid_map: Dict[str, str]) -> str:
    """Versiegelt das Mapping fuer den Transport durch fremde Kanaele.

    Rueckgabe ist ein Fernet-Token (str). Wer es in einem Log findet -- und
    genau dort landet es, das ist der Punkt --, hat eine Zeichenkette ohne
    Schluessel.
    """
    klartext = json.dumps(reid_map, ensure_ascii=False).encode("utf-8")
    return _reid_fernet().encrypt(klartext).decode("ascii")


def open_reid_map(value: Any, ttl_seconds: Optional[int] = None) -> Dict[str, str]:
    """Oeffnet ein versiegeltes Mapping. Im Zweifel LEER.

    Akzeptiert ausschliesslich die versiegelte Form. Ein Klartext-dict wird
    NICHT mehr angenommen: beide Formen zu akzeptieren waere ein Kanal, den
    niemand mehr benutzt, aber jeder noch benutzen KANN -- und ein
    client-gesetztes Mapping waere eine Steuerung der Antwort durch den
    Kontrollierten (dieselbe Klasse Befund wie die Client-Freigabe in F2).

    FEHLERRICHTUNG: laesst sich das Token nicht oeffnen (falscher Schluessel,
    abgelaufen, beschaedigt), gibt es KEIN Mapping -- die Antwort behaelt
    ihre Platzhalter. Unschoen, aber sicher. Die gefaehrliche Richtung waere
    ein Rueckfall auf einen ungeschuetzten Kanal.
    """
    if not isinstance(value, str) or not value:
        return {}
    ttl = _reid_ttl_seconds() if ttl_seconds is None else int(ttl_seconds)
    try:
        roh = _reid_fernet().decrypt(value.encode("ascii"), ttl=ttl)
        geoeffnet = json.loads(roh.decode("utf-8"))
    except Exception:
        # Bewusst ohne Wert im Log (Gesetz 5) und ohne Grund-Detail: die
        # Unterscheidung "abgelaufen" vs. "gefaelscht" hilft nur einem
        # Angreifer.
        return {}
    if not isinstance(geoeffnet, dict):
        return {}
    return {
        str(k): str(v)
        for k, v in geoeffnet.items()
        if isinstance(k, str) and isinstance(v, str)
    }

# Sicherheitsmarge (in Zeichen) auf die laengste bekannte Platzhalter-Laenge.
# Siehe ReidStreamProcessor fuer die Begruendung.
DEFAULT_PLACEHOLDER_MARGIN = 10

# Umgang mit Bild-Parts in multimodalen Nachrichten. Siehe Konstruktor.
IMAGE_POLICIES = ("redact", "block", "pass")


# ===========================================================================
# CALL-TYPE-REGISTER (DATENSCHLE-69) -- die OBERSTE Ebene: die Route
# ===========================================================================
# Dieselbe Bauart-Luecke gab es inzwischen viermal, jedes Mal eine Ebene
# tiefer entdeckt: Part-Ebene (DATENSCHLE-57), content-Container
# (DATENSCHLE-64), Part-Felder (DATENSCHLE-65), Message-Felder
# (DATENSCHLE-66). Ursache jedes Mal dieselbe: gelesen wurde, was man kannte,
# alles Uebrige lief still durch. Hier ist die letzte, oberste Ebene -- die
# ROUTE selbst. Vorher stand die Entscheidung als anonymes Tupel im
# Funktionsrumpf und lieferte bei Nicht-Treffer ``data`` UNVERAENDERT zurueck:
# kein Maskieren, kein Block, kein Fehler. Wer die Datenschleuse ueber eine
# nicht gelistete Route ansprach, war komplett ungeschuetzt und merkte es
# nicht -- "Schutz abwesend bei zugesichertem Schutz".
#
# Ab hier gilt dasselbe Prinzip wie beim Message-Feld-Register: jeder
# call_type steht in genau einer Liste. Was in keiner steht, ist unbekannt
# und blockt fail-closed. Eine neue litellm-Route zwingt damit zu einer
# BEWUSSTEN Entscheidung (Eintrag ins Register) statt lautlos ein Leck zu
# oeffnen.
#
# WICHTIG -- warum eine Route nicht allein am Namen haengt: der call_type sagt
# nur, WELCHE Route spricht, nicht WIE ihr Payload aussieht. Eine Route als
# "unterstuetzt" zu markieren, ohne ihre Struktur tatsaechlich zu maskieren,
# waere derselbe Fehler noch einmal, nur dokumentiert falsch. Deshalb prueft
# jeder unterstuetzte Pfad zusaetzlich die FORM seines Payloads und blockt,
# wenn sie nicht passt (_validate_call_type / _mask_text_prompt).
#
# Empirisch gegen litellm 1.97.0 nachgelesen (nicht geraten), Quellen:
#   proxy/common_request_processing.py:1432  pre_call_hook(call_type=route_type)
#   proxy/proxy_server.py:9353               route_type="acompletion"
#   proxy/proxy_server.py:9509               route_type="atext_completion"
#   proxy/anthropic_endpoints/endpoints.py:101      "anthropic_messages"
#   proxy/response_api_endpoints/endpoints.py:341   "aresponses"
#   integrations/custom_guardrail.py:670     "completion"/"acompletion"
#   proxy/pass_through_endpoints/...py:227   "text_completion"
#
# 1) CHAT-MESSAGES: Payload ist eine OpenAI-Chat-Completion, der Anwendertext
#    steht in ``messages[]``. Das ist der Pfad, den die Guardrail seit jeher
#    vollstaendig beherrscht (Message-Feld-Register, Part-Register, QI-Layer,
#    Re-Identifikation auf dem Rueckweg).
#    - ``acompletion``: /v1/chat/completions am Proxy.
#    - ``completion``:  kommt AUSSCHLIESSLICH aus
#      ``CustomGuardrail.async_pre_call_deployment_hook``
#      (integrations/custom_guardrail.py:668 reicht bei
#      ``CallTypes.completion`` den String ``"completion"`` weiter).
#
#      KORREKTUR des alten Kommentars (DATENSCHLE-69, Security-F3). Hier stand
#      "synchroner Pfad ... KEIN toter Eintrag" -- eine Behauptung ueber eine
#      Route, deren Payload-FORM nie gemessen wurde. Genau die Verwechslung,
#      die der Kasten weiter oben verbietet.
#
#      GEMESSEN gegen 1.97.0:
#        * ``litellm.completion`` ist KEINE Coroutine und laeuft durch den
#          synchronen ``wrapper`` (utils.py:1256). Der ruft
#          ``async_pre_call_deployment_hook`` NIE auf -- das tut nur
#          ``wrapper_async`` (utils.py:1558) an :1587, mit
#          ``call_type = original_function.__name__``. Aus dem synchronen
#          ``litellm.completion`` entsteht also nie ein
#          ``CallTypes.completion``. Der alte Kommentar war insofern falsch.
#        * Erreicht der Dispatcher trotzdem ``CallTypes.completion``, kommt
#          der String korrekt bei uns an. Der Eintrag ist also nicht tot --
#          nur anders belegt als behauptet.
#        * Der Payload ist dort NICHT ein blanker Chat-Body, sondern
#          router-aufgeloeste Deployment-kwargs. Ungeprueft blockten die hart:
#          "Payload enthaelt 6 Top-Level-Feld(er) ..." -- fail-closed, aber
#          Totalausfall. Deshalb PAYLOAD_FIELDS_DEPLOYMENT (siehe dort).
CALL_TYPES_CHAT_MESSAGES = (
    "acompletion",
    "completion",
)

# 2) TEXT-PROMPT: Payload traegt den Anwendertext in EINEM Feld, ``prompt``.
#    - ``atext_completion``: /v1/completions am Proxy (Legacy Completions).
#      Die alte Liste enthielt ``"text_completion"`` -- das trifft diese Route
#      NICHT, der Proxy uebergibt hier ``atext_completion``. Genau daran lief
#      /v1/completions bislang komplett an der Maskierung vorbei.
CALL_TYPES_TEXT_PROMPT = ("atext_completion",)

ALLOWED_CALL_TYPES = frozenset(CALL_TYPES_CHAT_MESSAGES + CALL_TYPES_TEXT_PROMPT)

# 3) BEKANNT, ABER NICHT GEPRUEFT. Diese call_types kommen in litellm 1.97.0
#    real vor -- wir behandeln sie (noch) nicht. Sie blocken wie jeder
#    unbekannte call_type, werden in der Meldung aber beim Namen genannt,
#    damit ein Betreiber sofort weiss, woran er ist. Die Namen stammen aus
#    dieser konstanten Liste, NIE aus dem Request (Gesetz 5).
#
#    Bewusst geblockt statt halb unterstuetzt (Begruendung je Gruppe):
#    - ``anthropic_messages``/``aanthropic_messages`` (/v1/messages): eigenes
#      Schema mit ``system`` als Top-Level-Feld und eigenen Content-Block-
#      Typen. Braucht ein eigenes Block-Register UND einen eigenen Rueckweg
#      (Antwort-``content``-Bloecke statt ``choices[].message``). Beides ist
#      ein eigenes Work Item; bis dahin blocken statt falsch versprechen.
#    - ``aresponses``/``responses`` (/v1/responses): nutzt ``input`` statt
#      ``messages``, dazu ``instructions`` als eigenes Feld und eigene
#      Item-Typen. Gleiche Begruendung.
#    - ``text_completion``: NICHT /v1/completions, sondern der Adapter-
#      Passthrough (pass_through_endpoints.py:227). Der Body ist dort
#      betreiber-/adapterdefiniert, also von unbekannter Form -> nicht
#      pruefbar. Der Eintrag ist damit belegt real, aber nicht unterstuetzt.
#    - Embeddings, Bild-, Audio-, Moderations-, Rerank-, Batch-, File-,
#      Vector-Store-, MCP-, A2A-, Google-GenAI- und Passthrough-Routen tragen
#      genauso Anwendertext nach draussen, haben aber jeweils eigene Payload-
#      Formen.
KNOWN_UNSUPPORTED_CALL_TYPES = frozenset({
    # Anthropic Messages / OpenAI Responses -- die agentischen Formate.
    "anthropic_messages",
    "aanthropic_messages",
    "aresponses",
    "responses",
    "_aresponses_websocket",
    "aget_responses",
    "alist_input_items",
    # Legacy-/Adapter-Passthrough mit betreiberdefiniertem Body.
    "text_completion",
    "pass_through_endpoint",
    "llm_passthrough_route",
    "allm_passthrough_route",
    # Google GenAI nativ.
    "generate_content",
    "agenerate_content",
    "generate_content_stream",
    "agenerate_content_stream",
    # Uebrige LLM-Routen mit eigenem Payload-Schema.
    "embedding",
    "aembedding",
    "image_generation",
    "aimage_generation",
    "image_edit",
    "aimage_edit",
    "moderation",
    "amoderation",
    "transcription",
    "atranscription",
    "speech",
    "aspeech",
    "rerank",
    "arerank",
    "search",
    "asearch",
    "ocr",
    "aocr",
    "_arealtime",
    "create_batch",
    "acreate_batch",
    "retrieve_batch",
    "aretrieve_batch",
    "vector_store_search",
    "avector_store_search",
    "call_mcp_tool",
    "list_mcp_tools",
    "send_message",
    "asend_message",
    "apply_guardrail",
    # --- Nachtrag (DATENSCHLE-69 F4): gegen litellm.types.utils.CallTypes
    # der Version 1.97.0 abgeglichen. Kein Sicherheitsdefekt -- diese Routen
    # blockten schon vorher als "unbekannt". Es ist reine Meldungsqualitaet:
    # ein Betreiber soll den Namen der Route lesen statt nur "unbekannt" und
    # sofort wissen, woran er ist. Die Namen stammen aus dieser konstanten
    # Liste, nie aus dem Request (Gesetz 5).
    # Dateien.
    "acreate_file",
    "afile_content",
    "afile_delete",
    "afile_list",
    "afile_retrieve",
    # Fine-Tuning.
    "acreate_fine_tuning_job",
    "acancel_fine_tuning_job",
    "alist_fine_tuning_jobs",
    "aretrieve_fine_tuning_job",
    "acancel_batch",
    # Assistants/Threads -- tragen Anwendertext in eigenen Schemata.
    "acreate_assistants",
    "adelete_assistant",
    "aget_assistants",
    "acreate_thread",
    "aget_thread",
    "a_add_message",
    "aget_messages",
    "arun_thread",
    "arun_thread_stream",
    # Code-Interpreter/Sandboxes/Container.
    "arun_code",
    "acode_interpreter_tool",
    "acreate_sandbox",
    "adelete_sandbox",
    "acreate_container",
    "adelete_container",
    "aretrieve_container",
    "alist_containers",
    "alist_container_files",
    "aupload_container_file",
    # Vector Stores.
    "avector_store_create",
    "avector_store_file_create",
    "avector_store_file_delete",
    "avector_store_file_list",
    "avector_store_file_retrieve",
    "avector_store_file_update",
    "avector_store_file_content",
    # Video.
    "acreate_video",
    "avideo_content",
    "avideo_delete",
    "avideo_edit",
    "avideo_extension",
    "avideo_list",
    "avideo_remix",
    "avideo_retrieve",
    "avideo_retrieve_job",
    "avideo_create_character",
    "avideo_get_character",
    # Ingest/Query/Skills.
    "aingest",
    "aquery",
    "acreate_skill",
})

# Erlaubte call_types nennen wir in der Blockmeldung NIE mit Client-Werten,
# sondern nur mit dieser konstanten, unveraenderlichen Liste (Gesetz 5).
_ALLOWED_CALL_TYPES_HINT = ", ".join(sorted(ALLOWED_CALL_TYPES))


# ===========================================================================
# TOP-LEVEL-FELD-REGISTER DES PAYLOADS (DATENSCHLE-69, zweite Ebene)
# ===========================================================================
# Das Register eine Ebene hoeher (ALLOWED_CALL_TYPES) registriert die ROUTE.
# Es sagt aber nur, WELCHE Route spricht -- nicht, WIE ihr Body aussieht.
# Genau dort sass die sechste Instanz derselben Fehlerklasse:
#
#   DATENSCHLE-57  Content-Part-Typen
#   DATENSCHLE-64  content-Container
#   DATENSCHLE-65  Part-Felder
#   DATENSCHLE-66  Message-Felder
#   DATENSCHLE-69  Routen                        <- registriert
#   DATENSCHLE-69  TOP-LEVEL-FELDER DES PAYLOADS <- diese Ebene
#
# Warum ein ungepruefte Top-Level-Feld ein Leck ist und nicht nur eine
# Unsauberkeit -- empirisch belegt gegen litellm 1.97.0:
#   * ``litellm.utils.get_non_default_completion_params`` (utils.py, dort als
#     Funktionsdefinition zu finden -- in 1.97.0 Zeile 9255) filtert die
#     Top-Level-Keys gegen ``litellm.types.utils.all_litellm_params``. Alles,
#     was NICHT in dieser Liste steht, wird an den Provider gereicht.
#   * Benannte OpenAI-Parameter gehen direkt hinaus -- ``suffix`` z.B. ueber
#     ``main.py:7154`` in die Provider-Params.
#   * Alles Uebrige landet in ``extra_body``
#     (``utils.py``::``add_provider_specific_params_to_optional_params``, in
#     1.97.0 ab Zeile 4410) und geht ebenso hinaus;
#     ``_ensure_extra_body_is_safe``
#     (``litellm_core_utils/llm_request_utils.py:6``) filtert dort nichts
#     Sicherheitsrelevantes.
# Ein unbekanntes Top-Level-Feld ist damit ein vollwertiger Ausgangskanal.
#
# Aufbau wie beim Message-Feld-Register (DATENSCHLE-66), nur pro Route:
#   1) MASKIERT   Freitext ans Zielmodell -> durch DENSELBEN Masker wie der
#                 content-Pfad. Kein zweites Mapping, sonst bricht der Rueckweg.
#   2) VALIDIERT  Steuerparameter ohne Freitext. Sie muessen den Provider
#                 unveraendert erreichen, werden aber eng auf ihre Form
#                 geprueft. Die Pruefung steht im VALIDATE-Pfad und BLOCKT --
#                 ein ``isinstance``-Guard im Verarbeitungspfad ist immer ein
#                 stiller Durchlass (schwerstes Finding von DATENSCHLE-66).
#   3) ALLES UEBRIGE BLOCKT. Bekannte Felder werden beim Namen genannt
#      (KNOWN_UNSUPPORTED_PAYLOAD_FIELDS), unbekannte nur als Fingerprint --
#      auch ein Feldname ist Client-Inhalt (Gesetz 5).

#: Modellnamen duerfen Provider-Praefixe tragen ("azure/meine-deployment").
PAYLOAD_MODEL_PATTERN = re.compile(r"[A-Za-z0-9_.:/@-]{1,256}")

#: Opake Kennungen (organization, user_id, Callback-Namen). Bewusst eng:
#: was hier nicht passt, ist kein Bezeichner, sondern ein Freitext-Kanal.
PAYLOAD_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")

#: ``stream_options`` ist ein Schalter-Objekt, kein Textkanal.
STREAM_OPTIONS_ALLOWED_FIELDS = frozenset({"include_usage", "continuous_usage_stats"})

#: Maximale Anzahl Eintraege in ``stop`` bzw. in einer Callback-Liste. Echte
#: Requests bleiben weit darunter; eine unbegrenzte Liste ist nur ein Weg,
#: die Guardrail mit Analyzer-Calls zu fluten.
PAYLOAD_MAX_LIST_ITEMS = 32

#: Obergrenze fuer die BATCH-Form von ``prompt`` (Liste von Prompts).
#:
#: Eigene Konstante statt PAYLOAD_MAX_LIST_ITEMS: die beiden Listen sind
#: nicht dieselbe Sorte Liste. 32 ``stop``-Sequenzen sind grosszuegig (die
#: OpenAI-API erlaubt vier), 32 Prompts sind fuer einen Batch dagegen knapp
#: -- die Legacy-Completions-API wird real so benutzt. Ein zu enges Limit
#: waere ein Fix, der einen anderen Defekt erzeugt.
#:
#: WARUM ES DIE GRENZE BRAUCHT: jeder Eintrag kostet einen eigenen
#: Analyzer-Call. Ein einzelner Request skaliert also linear in Worker-Zeit
#: -- 400 Eintraege waren gemessen 9,7 s. Das ist kein Speicher-, sondern
#: ein Verfuegbarkeitsproblem: so lange steht der Worker fuer niemanden
#: sonst zur Verfuegung.
#:
#: DIE ZAHL 64 IST GESETZT, NICHT GEMESSEN -- und dieser Satz steht hier,
#: weil die Zeilen darueber das Gegenteil nahelegen. GEMESSEN ist der
#: EFFEKT (400 Eintraege = 9,7 s Worker-Zeit), NICHT die Grenze. Die 64 ist
#: eine Annahme darueber, was ein realer Prompt-Batch braucht.
#:
#: Eine Zahl ohne Beleg erkennt man als Setzung. Eine Zahl direkt NEBEN
#: einer echten Messung liest sich, als sei sie daraus gefolgt -- und
#: niemand prueft nach, weil ja offensichtlich gemessen wurde. Genau davor
#: warnt dieser Absatz.
#:
#: Wer die Zahl aendern will, braucht Betriebsdaten: der erste Betreiber,
#: der an die Grenze stoesst, liefert sie. Bis dahin bewusst konservativ
#: und bewusst aenderbar.
PAYLOAD_MAX_PROMPT_ITEMS = 64

#: Obergrenze fuer die Anzahl Messages eines Chat-Requests.
#:
#: Dieselbe Begruendung wie bei PAYLOAD_MAX_PROMPT_ITEMS, nur auf der
#: HAUPTROUTE und mit dem groesseren Volumen: jede Message kostet mindestens
#: einen eigenen Analyzer-Call. Ein Request skaliert damit linear in
#: Worker-Zeit, und so lange steht der Worker fuer niemanden sonst bereit.
#: Nur ``prompt`` zu begrenzen und ``messages`` offen zu lassen waere die
#: halbe Massnahme gewesen.
#:
#: Deutlich hoeher als das prompt-Limit, weil die Wertform eine andere ist:
#: ein Prompt-Batch von 64 ist gross, ein Gespraechsverlauf von 64 Turns ist
#: normal.
#:
#: DIE ZAHL 256 IST GESETZT, NICHT GEMESSEN -- und sie ist sogar noch
#: schwaecher belegt als die 64: sie ist aus dem FORMUNTERSCHIED zum
#: prompt-Limit abgeleitet ("ein Gespraech darf laenger sein als ein
#: Batch"), nicht aus einer Messung. Es gibt keinen Datenpunkt, der sagt,
#: dass 256 die richtige Stelle ist -- nur das Argument, dass sie ueber 64
#: liegen muss.
#:
#: Wer sie aendern will, braucht Betriebsdaten: der erste Betreiber, der an
#: die Grenze stoesst, liefert sie. Bis dahin bewusst konservativ und
#: bewusst aenderbar.
PAYLOAD_MAX_MESSAGES = 256

# --- 1) Gemeinsame Steuerparameter beider Routen ---------------------------
# Werte sind der Name des Formpruefers (siehe _PAYLOAD_VALIDATORS).
_COMMON_VALIDATED = {
    "model": "model",
    "stream": "bool",
    "stream_options": "stream_options",
    "temperature": "number",
    "top_p": "number",
    "n": "int",
    "seed": "int",
    "max_tokens": "int",
    "presence_penalty": "number",
    "frequency_penalty": "number",
    "logit_bias": "logit_bias",
    "logprobs": "bool_or_int",
    # Vom Proxy aus der Betreiber-Konfiguration gesetzt, stehen aber NICHT in
    # all_litellm_params -- sie erreichen den Provider ueber extra_body und
    # werden deshalb wie Client-Eingaben geprueft statt blind vertraut.
    "timeout": "number",
    "drop_params": "bool",
    "disable_fallbacks": "bool",
    "organization": "identifier",
    "user_id": "identifier",
    "success_callback": "identifier_list",
    "failure_callback": "identifier_list",
    # Verbindungs-Keys, die der Proxy legitim selbst setzt und die den
    # Provider byte-identisch erreichen muessen -- deshalb eng validiert
    # statt geblockt (gleiche Logik wie tool_call_id auf Message-Ebene).
    # ``api_version`` landet auf Azure im Query-String der URL: ohne dieses
    # enge Muster ist das eine Parameter-Injection in die Provider-URL.
    "api_version": "api_version",
    "api_key": "credential",
}


class _PayloadRoute(NamedTuple):
    """Das Payload-Schema EINER Route.

    ``required`` ist das Feld, das den Anwendertext traegt; fehlt es, ist der
    Payload nicht pruefbar. ``forbidden`` ist das Textfeld der jeweils ANDEREN
    Route: taucht es hier auf, passt der Body auf zwei Routen gleichzeitig und
    ist damit mehrdeutig (security-baseline.md). Bisher war diese Regel nur in
    EINER Richtung umgesetzt -- die Text-Route blockte ein mitgeschicktes
    ``messages``, die Chat-Route ein mitgeschicktes ``prompt`` nicht.
    """

    name: str
    masked: Tuple[str, ...]
    validated: Dict[str, str]
    required: str
    forbidden: str


#: /v1/chat/completions -- der Anwendertext steht in ``messages[]``.
#: ``messages`` selbst maskiert der bestehende Pfad im Hook; hier ist es nur
#: als "behandelt" registriert.
CHAT_PAYLOAD_ROUTE = _PayloadRoute(
    name="Chat-Completion (messages)",
    masked=(
        "messages",
        # Braucht keinen Trick: ``tools[].function.description`` ist ein
        # regulaeres Chat-Completion-Feld, wird garantiert uebertragen und
        # traegt in der Praxis Kundennamen und Enum-Listen echter Stammdaten.
        "tools",
        "tool_choice",
        # Legacy-Form derselben Nutzlast (vor tools/tool_choice).
        "functions",
        "function_call",
        # JSON-Schema-Modus: die ``description``-Felder des Schemas sind
        # Freitext und gehen unveraendert ans Modell.
        "response_format",
        "stop",
        "user",
    ),
    validated={
        **_COMMON_VALIDATED,
        "max_completion_tokens": "int",
        "top_logprobs": "int",
        "parallel_tool_calls": "bool",
        "service_tier": "identifier",
        "reasoning_effort": "identifier",
        "store": "bool",
    },
    required="messages",
    forbidden="prompt",
)

#: /v1/completions -- der Anwendertext steht in ``prompt``.
TEXT_PAYLOAD_ROUTE = _PayloadRoute(
    name="Text-Completion (prompt)",
    masked=(
        "prompt",
        # DER Kanal aus F1: ein FIM-/Code-Completion-Client legt den Kontext
        # HINTER der Einfuegestelle in ``suffix``. Bei einem Kanzlei- oder
        # Praxisdokument stehen dort die Mandanten- bzw. Patientendaten.
        "suffix",
        "stop",
        "user",
    ),
    validated={
        **_COMMON_VALIDATED,
        "best_of": "int",
        "echo": "bool",
    },
    required="prompt",
    forbidden="messages",
)

PAYLOAD_ROUTES = {
    **{ct: CHAT_PAYLOAD_ROUTE for ct in CALL_TYPES_CHAT_MESSAGES},
    **{ct: TEXT_PAYLOAD_ROUTE for ct in CALL_TYPES_TEXT_PROMPT},
}

# --- 2) Infrastruktur-Keys: vom Proxy bzw. von litellm selbst gesetzt ------
# Diese Keys stehen nicht im Body des Clients, sondern legt
# ``litellm.proxy.litellm_pre_call_utils.add_litellm_data_to_request`` in
# ``data``, BEVOR der Guardrail-Hook laeuft. Sie duerfen deshalb nicht als
# "unbekanntes Client-Feld" blocken -- sonst blockt jeder echte Request.
#
# KRITERIUM (zweimal geschaerft, jeweils nach einem Security-Gate). Ein Key
# darf hier nur stehen, wenn BEIDES gilt:
#
#   (a) Er erreicht den Provider auf KEINEM Weg -- nicht im Body, nicht als
#       HTTP-Header, nicht in der URL bzw. deren Query-String, nicht ueber
#       Verbindungs-Konfiguration. Und das ist GEMESSEN, nicht angenommen.
#   (b) Er bestimmt nicht, WOHIN die Anfrage geht, MIT WESSEN Zugangsdaten
#       oder OB sie ueberhaupt hinausgeht. Diese Frage ist schaerfer als
#       (a): ``api_base`` traegt selbst keine PII und leitet trotzdem den
#       kompletten Verkehr auf einen fremden Server um.
#
# Die URL kam erst im dritten Gate dazu -- und der Fehler lag in der
# MESSMETHODE, nicht in einem einzelnen Key: geprueft wurden Header und Body,
# die URL stand nicht auf der Liste. ``api_version`` geht auf Azure genau
# dort hinaus, als Query-Parameter
# (``?api-version=2024-02-01&…``). Gegen ``openai`` ist derselbe Key dicht.
#
# DARAUS FOLGT, und das ist wichtiger als jeder Einzelfund:
#   * Die Messung ist PROVIDER-ABHAENGIG. Was gegen einen Provider-Handler
#     dicht ist, muss es gegen einen anderen nicht sein. Gemessen wird
#     deshalb gegen mehrere, mindestens openai und azure.
#   * Ein FEHLER in der Messung ist kein Freibrief. Laeuft der Aufruf nicht
#     durch oder kommt kein Request an, lautet das Ergebnis NICHT GEMESSEN --
#     und ein nicht gemessener Key gehoert nicht auf diese Liste. Genau so
#     waere ``model_list`` beinahe durchgerutscht (Verbindungsfehler), und
#     genau so ist ``mock_response`` hier herausgeflogen.
#   * Eine Messung ist nur so gut wie ihre WERTFORM. Ein Marker in der
#     falschen Struktur misst nichts. Deshalb bekommt jeder Key eine Form,
#     die er real annehmen kann.
#   * Die Messliste wird gegen DIESE Konstante abgeglichen, nicht von Hand
#     gefuehrt. Sechs Keys waren nie gemessen worden, weil sie in der
#     Messliste schlicht fehlten -- darunter ``api_base``.
#
# Die erste Fassung dieser Liste prueft nur eine Teilbedingung: "steht in
# ``litellm.types.utils.all_litellm_params``, wird also von
# ``get_non_default_completion_params`` (utils.py, Funktionsdefinition) aus
# den Provider-Parametern gefiltert". Das ist NOTWENDIG, aber nicht
# HINREICHEND -- und genau diese Verwechslung war ein High-Finding:
# ``headers`` steht in all_litellm_params und geht trotzdem hinaus, nur eben
# als HTTP-Header statt im Body (``main.py:5029``:
# ``headers = kwargs.get("headers") or extra_headers``, danach
# ``headers=headers`` in jeden Provider-Handler).
#
# Deshalb wird die Liste nicht mehr aus einer Namensliste abgeleitet, sondern
# GEMESSEN: ein mitschneidender Provider-Server, ein echter
# ``litellm.completion``-Aufruf pro Key, Pruefung des kompletten ausgehenden
# HTTP-Requests auf Header UND Body. Ergebnis gegen 1.97.0: von 37 Keys
# erreichen genau drei den Provider -- sie stehen in
# PAYLOAD_FIELDS_TRANSPORT_CHANNELS und blocken.
#
# ACHTUNG, bewusst NICHT hier drin: ``extra_headers`` und sein aelterer
# Zwillingsname ``headers`` -- derselbe Kanal, zwei Namen. Dass der eine
# geblockt war und der andere passierte, war kein Abwaegen, sondern ein
# uebersehener Alias.
#
# BEKANNTE GRENZE dieser Liste, damit sie niemand fuer mehr haelt, als sie
# ist: "erreicht den Provider nicht" heisst NICHT "ist harmlos". ``metadata``
# etwa nimmt ein Client entgegen und litellm reicht es an seine
# Logging-Callbacks weiter. Ein Client, der dort PII hineinschreibt, bekommt
# sie also nicht zum Modell, wohl aber potenziell ins Log (Gesetz 5). Diese
# Ebene -- Client-Eingaben auf dem LOGGING-Weg statt auf dem Provider-Weg --
# deckt dieses Register bewusst nicht ab; sie ist ein eigenes Work Item.
PAYLOAD_FIELDS_INFRASTRUCTURE = frozenset({
    # Vom Proxy bei JEDEM Request gesetzt (empirisch gegen 1.97.0 gemessen).
    "metadata",
    # ``proxy_server_request`` steht bewusst NICHT mehr hier, sondern in
    # PAYLOAD_FIELDS_RESYNCED: es ist kein Feld, das nur passiert, sondern
    # eines, das die Guardrail selbst BEHANDELN muss. Siehe dort.
    "secret_fields",
    # Vom Proxy je nach Header-/Key-Konfiguration gesetzt.
    "litellm_metadata",
    "litellm_session_id",
    "litellm_trace_id",
    "litellm_call_id",
    "litellm_logging_obj",
    "litellm_disabled_callbacks",
    "allowed_model_region",
    "cache",
    "caching",
    "ttl",
    "tags",
    "num_retries",
    "max_retries",
    "stream_timeout",
    "request_timeout",
    # Routing-/Betriebsschalter, die litellm selbst auswertet.
    "base_model",
    "model_info",
    "fallbacks",
    "context_window_fallback_dict",
    "guardrails",
    "enable_json_schema_validation",
    "shared_session",
    "no-log",
    "turn_off_message_logging",
    "preset_cache_key",
    "id",
})

# --- 2a) DEPLOYMENT-PFAD: dasselbe Register, ein anderer Absender ---------
# (DATENSCHLE-69, Security-F3)
#
# litellm ruft eine Guardrail an ZWEI Stellen: am Proxy (ProxyLogging.
# pre_call_hook, Client-Body) und nach der Routing-Entscheidung
# (CustomGuardrail.async_pre_call_deployment_hook, router-aufgeloeste
# Deployment-kwargs). Beide landen in demselben ``async_pre_call_hook``.
#
# Der alte Kommentar behauptete, der Register-Eintrag ``"completion"`` sei
# durch diesen zweiten Weg belegt -- ohne die FORM des Payloads dort je
# gemessen zu haben. Genau die Verwechslung, die die eigene Doktrin verbietet:
# "der call_type sagt nur, WELCHE Route spricht, nicht WIE ihr Payload
# aussieht." Nachgemessen war der Befund ein Totalausfall: die Deployment-
# kwargs blockten hart, jeder Request, fail-closed -- und die erste
# Betreiberreaktion darauf ist, die Guardrail abzuschalten.
#
# GEMESSEN (litellm 1.97.0, echter Router mit echtem Deployment), die
# Top-Level-Keys auf dem Deployment-Pfad:
#   api_base, api_key, caching, client, guardrails, litellm_call_id,
#   litellm_trace_id, max_retries, merge_reasoning_content_in_choices,
#   messages, metadata, mock_response, model, model_info, stream, timeout,
#   use_in_pass_through, use_litellm_proxy, use_xai_oauth
# Dazu die fuenf ``user_api_key_*``-Keys, die litellm in
# integrations/custom_guardrail.py:661-666 selbst aus den kwargs liest, um
# UserAPIKeyAuth zu bauen, sowie ``guardrail_to_apply`` (:657).
#
# WARUM DAS KEIN AUFWEICHEN IST: dieses Register gilt AUSSCHLIESSLICH,
# solange wir nachweislich im Deployment-Hook stehen (ContextVar, gesetzt in
# unserem eigenen ``async_pre_call_deployment_hook``). Auf dem Client-Pfad
# bleibt jeder dieser Keys geblockt -- ``api_base`` etwa leitet, client-
# gesetzt, den kompletten Verkehr auf einen fremden Server um; auf dem
# Deployment-Pfad setzt ihn der ROUTER. Derselbe Name, eine andere Herkunft,
# ein anderes Vertrauensmodell. Der Deployment-Pfad bekommt ein GROESSERES
# Register, kein laxeres: ein unbekannter Key blockt dort genauso.
PAYLOAD_FIELDS_DEPLOYMENT = frozenset({
    # Vom Router aus der Deployment-Konfiguration des BETREIBERS aufgeloest.
    # Auf dem Client-Pfad blockt api_base als Transport-Kanal -- hier stammt
    # er aus der config.yaml, nicht aus dem Request.
    "api_base",
    # Vom Router injizierte Betriebs-/Verbindungsschalter (gemessen).
    "client",
    "merge_reasoning_content_in_choices",
    "use_in_pass_through",
    "use_litellm_proxy",
    "use_xai_oauth",
    # Identitaet des Aufrufers, vom PROXY gesetzt und von litellm selbst
    # gelesen (custom_guardrail.py:661-666). litellm strippt gleichnamige
    # CLIENT-Metadaten ausdruecklich, weil ein Client sie sonst faelschen
    # koennte -- auf dem Client-Pfad blocken sie deshalb weiterhin.
    "user_api_key_user_id",
    "user_api_key_team_id",
    "user_api_key_end_user_id",
    "user_api_key_hash",
    "user_api_key_request_route",
    # Setzt litellm selbst, wenn die Guardrail ueber apply_guardrail laeuft
    # (custom_guardrail.py:657).
    "guardrail_to_apply",
})

#: Merker fuer "wir stehen im Deployment-Hook". ContextVar und NICHT ein
#: Instanz-Attribut: die Guardrail-Instanz ist prozessweit geteilt und
#: bedient nebenlaeufige Requests. Ein Attribut waere ein Datenrennen, bei
#: dem ein Client-Request das erweiterte Register eines gleichzeitigen
#: Deployment-Requests erwischen koennte -- also ein Sicherheitsdefekt.
#: ContextVars sind pro asyncio-Task isoliert.
_DEPLOYMENT_PATH = contextvars.ContextVar(
    "datenschleuse_deployment_path", default=False
)


# --- 2b) BEHANDELT: abgeleitete Kopien des Payloads -----------------------
# Die dritte Kategorie neben "passiert" und "blockt": Keys, die den Payload
# nicht WEITERTRAGEN, sondern ihn SPIEGELN. Sie erreichen den Provider nicht
# (deshalb standen sie auf der Passier-Liste) -- aber sie halten eine Kopie
# genau der Daten, die wir gerade maskiert haben, und geben sie an einen
# anderen Kanal weiter: das Logging.
#
# Das ist die Frage, die das Passier-Kriterium nie gestellt hat. Es fragte
# "erreicht dieser Key den Provider?" und war damit richtig, aber unvollstaendig.
# Die fehlende Frage lautet: "Traegt dieser Key eine VERALTETE, unmaskierte
# Kopie des Payloads?" -- und fuer ``proxy_server_request`` ist die Antwort ja.
#
# ``proxy_server_request["body"]`` ist litellms flacher Logging-Schnappschuss
# (1.97.0, proxy/litellm_pre_call_utils.py:1690-1692):
#
#     _body_snapshot = {k: v for k, v in data.items() if k not in exclude}
#     data["proxy_server_request"]["body"] = _body_snapshot
#
# FLACH ist das entscheidende Wort: pro Key haelt der Schnappschuss dieselbe
# Objekt-Referenz wie ``data``. Daraus folgt unmittelbar, welche Felder dicht
# waren und welche nicht:
#
#   * IN-PLACE mutiert (``messages``: die Message-Dicts werden veraendert, die
#     Liste bleibt dieselbe)  -> Schnappschuss sieht die Maskierung mit.
#   * durch REBINDING maskiert (``data[feld] = maskiert``)
#                              -> Schnappschuss haelt weiter den ALTEN Wert.
#
# Konsumenten laut litellms eigenem Kommentar an der Fundstelle:
# ``standard_logging_payload``, ``lago``, ``spend_tracking_utils``,
# ``streaming_iterator``. ``turn_off_message_logging`` rettet NICHT:
# ``perform_redaction`` (litellm_core_utils/redact_messages.py:238-240)
# redigiert ausschliesslich ``messages``, ``prompt`` und ``input``.
#
# WARUM RE-SYNC UND NICHT DURCHGAENGIG IN-PLACE
# ---------------------------------------------
# "Container in-place mutieren statt neu binden" schliesst die Fehlerklasse
# eleganter -- aber nur fuer Container. Es ist fuer die betroffenen Felder
# NACHWEISLICH NICHT DURCHFUEHRBAR: ``prompt`` (als String), ``suffix``,
# ``user`` und ``stop`` (als String) sind Python-``str``, also unveraenderlich.
# Es gibt keine Operation, die einen ``str`` an Ort und Stelle maskiert. Eine
# Regel "immer in-place" waere damit unerfuellbar und wuerde still gebrochen --
# genau die Fehlerklasse, die wir schliessen wollen.
#
# Der Re-Sync BAUT den Schnappschuss NEU statt ihn feldweise nachzuziehen.
# Das ist der Unterschied zwischen "den Einzelfall repariert" und "die Klasse
# geschlossen": ein feldweiser Abgleich deckt die Felder ab, an die jemand
# gedacht hat; der Neubau deckt alles ab, was im Payload steht -- auch das,
# was ein kuenftiger Commit hinzufuegt, mutabel oder nicht.
#
# VERSIONSDRIFT -- die Korrektur einer zurueckgezogenen Behauptung.
#
# Hier stand: der Fehler sei "in BEIDE Richtungen harmlos -- wir nehmen einen
# Key zu viel auf (er ist dann maskiert oder registriert, also geprueft)".
# Das ist FALSCH und wird zurueckgezogen (Security-F1b). "Registriert" heisst
# nicht "unschaedlich gemacht": ``api_key`` ist VALIDIERT, nicht maskiert --
# er muss den Provider byte-identisch erreichen. Ein Token, das die
# Formpruefung besteht, ist immer noch ein Token im Log. Die Annahme hat
# genau das Leck getragen, das sie fuer unmoeglich erklaerte.
#
# Richtig ist die ASYMMETRIE, und nur sie:
#   * ein Key zu WENIG in unserer Menge (litellm schliesst ihn aus, wir
#     nicht) traegt ihn beim Neubau ins Log -- das ist das Leck;
#   * ein Key zu VIEL (wir schliessen ihn aus, litellm nicht) zeigt den
#     Konsumenten weniger als frueher -- nie mehr.
# Deshalb ist der Vertrag eine OBERMENGE, keine Gleichheit, und deshalb wird
# er GEMESSEN statt angenommen: siehe LOGGING_SNAPSHOT_EXCLUDE.
PAYLOAD_FIELDS_RESYNCED = frozenset({
    "proxy_server_request",
})

#: Alle Felder, die auf IRGENDEINER Route Anwendertext tragen. Basis fuer
#: die Redaktion eines geblockten Requests -- abgeleitet aus dem Register,
#: nicht handgepflegt: ein kuenftiges maskiertes Feld wird damit automatisch
#: mitredigiert, ohne dass jemand daran denken muss.
_ALLE_MASKIERTEN_FELDER = frozenset()  # wird nach den Routen gefuellt

#: Zugangs-Geheimnisse, die NIE in den Logging-Schnappschuss gehoeren.
#:
#: Sie stehen hier aus einem SACHGRUND, nicht weil irgendeine
#: litellm-Version sie ausschliesst: ein Zugangs-Token hat in einem
#: Log nichts zu suchen (Gesetz 5,
#: ``docs/foundation/security-baseline.md``: keine Tokens in Logs). Diese
#: Begruendung ueberlebt jedes Upgrade -- eine abgeschriebene Fremdkonstante
#: tut das nicht.
#:
#: WARUM DAS NOETIG IST, obwohl ``api_key`` im Payload-Register steht: er ist
#: dort VALIDIERT, nicht maskiert. Der Formpruefer sagt "sieht aus wie ein
#: Token" und laesst ihn unveraendert weiterlaufen -- er MUSS den Provider
#: byte-identisch erreichen, sonst ist Pass-Through-Auth kaputt. Ein Token,
#: das die Formpruefung besteht, ist immer noch ein Token im Log.
#:
#: GEMESSEN (1.94.0 und 1.96.2, ``proxy/litellm_pre_call_utils.py``):
#: ``data["api_key"]`` wird aus dem ``x-api-key``-Header gesetzt (Z. 1422)
#: und der Schnappschuss DANACH gebaut (Z. 1590) -- auf diesen Versionen
#: steht das Token also bereits in litellms eigenem Schnappschuss. Wir sind
#: hier bewusst STRENGER als litellm.
SNAPSHOT_CREDENTIAL_KEYS = frozenset({
    "api_key",
    "headers",
    "extra_headers",
    "provider_specific_header",
})

#: Was beim Neubau des Logging-Schnappschusses NICHT uebernommen wird.
#:
#: Zwei Gruppen mit zwei verschiedenen Begruendungen -- bewusst getrennt,
#: weil sie unterschiedlich altern:
#:
#:   * STRUKTURELL (``secret_fields``, ``proxy_server_request``): litellms
#:     eigene Ausschluesse. ``proxy_server_request`` wuerde den
#:     Schnappschuss auf sich selbst zeigen lassen (Endlos-Traversierung),
#:     ``secret_fields`` ist der Geheimnis-Container.
#:   * CREDENTIALS (``SNAPSHOT_CREDENTIAL_KEYS``): siehe dort.
#:
#: Eigene Konstante statt Import: ``_body_snapshot_exclude`` ist bei litellm
#: eine LOKALE Variable in ``add_litellm_data_to_request`` -- importierbar
#: ist sie nicht. Die Guardrail muss ausserdem ohne installiertes litellm
#: importierbar und testbar bleiben.
#:
#: DER VERTRAG, und wie er GEPRUEFT wird: diese Menge muss eine OBERMENGE der
#: litellm-eigenen sein. ``test/test_snapshot_exclude_contract.py`` liest
#: litellms Zuweisung zur Laufzeit aus dem Quelltext (ast) und prueft genau
#: das -- statt die Menge ein zweites Mal abzuschreiben. Zwei Kopien
#: derselben Vermutung sind keine Bestaetigung; das war der Fehler der
#: ersten Runde.
LOGGING_SNAPSHOT_EXCLUDE = frozenset({
    "secret_fields",
    "proxy_server_request",
}) | SNAPSHOT_CREDENTIAL_KEYS


#: GEMESSENE Ausgangskanaele jenseits des Bodys (litellm 1.97.0). Jeder
#: dieser Keys erfuellt das alte, zu enge Kriterium -- er steht in
#: all_litellm_params -- und erreicht den Provider trotzdem. Sie stehen
#: deshalb ausdruecklich NICHT auf der Passier-Liste, sondern blocken.
#:
#: Als eigene Konstante, damit die Test-Suite die Trennung erzwingen kann
#: und ein spaeterer Beitrag sie nicht versehentlich zurueckschiebt.
PAYLOAD_FIELDS_TRANSPORT_CHANNELS = frozenset({
    # ``headers``/``extra_headers`` landen im selben dict und gehen als
    # HTTP-Header auf die Leitung. Der Proxy setzt ``headers`` nur, wenn der
    # Betreiber ``forward_client_headers_to_llm_api`` ausdruecklich
    # einschaltet -- die Standard-Installation ist davon nicht betroffen.
    # Und genau dieses Feature IST ein PII-Ausgangskanal: es reicht
    # Client-HTTP-Header ungeprueft ans Modell weiter.
    "headers",
    "extra_headers",
    # ``provider_specific_header.extra_headers`` wird provider-abhaengig in
    # dieselben HTTP-Header gemischt
    # (ProviderSpecificHeaderUtils.get_provider_specific_headers).
    "provider_specific_header",
    # Eigener Fund beim Nachmessen: die Deployment-Eintraege von
    # ``model_list`` tragen eigene ``litellm_params.extra_headers`` -- und
    # die landen ebenfalls auf der Leitung. Ein Client hat an der
    # Routing-Konfiguration ohnehin nichts zu suchen.
    "model_list",
    # --- Dritte Runde: die URL und die Verbindung selbst -------------------
    # ``api_version`` landet auf Azure im QUERY-STRING der Provider-URL.
    # Gegen openai ist derselbe Key dicht -- deshalb wird provider-
    # uebergreifend gemessen. Er blockt nicht, sondern wird eng VALIDIERT:
    # der Proxy setzt ihn selbst aus dem Query-String eines Azure-Clients,
    # und er muss den Provider byte-identisch erreichen.
    "api_version",
    # ``api_key`` geht als ``authorization``-Header hinaus. Ebenfalls eng
    # validiert statt geblockt: Pass-Through-Auth ist ein legitimes Setup.
    "api_key",
    # ``api_base`` traegt selbst keine PII -- er bestimmt das ZIEL. Gemessen
    # mit einem zweiten Mitschnitt-Server: ein client-gesetzter api_base
    # leitet die komplette Anfrage dorthin um. Der Proxy setzt ihn nie
    # selbst, also blockt er.
    "api_base",
})


# --- 3) Bekannt, aber nicht behandelt -> blockt, wird aber benannt ---------
# "Was du nicht behandelst, blockt -- und wird benannt." Diese Felder gibt es
# real; die Datenschleuse prueft sie (noch) nicht. Jeder Eintrag ist ein
# eigenes Work Item, kein stillschweigendes Durchreichen. Die Namen stammen
# aus dieser konstanten Liste, NIE aus dem Request (Gesetz 5).
KNOWN_UNSUPPORTED_PAYLOAD_FIELDS = frozenset({
    # Freitext-/Binaerkanaele mit eigener Form, die ein eigenes Register
    # braeuchten:
    "audio",               # Audio-Ein-/Ausgabe: eigenes Part-Format
    "modalities",          # schaltet die Audio-Ausgabe frei -> siehe audio
    "prediction",          # Predicted Outputs: traegt kompletten Nutzertext
    "thinking",            # Anthropic-Reasoning-Konfiguration
    "web_search_options",  # Suchanfragen gehen an einen Dritt-Dienst
    "safety_identifier",   # Endnutzer-Kennung wie user -> eigener Fall
    "verbosity",
    # Geht als HTTP-Header bzw. als roher Body-Zusatz an den Provider und
    # damit komplett an der Payload-Pruefung vorbei:
    "extra_headers",
    # Derselbe HTTP-Header-Kanal wie extra_headers, nur der aeltere Name --
    # und die beiden landen in litellm im selben dict. Dass hier frueher nur
    # einer der beiden Namen stand, war der Defekt.
    "headers",
    "provider_specific_header",
    # Routing-/Verbindungs-Konfiguration: die Deployment-Eintraege tragen
    # eigene extra_headers und gehen damit auf die Leitung.
    "model_list",
    # Bestimmt das ZIEL der Anfrage. Gemessen: leitet den kompletten Verkehr
    # auf einen fremden Server um. Der Proxy setzt ihn nie selbst.
    "api_base",
    # Waehlt den Provider-Handler und damit, ob ueberhaupt eine URL mit
    # Query-Parametern gebaut wird. Der Proxy setzt ihn nie selbst.
    "custom_llm_provider",
    # Unterdrueckt den echten Aufruf -- dadurch NICHT messbar. Ungemessen
    # darf nach dem Kriterium oben nicht passieren.
    "mock_response",
    "extra_body",
    "deployment_id",
    "include_server_side_tool_invocations",
    # Prompt-Management: der Text kaeme dann aus einer fremden Quelle und
    # stuende gar nicht in dem Payload, den wir pruefen koennen.
    "prompt_id",
    "prompt_label",
    "prompt_version",
    "prompt_variables",
    "litellm_system_prompt",
    "user_continue_message",
    "assistant_continue_message",
    "allowed_openai_params",
})

#: Erlaubte Felder nennen wir in der Blockmeldung nur ueber diese konstanten
#: Listen, nie mit Client-Werten (Gesetz 5).
_PAYLOAD_FIELDS_HINT = {
    route.name: ", ".join(sorted(set(route.masked) | set(route.validated)))
    for route in (CHAT_PAYLOAD_ROUTE, TEXT_PAYLOAD_ROUTE)
}


# --- 4) Formpruefer der validierten Felder ---------------------------------
# Ein registriertes Feld mit falschem Typ ist derselbe Defekt wie ein
# unbekanntes Feld: niemand hat den Inhalt geprueft. Diese Pruefer BLOCKEN
# deshalb -- sie ueberspringen nie still.
#
# In keiner Meldung steht ein Client-WERT, nur der Python-Typname und der
# Feldname aus unserer eigenen konstanten Liste (Gesetz 5).
def _payload_form_error(field: str, value: Any, erwartet: str) -> None:
    raise DatenschleuseBlocked(
        f"{field} vom Typ {type(value).__name__!r} hat nicht die erwartete "
        f"Form ({erwartet}) und wird deshalb nicht geprueft -- blockiert "
        "(fail-closed)."
    )


def _payload_expect_bool(value: Any, field: str) -> None:
    if not isinstance(value, bool):
        _payload_form_error(field, value, "true/false")


def _payload_expect_int(value: Any, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        _payload_form_error(field, value, "ganze Zahl")


def _payload_expect_number(value: Any, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _payload_form_error(field, value, "Zahl")


def _payload_expect_bool_or_int(value: Any, field: str) -> None:
    # ``logprobs`` ist auf der Chat-Route ein Schalter, auf der Text-Route
    # eine Anzahl. Beides ist eine Zahl bzw. ein Bool -- nie Text.
    if not isinstance(value, (bool, int)):
        _payload_form_error(field, value, "true/false oder ganze Zahl")


def _payload_expect_model(value: Any, field: str) -> None:
    if not isinstance(value, str) or not PAYLOAD_MODEL_PATTERN.fullmatch(value):
        _payload_form_error(field, value, "Modellname")


def _payload_expect_identifier(value: Any, field: str) -> None:
    if not isinstance(value, str) or not PAYLOAD_IDENTIFIER_PATTERN.fullmatch(value):
        _payload_form_error(field, value, "Bezeichner aus A-Z a-z 0-9 _ . : -")


def _payload_expect_identifier_list(value: Any, field: str) -> None:
    if not isinstance(value, list) or len(value) > PAYLOAD_MAX_LIST_ITEMS:
        _payload_form_error(field, value, "Liste von Bezeichnern")
    for item in value:
        _payload_expect_identifier(item, field)


def _payload_expect_logit_bias(value: Any, field: str) -> None:
    if not isinstance(value, dict):
        _payload_form_error(field, value, "Objekt aus Token-ID -> Zahl")
    for key, bias in value.items():
        # Der SCHLUESSEL ist hier client-kontrolliert und damit potenziell ein
        # Schmuggelkanal -- deshalb eng auf eine Ziffernfolge geprueft und in
        # der Meldung nie ausgegeben.
        if not isinstance(key, str) or not key.isdigit():
            _payload_form_error(field, key, "Token-ID als Ziffernfolge")
        if isinstance(bias, bool) or not isinstance(bias, (int, float)):
            _payload_form_error(field, bias, "Zahl")


def _payload_expect_stream_options(value: Any, field: str) -> None:
    if not isinstance(value, dict):
        _payload_form_error(field, value, "Objekt")
    unbekannt = sum(1 for key in value if key not in STREAM_OPTIONS_ALLOWED_FIELDS)
    if unbekannt:
        raise DatenschleuseBlocked(
            f"{field} enthaelt {unbekannt} ungepruefte(s) Feld(er) -- blockiert "
            "(fail-closed). Erlaubt: "
            f"{', '.join(sorted(STREAM_OPTIONS_ALLOWED_FIELDS))}."
        )
    for key, schalter in value.items():
        if not isinstance(schalter, bool):
            # ``key`` stammt hier aus der Allowlist oben, ist also konstant.
            _payload_form_error(f"{field}.{key}", schalter, "true/false")


#: Azure-API-Versionen sind Datumsstempel, optional mit Vorschau-Suffix.
#: Bewusst ohne ``&`` und ``=``: genau damit haengt man einen zweiten
#: Query-Parameter an die Provider-URL an.
API_VERSION_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?")

#: Zugangsdaten sind zusammenhaengende Tokens ohne Leerzeichen und ohne
#: Zeilenumbrueche. Ein Freitext passt hier nicht hinein.
CREDENTIAL_PATTERN = re.compile(r"[A-Za-z0-9_.:/+=-]{1,512}")


def _payload_expect_api_version(value: Any, field: str) -> None:
    if not isinstance(value, str) or not API_VERSION_PATTERN.fullmatch(value):
        _payload_form_error(field, value, "Datumsstempel wie 2024-02-01")


def _payload_expect_credential(value: Any, field: str) -> None:
    if not isinstance(value, str) or not CREDENTIAL_PATTERN.fullmatch(value):
        _payload_form_error(field, value, "Zugangs-Token ohne Leerzeichen")


_PAYLOAD_VALIDATORS = {
    "api_version": _payload_expect_api_version,
    "credential": _payload_expect_credential,
    "bool": _payload_expect_bool,
    "int": _payload_expect_int,
    "number": _payload_expect_number,
    "bool_or_int": _payload_expect_bool_or_int,
    "model": _payload_expect_model,
    "identifier": _payload_expect_identifier,
    "identifier_list": _payload_expect_identifier_list,
    "logit_bias": _payload_expect_logit_bias,
    "stream_options": _payload_expect_stream_options,
}

# Register-Ableitung: die Union der maskierten Felder beider Routen. Steht
# hier, weil erst ab dieser Stelle beide Routen definiert sind.
_ALLE_MASKIERTEN_FELDER = frozenset(
    CHAT_PAYLOAD_ROUTE.masked
) | frozenset(TEXT_PAYLOAD_ROUTE.masked)

# Bauart-Absicherung: jedes registrierte Feld braucht einen echten Pruefer.
# Ein Tippfehler im Register wuerde sonst zur Laufzeit im Verarbeitungspfad
# landen -- also genau dort, wo ein Fehler zum Durchlass wird.
for _route in (CHAT_PAYLOAD_ROUTE, TEXT_PAYLOAD_ROUTE):
    _fehlend = sorted(set(_route.validated.values()) - set(_PAYLOAD_VALIDATORS))
    if _fehlend:  # pragma: no cover - Import-Zeit-Zusicherung
        raise RuntimeError(f"Payload-Register ohne Formpruefer: {_fehlend}")
del _route

# Ein gemessener Transportkanal darf NIE auf der Passier-Liste landen. Als
# Import-Zeit-Zusicherung, nicht nur als Test: dieser Fehler war einmal ein
# High-Finding und soll beim naechsten Mal gar nicht erst startbar sein.
_durchgerutscht = sorted(
    PAYLOAD_FIELDS_TRANSPORT_CHANNELS & PAYLOAD_FIELDS_INFRASTRUCTURE
)
if _durchgerutscht:  # pragma: no cover - Import-Zeit-Zusicherung
    raise RuntimeError(
        "Diese Keys erreichen den Provider und duerfen nicht ungeprueft "
        f"passieren: {_durchgerutscht}"
    )
del _durchgerutscht


# ===========================================================================
# MESSAGE-FELD-REGISTER (DATENSCHLE-66)
# ===========================================================================
# Warum ein Register statt einzelner if-Zweige: der Guardrail hat dieselbe
# Luecke jetzt dreimal gehabt -- Part-Ebene (DATENSCHLE-57), content-Container
# (DATENSCHLE-64) und nun jedes Feld NEBEN content (DATENSCHLE-66, PII in
# ``tool_calls[].function.arguments`` lief unveraendert ans Modell). Ursache
# war jedes Mal dieselbe: gelesen wurde, was man kannte; alles Uebrige lief
# still durch. Deshalb wird ab hier nicht mehr Feld fuer Feld entdeckt,
# sondern EINMAL vollstaendig erfasst: jedes Feld einer Chat-Message steht in
# genau einer der drei Listen unten. Was in keiner steht, ist unbekannt und
# blockt fail-closed. Ein neues Feld der OpenAI-API zwingt damit zu einer
# bewussten Entscheidung (Eintrag ins Register), statt lautlos ein Leck zu
# oeffnen.
#
# 1) MASKIERT: freier Text, der ans Zielmodell geht -> durch Presidio +
#    Masker (dasselbe reid_map wie content, kein zweites Mapping).
MESSAGE_FIELDS_MASKED = (
    "content",
    "name",
    "refusal",
    "tool_calls",
    "function_call",
    # Reasoning-Modelle spielen ihren Gedankengang im naechsten Turn zurueck.
    # Das ist Freitext und enthaelt regelmaessig genau die Werte, um die es im
    # Gespraech geht -> maskieren wie jeden anderen Text.
    "reasoning_content",
)

# 2) VALIDIERT: Protokoll-Felder, die KEIN Freitext sind. Sie werden nicht
#    maskiert (ihr Wert muss byte-identisch erhalten bleiben, sonst bricht die
#    Zuordnung von tool_call zu Tool-Ergebnis), aber sie werden gegen ein
#    enges Format geprueft -- sonst waeren sie ein bequemer Schmuggelkanal.
MESSAGE_FIELDS_VALIDATED = (
    "role",
    "tool_call_id",
    # Caching-Marker (Anthropic-Stil, von LiteLLM/Hermes injiziert). Traegt
    # keinen Anwendertext, nur einen Schalter -> validieren statt maskieren.
    # Wichtig: Hermes setzt das Feld automatisch, sobald Provider-ID oder
    # Hostname den Token "litellm" enthaelt. Ein Selbsthoster mit der
    # Subdomain litellm.seine-domain.de wuerde ohne diesen Eintrag ab der
    # ersten Folge-Nachricht hart geblockt (QA-Audit).
    "cache_control",
)

ALLOWED_MESSAGE_FIELDS = frozenset(MESSAGE_FIELDS_MASKED + MESSAGE_FIELDS_VALIDATED)

# Protokoll-Rollen. Eine unbekannte Rolle ist entweder ein Client-Fehler oder
# ein Schmuggelversuch (Freitext im role-Feld) -> fail-closed.
ALLOWED_ROLES = frozenset(
    {"system", "user", "assistant", "tool", "function", "developer"}
)

# Opake Korrelations-IDs (tool_call_id, tool_calls[].id): vom Modell bzw. der
# API vergeben, nie Freitext. Bewusst eng: alles, was hier nicht passt, ist
# kein legitimer Identifier.
# ACHTUNG: wird mit ``fullmatch`` benutzt, NICHT mit ``match``. ``$`` matcht
# in Python auch VOR einem abschliessenden Newline -- mit ``^...$`` und
# ``match`` waere "call_1\n" ein gueltiger Identifier gewesen und der
# Zeilenumbruch ein kleiner, aber echter Schmuggelkanal (Security-Audit F6).
OPAQUE_ID_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")

# Maximale Verschachtelungstiefe in ``arguments``. Echte Tool-Argumente sind
# flach; alles darueber ist entweder kaputt oder ein Versuch, die Guardrail in
# einen RecursionError laufen zu lassen (unkontrollierter Fehlerpfad statt
# fail-closed, Security-Audit F7).
MAX_JSON_DEPTH = 64

# Fuellzeichen, das im Verifikationsdurchlauf an die Stelle bekannter
# Platzhalter tritt (siehe _verify_no_pii_left).
_PLACEHOLDER_PROBE_FILLER = " "

# Felder eines einzelnen tool_call-Eintrags (gleiche Logik eine Ebene tiefer).
TOOL_CALL_ALLOWED_FIELDS = frozenset({"id", "type", "index", "function"})
TOOL_CALL_FUNCTION_ALLOWED_FIELDS = frozenset({"name", "arguments"})
# ``type`` fehlt bei manchen Clients ganz (historisch impliziert "function").
ALLOWED_TOOL_CALL_TYPES = frozenset({"function"})

# Erlaubte Struktur von ``cache_control``. Bewusst eng: ein Marker hat genau
# diese zwei Felder und diese Werte -- alles andere ist kein Caching-Hinweis,
# sondern ein Kanal, den niemand geprueft hat.
CACHE_CONTROL_ALLOWED_FIELDS = frozenset({"type", "ttl"})
CACHE_CONTROL_TYPES = frozenset({"ephemeral"})
CACHE_CONTROL_TTLS = frozenset({"5m", "1h"})

# Felder, die es in der Praxis gibt, die wir aber (noch) NICHT behandeln.
# Sie blocken wie jedes unbekannte Feld -- werden in der Meldung aber beim
# Namen genannt, damit ein Betreiber weiss, woran er ist. Die Namen stammen
# aus dieser konstanten Liste, nie aus dem Request (Gesetz 5).
KNOWN_UNSUPPORTED_MESSAGE_FIELDS = frozenset({
    "audio",
    "annotations",
    "thinking_blocks",
    "reasoning",
    "redacted_thinking_blocks",
    "provider_specific_fields",
    "prefix",
    "partial",
})

# Freitext-Felder eines Streaming-Deltas NEBEN ``content``. Sie brauchen
# dieselbe Sliding-Window-Behandlung wie der Textkanal: ein Platzhalter kann
# auch hier mitten durch einen Chunk brechen. Als Liste statt einzeln
# behandelt, damit ein weiteres Feld eine Zeile ist und nicht wieder ein
# vergessener Pfad (``refusal`` war genau das, Security-Audit S1).
STREAM_TEXT_DELTA_FIELDS = ("reasoning_content", "refusal")

# Betreiber-Diagnose. Blockmeldungen gehen an den Client; hier landet
# zusaetzlich serverseitig, WAS geblockt hat -- Feldnamen bzw. Fingerprints,
# niemals Werte.
_LOG = logging.getLogger("datenschleuse")

# Erlaubte Felder in der Blockmeldung nennen wir NIE mit Client-Werten,
# sondern nur mit dieser konstanten, unveraenderlichen Liste (Gesetz 5).
_ALLOWED_FIELDS_HINT = ", ".join(sorted(ALLOWED_MESSAGE_FIELDS))


def _image_part_url(part: Dict[str, Any]) -> str:
    """Liest die URL aus einem ``image_url``-Part. Das OpenAI-Format ist
    ``{"type": "image_url", "image_url": {"url": "..."}}``, manche Clients
    schicken den String direkt — beides akzeptieren, nichts erraten."""
    value = part.get("image_url")
    if isinstance(value, dict):
        url = value.get("url")
        return url if isinstance(url, str) else ""
    return value if isinstance(value, str) else ""


def _split_data_url(url: str) -> Tuple[str, Optional[bytes]]:
    """``data:image/png;base64,XXXX`` -> ``("image/png", b"...")``.

    Liefert ``(mime, None)``, wenn aus der URL keine Bilddaten gewonnen
    werden konnten -- der Aufrufer entscheidet dann fail-closed. ``mime``
    ist dabei das verlaessliche Signal FUER DEN AUFRUFER, WARUM es keine
    Bytes gab: leer, wenn ueberhaupt kein ``data:``-Header mit
    base64-Marker erkannt wurde (z.B. eine externe http-URL); gesetzt,
    wenn der Header erkannt wurde, das Payload danach aber fehlt oder
    nicht dekodierbar ist. WICHTIG: mime muss deshalb VOR der
    Payload-Pruefung berechnet werden -- sonst geht bei einem leeren
    Payload (``data:image/png;base64,``) das mime-Signal verloren und ein
    Aufrufer kann eine leere eingebettete data:-URL nicht mehr von einer
    echten externen URL unterscheiden (siehe QA-Finding zu Finding 5)."""
    if not isinstance(url, str) or not url.startswith("data:"):
        return "", None
    header, _, payload = url.partition(",")
    if "base64" not in header:
        return "", None
    mime = header[len("data:") :].split(";")[0].strip()
    if not payload:
        return mime, None
    try:
        return mime, base64.b64decode(payload, validate=True)
    except Exception:
        return mime, None


def _to_data_url(raw: bytes, mime: str) -> str:
    return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"

# Hinweis an das Ziel-Modell, dass Platzhalter wie <PERSON_1>/<ADDRESS_0>
# bewusste Anonymisierung sind, kein Fehler. Ohne diesen Hinweis neigen
# manche Modelle dazu, Platzhalter als vermeintlichen Tippfehler zu behandeln
# und nachzufragen oder den Text "korrigieren" zu wollen -- das zerstoert
# sowohl die UX als auch (im schlimmsten Fall) die Platzhalter selbst, wenn
# das Modell sie in seiner Antwort umformuliert statt wortwoertlich
# zurueckzugeben (worauf die Re-Identifikation angewiesen ist).
#
# Live-Deploy-Befund (2026-07-29, preview-api-Livetest gegen gpt-4o-mini via
# eurouter.ai): eine fruehere Fassung enthielt ein konkretes Beispiel
# ("<PERSON_1> statt \"Hans Müller\""), um das Prinzip zu illustrieren.
# Ergebnis: das Modell griff den Beispielnamen als vermeintlich "echten Wert"
# auf und antwortete mit "Hallo Hans Müller!" -- obwohl der reid_map ein
# GANZ ANDERER Name zugrunde lag. Kein PII-Leck (der erfundene Name ist
# harmlos), aber eine kaputte, fuer den Nutzer verwirrende Antwort. Reproduziert
# mit UND ohne zusaetzliche eigene System-Message. Deshalb bewusst OHNE
# konkretes Namensbeispiel formuliert -- das Prinzip laesst sich abstrakt
# erklaeren, ohne dem Modell einen Namen zum Nachplappern anzubieten.
#
# E2E-Befund (2026-08-19, DATENSCHLE-67, Round-Trip-Beweis gegen den echten
# Stack): dieselbe Fehlerklasse steckte eine Ebene tiefer noch drin. Die
# Beispiele lauteten frueher <PERSON_1>, <ADDRESS_0>, ... -- also exakt die
# Form <TYP_ZAHL>, die Masker._placeholder_for() auch fuer ECHTE Werte
# vergibt. Im Beweislauf war <PERSON_1> gleichzeitig Beispiel im Hinweis UND
# echter Platzhalter fuer "Thomas Schneider". Das Modell sieht denselben Token
# dann in zwei voellig verschiedenen Bedeutungen; greift es das Beispiel auf,
# macht die Re-Identifikation stillschweigend den echten Namen daraus und
# setzt ihn an eine Stelle, an die er nie gehoerte. Kein PII-Leck (der
# Klartext geht weiterhin nicht raus), aber eine falsche Antwort -- und zwar
# eine stille (siehe docs/HEADROOM.md zur Fail-Semantik).
#
# Erster Fix-Versuch und was er lehrte (ebenfalls DATENSCHLE-67): die
# Beispiele wurden auf die Schablone <PERSON_N> umgestellt, mit dem Zusatz
# "wobei N fuer eine Ziffer steht". Kollisionsfrei -- aber gemessen gegen
# llama3.1:8b brandgefaehrlich: das Modell setzte die Ziffer PFLICHTBEWUSST
# ein und gab <PERSON_1> zurueck, wo <PERSON_0> stand. 3 von 3 Laeufen, bei
# temperature 0. Damit war jeder Platzhalter der Antwort unbrauchbar -- die
# Re-Identifikation findet <PERSON_1> nicht im Mapping und laesst ihn stehen
# (stiller Fehler) oder trifft eine ANDERE Person, falls es einen echten
# <PERSON_1> gibt. Aus einem seltenen Kollisionsrisiko war ein systematischer
# Totalausfall geworden.
#
# Die allgemeine Lehre aus beiden Befunden: Was der Hinweis dem Modell
# hinhaelt, baut das Modell nach -- egal ob Beispielname ("Hans Mueller"),
# echter Beispiel-Platzhalter (<PERSON_1>) oder Schablone (<PERSON_N>).
# Deshalb enthaelt der Hinweis GAR KEINEN Token in spitzen Klammern mehr; er
# beschreibt das Prinzip in Worten und schuetzt die Nummer ausdruecklich.
# Gemessen: 3 von 3 Laeufen indextreu. Abgesichert durch
# TestNoticePlaceholderCollision in test/test_datenschleuse_guardrail.py.
ANONYMIZATION_NOTICE = (
    "Hinweis: Dieser Text wurde vor der Übermittlung automatisch pseudonymisiert. "
    "Angaben in spitzen Klammern sind Platzhalter und stehen bewusst anstelle "
    "der jeweils echten Werte. Das ist kein Tippfehler und keine fehlende "
    "Information — behandle jeden Platzhalter als den echten Wert, den er "
    "ersetzt, und gib ihn in deiner Antwort exakt so zurück, wie er dir "
    "übergeben wurde, mit unveränderter Nummer (nicht umformulieren, nicht "
    "umnummerieren, nicht durch einen Beispielwert ersetzen, nicht danach "
    "fragen)."
)


class DatenschleuseConfigError(Exception):
    """Fehlerhafte BETREIBER-Konfiguration. Wird beim START geworfen, nicht
    beim ersten Request.

    Der Unterschied ist nicht kosmetisch: ein Konfigurationsfehler, der erst
    im Betrieb auffaellt, erscheint dort als Ausfall -- der Betreiber sucht
    dann an der falschen Stelle. Vorbild ist ``QiStateStore``, das aus
    demselben Grund im Konstruktor abbricht.

    Bewusst KEIN Subtyp von DatenschleuseBlocked: das hier ist kein
    Request, der geblockt wird, sondern eine Instanz, die gar nicht erst
    laufen darf.
    """


class DatenschleuseBlocked(Exception):
    """Wird geworfen, wenn fail-closed greift. LiteLLM behandelt eine im
    pre_call-Hook geworfene Exception als Guardrail-Block -> Request wird
    NICHT ans LLM weitergereicht (kein unmaskiertes PII verlaesst das System)."""


# ===========================================================================
# Betreiber-Geheimnis des Freigabe-Headers (DATENSCHLE-69, Runde 4, F2)
# ===========================================================================
#: ENV-Name des Header-Geheimnisses. Als Konstante, weil ihn ausser dem
#: Konstruktor auch die Konfigurationsmeldungen nennen muessen -- ein
#: Betreiber, der beim Start abbricht, braucht den Namen des Schalters.
APPROVAL_SECRET_ENV = "DATENSCHLEUSE_APPROVAL_HEADER_SECRET"

#: Mindestlaenge des Header-Geheimnisses. SETZUNG (von Oliver entschieden,
#: Runde 4) -- aber keine willkuerliche, deshalb die Herleitung:
#:
#: Dieser Schalter schaltet den Stufe-2-SCHUTZ AB. Ein Geheimnis, das man
#: raten kann, ist auf diesem Schalter kein Geheimnis -- und schlimmer als
#: gar keines, weil der Betreiber sich darauf verlaesst.
#:
#: Das hier ist ein Maschine-zu-Maschine-Geheimnis, kein Passwort, das sich
#: ein Mensch merken muss. Es soll deshalb ERZEUGT und nicht ausgedacht
#: werden. Die Zahl ist genau so gewaehlt, dass sie das erzwingt:
#: ``secrets.token_urlsafe(24)`` liefert exakt 32 Zeichen -- die Grenze
#: liegt also auf dem kleinsten sinnvollen Ergebnis des empfohlenen
#: Erzeugungswegs, und der in der Fehlermeldung genannte Befehl
#: (``token_urlsafe(32)``, 43 Zeichen) passt bequem darueber.
#:
#: Ein ausgedachter Wert kann die Grenze weiterhin erreichen -- eine deutsche
#: Passphrase mit 32+ Zeichen ist zulaessig. Ausgeschlossen wird nur die
#: Klasse, die sich brute-forcen laesst.
#:
#: KEIN Bestandsschutz noetig: der Header-Weg ist NEU in diesem Branch (er
#: entstand als Antwort auf F2 aus Runde 1). Es kann keine Installation
#: geben, die ein kuerzeres Geheimnis nutzt -- wir brechen nichts.
APPROVAL_SECRET_MIN_LEN = 32

#: Der empfohlene Erzeugungsbefehl. Steht in der Fehlermeldung, weil eine
#: Meldung, die nur verbietet, den Betreiber raten laesst -- und er raet dann
#: etwas, das gerade so durchkommt. Vorbild: die Fernet-Key-Meldung in
#: configure_reid_crypto().
APPROVAL_SECRET_HOWTO = (
    'python3 -c "import secrets; print(secrets.token_urlsafe(32))"'
)


def _validate_approval_header_secret(roh: Any) -> str:
    """Prueft das Header-Geheimnis. BEIM START, nicht beim ersten Request.

    Der Schwesterschalter zu ``configure_reid_crypto()``. Der bekam in dieser
    Runde die Start-Pruefung; dieser hier blieb ungeschuetzt -- und lief
    deshalb genau in die Fehlerklasse, die dort schon geschlossen war: eine
    unbrauchbare Konfiguration faellt erst im Betrieb auf, dort als
    scheinbarer Ausfall.

    Geprueft werden GENAU die Eigenschaften, auf die sich der Vergleich in
    ``_operator_approved`` verlaesst -- nicht mehr:

    * ``str``: ein Nicht-String stirbt sonst am ``.strip()`` im Konstruktor,
      als AttributeError, der dem Betreiber nichts sagt.
    * UTF-8-darstellbar: ``os.getenv`` gibt undekodierbare Bytes als
      Surrogate zurueck (``surrogateescape``). Die fliegen erst beim
      ``.encode("utf-8")`` im Request auf -- also wieder mitten im Vergleich.
    * nicht ausschliesslich Leerzeichen: das wuerde den Header-Weg still
      ABSCHALTEN, waehrend der Betreiber glaubt, er habe ihn konfiguriert.
      Ein stiller Zustand ist hier gefaehrlicher als ein Abbruch.

    BEWUSST NICHT geprueft: eine Mindestlaenge. Das waere eine
    Passwort-Policy und damit eine Betreiber-Entscheidung, keine Frage der
    Bauart -- und sie wuerde bestehende Setups beim Update hart brechen.
    Vermerkt am Work Item statt hier stillschweigend entschieden.

    Der LEERE Wert bleibt gueltig: er ist die dokumentierte Abschaltung des
    Header-Wegs (sicherer Default). Ein Abbruch dort koennte niemand mehr
    ohne Header-Freigabe betreiben.
    """
    if roh is None:
        return ""
    if not isinstance(roh, str):
        raise DatenschleuseConfigError(
            f"{APPROVAL_SECRET_ENV} muss eine Zeichenkette sein (war: "
            f"{type(roh).__name__}). Erwartet wird das Geheimnis im Klartext; "
            "leer oder ungesetzt schaltet den Header-Freigabeweg ab."
        )
    if roh == "":
        return ""
    try:
        roh.encode("utf-8")
    except UnicodeEncodeError:
        # Bewusst OHNE den Wert in der Meldung (Gesetz 5) -- und ohne den
        # Text der Ausnahme, der die verantwortlichen Zeichen mitfuehrt.
        raise DatenschleuseConfigError(
            f"{APPROVAL_SECRET_ENV} enthaelt Zeichen, die sich nicht als "
            "UTF-8 darstellen lassen (typisch: undekodierbare Bytes aus der "
            "Umgebung, die Python als Surrogate durchreicht). Der Vergleich "
            "wuerde damit erst im Request scheitern -- Abbruch beim Start."
        ) from None
    geputzt = roh.strip()
    if not geputzt:
        raise DatenschleuseConfigError(
            f"{APPROVAL_SECRET_ENV} besteht nur aus Leerzeichen. Das wuerde "
            "den Header-Freigabeweg still ABSCHALTEN, waehrend die "
            "Konfiguration so aussieht, als sei er aktiv. Entweder ein "
            "echtes Geheimnis setzen oder die Variable ganz weglassen."
        )
    if len(geputzt) < APPROVAL_SECRET_MIN_LEN:
        # Die LAENGE nennen wir, den WERT nie (Gesetz 5) -- auch ein
        # untaugliches Geheimnis ist ein Geheimnis und darf nicht ueber die
        # Startmeldung ins Log wandern.
        raise DatenschleuseConfigError(
            f"{APPROVAL_SECRET_ENV} ist zu kurz "
            f"({len(geputzt)} Zeichen, mindestens {APPROVAL_SECRET_MIN_LEN}). "
            "Dieser Schalter schaltet den Stufe-2-SCHUTZ ab -- ein Geheimnis, "
            "das man raten kann, ist auf ihm kein Geheimnis, sondern eine "
            "Zusage, auf die sich der Betreiber faelschlich verlaesst. "
            "Es soll erzeugt und nicht ausgedacht werden: "
            f"{APPROVAL_SECRET_HOWTO}"
        )
    return geputzt


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


#: Prozesslokaler Salt fuer den Feldnamen-Fingerprint.
#:
#: Einmal beim Start erzeugt, verlaesst den Prozess nie. Bewusst NICHT
#: konfigurierbar: ein Salt, den man setzen kann, wird irgendwo eingecheckt
#: -- und ein bekannter Salt ist kein Salt.
_FIELD_FINGERPRINT_SALT = os.urandom(16)


def _field_fingerprint(name: Any) -> str:
    """Stabiler, wertfreier Kurz-Fingerprint eines Feldnamens.

    Warum nicht einfach den Namen ausgeben: ein FELDNAME ist Client-Inhalt.
    ``{"Max Mustermann": ...}`` oder eine IBAN als Schluessel sind trivial
    konstruierbar -- und die Blockmeldung wird geloggt und an den Client
    zurueckgegeben. Der Fingerprint gibt dem Betreiber trotzdem eine
    Handhabe: derselbe Feldname ergibt denselben Wert, damit laesst sich ein
    blockendes Feld eingrenzen, ohne dass sein Inhalt das System verlaesst.

    GESALZEN, und das ist nicht kosmetisch: ohne Salt war dies ein nacktes
    SHA-256 ueber ``repr(name)``, gekuerzt auf 8 Hex-Zeichen. Feldnamen sind
    extrem entropiearm -- ein Name, eine IBAN, eine E-Mail-Adresse. Wer
    einen Fingerprint aus einem Log sieht, rechnet ihn per Woerterbuch
    zurueck. Der Schutz gab damit genau das preis, wovor er schuetzen
    sollte. Mit prozesslokalem Salt bleibt die zugesagte Eigenschaft
    (gleicher Name -> gleicher Wert innerhalb eines Prozesses) erhalten,
    die Rueckrechnung nicht.
    """
    return hashlib.blake2s(
        repr(name).encode("utf-8"), key=_FIELD_FINGERPRINT_SALT, digest_size=4
    ).hexdigest()


class _UnsafeJson(Exception):
    """JSON, das zwar parst, aber nicht eindeutig ist -- und deshalb nicht
    zuverlaessig geprueft werden kann. Bewusst KEIN ValueError-Subtyp, damit
    es nicht versehentlich im Parser-Fallback landet."""


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """object_pairs_hook: lehnt doppelte JSON-Schluessel ab.

    ``json.loads`` behaelt bei doppelten Keys still den LETZTEN Wert. Der
    erste wird nie geparst, nie analysiert -- und wenn der Rest der Struktur
    sauber ist, ging der unveraenderte Rohstring hinaus, PII inklusive
    (Security-Audit F2). Doppelte Keys sind in echten Tool-Argumenten
    bedeutungslos und als Umgehung trivial zu konstruieren: blocken.
    """
    seen = set()
    for key, _ in pairs:
        if key in seen:
            # Gesetz 5: der Schluessel selbst ist Client-Inhalt -> nie ausgeben.
            raise _UnsafeJson("doppelter Schluessel in arguments")
        seen.add(key)
    return dict(pairs)


def _reject_json_constant(name: str) -> Any:
    """parse_constant: ``NaN``/``Infinity``/``-Infinity`` sind kein striktes
    JSON. Python parst sie klaglos und emittiert sie wieder -- Empfaenger mit
    striktem Parser bekommen dann kaputte Argumente (Security-Audit F8)."""
    raise _UnsafeJson("nicht-standardkonforme JSON-Konstante in arguments")


def json_escaped_mapping(mapping: Dict[str, str]) -> Dict[str, str]:
    """Baut aus dem reid_map ein Mapping, dessen WERTE bereits so escaped
    sind, wie sie INNERHALB eines JSON-Strings stehen muessen.

    Warum: auf dem Rueckweg wird ein Platzhalter in
    ``tool_calls[].function.arguments`` durch den Klartext ersetzt. Steht in
    diesem Klartext ein Anfuehrungszeichen oder Backslash (``Max "Maxi"
    Mustermann``), macht ein naives ``str.replace`` aus gueltigem JSON
    kaputtes JSON -- der Tool-Aufruf ist beim Client unbrauchbar. Deshalb
    wird der Wert vorher JSON-escaped (``json.dumps`` liefert ihn mit
    Anfuehrungszeichen, die beiden aeusseren fallen weg).
    """
    return {k: json.dumps(v, ensure_ascii=False)[1:-1] for k, v in (mapping or {}).items()}


def _reidentify_json_node(node: Any, mapping: Dict[str, str]) -> Any:
    """Ersetzt Platzhalter in allen Strings eines geparsten JSON-Baums
    (Werte UND Schluessel -- maskiert wurden beide, siehe Masking-Pfad)."""
    if isinstance(node, str):
        return reidentify_full(node, mapping)
    if isinstance(node, list):
        return [_reidentify_json_node(v, mapping) for v in node]
    if isinstance(node, dict):
        return {
            _reidentify_json_node(k, mapping): _reidentify_json_node(v, mapping)
            for k, v in node.items()
        }
    return node


def reidentify_json_arguments(raw: Any, mapping: Dict[str, str]) -> Any:
    """Re-Identification fuer einen ``arguments``-JSON-String.

    Strukturerhaltend: geparst, in den Strings ersetzt, wieder serialisiert.
    Damit uebernimmt ``json.dumps`` das Escaping und das Ergebnis ist garantiert
    wieder gueltiges JSON. Nur wenn ``raw`` gar kein gueltiges JSON ist (Modelle
    liefern gelegentlich kaputte ``arguments``), wird auf einen Textersatz mit
    JSON-escapten Werten zurueckgefallen -- die beste verfuegbare Naeherung fuer
    einen String, der JSON sein wollte.
    """
    if not mapping or not isinstance(raw, str) or not raw:
        return raw
    if not any(placeholder in raw for placeholder in mapping):
        # Kein Platzhalter enthalten -> nichts zu ersetzen. Wichtig, damit
        # PII-freie Tool-Aufrufe den Client BYTE-IDENTISCH erreichen und
        # nicht durch eine ueberfluessige Re-Serialisierung laufen.
        return raw
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return reidentify_full(raw, json_escaped_mapping(mapping))
    return json.dumps(_reidentify_json_node(parsed, mapping), ensure_ascii=False)


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
        image_redactor_url: Optional[str] = None,
        image_policy: Optional[str] = None,
        qi_risk_preset: Optional[str] = None,
        qi_state_key: Optional[str] = None,
        qi_state_db: Optional[str] = None,
        qi_state_ttl_seconds: Optional[int] = None,
        qi_store: Any = None,
        approval_header_secret: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        # Krypto-Konfiguration ZUERST und beim START (W2/W3). Ein
        # ungueltiger Schluessel oder eine unsinnige TTL bricht hier ab --
        # nicht erst beim ersten Request, wo der Betreiber es fuer einen
        # Ausfall haelt und an der falschen Stelle sucht. Vorbild:
        # QiStateStore.
        configure_reid_crypto()

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

        # --- Bild-Parts (multimodal) ----------------------------------------
        # Text war nie das ganze Problem: ein Screenshot mit derselben Adresse
        # drauf lief bis hierher unveraendert zum Modell, weil unten nur
        # ``type == "text"``-Parts maskiert werden. Presidio kann Bilder
        # schwaerzen (OCR + Boxen), das laeuft aber in einem EIGENEN Dienst
        # (microsoft/presidio-image-redactor, POST /redact).
        #
        # Policy statt stillem Default, weil beide Enden gefaehrlich sind: ohne
        # Redactor-Container waere "durchlassen" ein stilles Leck und "blocken"
        # ein hartes Verhaltensbruch. Deshalb explizit:
        #   redact = schwaerzen, Fehler => Block (empfohlen, braucht den Dienst)
        #   block  = Bilder grundsaetzlich ablehnen (sicher ohne Extra-Dienst)
        #   pass   = altes Verhalten, Bilder gehen UNGEPRUEFT raus (bewusste Luecke)
        self.image_redactor_url = (
            image_redactor_url
            or kwargs.pop("presidio_image_redactor_url", None)
            or os.getenv("PRESIDIO_IMAGE_REDACTOR_API_BASE")
            or ""
        ).rstrip("/")
        policy = (kwargs.pop("image_policy", None) or image_policy or os.getenv("DATENSCHLEUSE_IMAGE_POLICY") or "").strip().lower()
        if not policy:
            # Kein expliziter Wunsch: mit Dienst schwaerzen, ohne Dienst
            # ablehnen. Nie stillschweigend durchlassen — das war die Luecke.
            policy = "redact" if self.image_redactor_url else "block"
        if policy not in IMAGE_POLICIES:
            raise ValueError(
                f"image_policy={policy!r} unbekannt — erlaubt: {', '.join(sorted(IMAGE_POLICIES))}"
            )
        if policy == "redact" and not self.image_redactor_url:
            raise ValueError(
                "image_policy='redact' ohne image_redactor_url/"
                "PRESIDIO_IMAGE_REDACTOR_API_BASE — der Dienst muss erreichbar "
                "konfiguriert sein, sonst waere jedes Bild ein Blindflug."
            )
        self.image_policy = policy

        # --- Betreiber-Freigabe fuer Stufe 2 (DATENSCHLE-69, Security-F2) ---
        # Der Header-Weg ist NUR aktiv, wenn der Betreiber ein Geheimnis
        # konfiguriert hat. Ohne Geheimnis waere der Header wieder blosse
        # Client-Eingabe -- also genau der Defekt, den wir schliessen. Der
        # sichere Default ist deshalb "Header-Weg aus", nicht "offen".
        # Geprueft BEIM START (Runde 4, F2) -- siehe
        # _validate_approval_header_secret. Der ``or``-Fallback bleibt: das
        # erste WAHRE Glied gewinnt, ein leerer Wert faellt weiter durch.
        self.approval_header_secret = _validate_approval_header_secret(
            approval_header_secret
            or kwargs.pop("approval_header_secret", None)
            or os.getenv(APPROVAL_SECRET_ENV)
            or ""
        )
        # Einmal kodiert statt bei jedem Request: ``hmac.compare_digest`` ist
        # auf BYTES definiert und verweigert ``str`` mit Nicht-ASCII (F2).
        # Der Vergleich bleibt auf Bytes konstantzeitig.
        self._approval_secret_bytes = self.approval_header_secret.encode("utf-8")

        # --- Schutzklassen-Modell (IMMER aktiv, keine Konfigurationsoption) --
        # Laedt presidio/sensitivity-keywords.yml einmalig. Fail-closed beim
        # START: eine kaputte/fehlende Config wirft SensitivityConfigError und
        # verhindert, dass der Guardrail (und damit der ganze Proxy) ueberhaupt
        # hochkommt -- blind klassifizieren waere gefaehrlicher als nicht
        # starten. Siehe docs/SENSITIVITY-INTEGRATION.md.
        self.classifier = sc.SensitivityClassifier()

        # --- Quasi-Identifier-Layer (opt-in) --------------------------------
        # Aktiv, sobald ein Risiko-Preset gesetzt ist (Config: qi_risk_preset).
        # Ist es None/"off", bleibt der QI-Layer komplett aus -> Verhalten exakt
        # wie bisher (wichtig: bestehende Tests konstruieren die Guardrail ohne
        # Preset und brauchen daher KEINEN State-Key).
        self.qi_risk_preset = kwargs.pop("qi_risk_preset", None) or qi_risk_preset
        self.qi_enabled = bool(
            self.qi_risk_preset and str(self.qi_risk_preset).strip().lower() != "off"
        )
        self.qi_threshold = qig.threshold_for_preset(self.qi_risk_preset)
        self._qi_store = None
        if self.qi_enabled:
            if qi_store is not None:
                # Test-/DI-Pfad: fertigen Store injizieren.
                self._qi_store = qi_store
            else:
                # Produktionspfad: verschluesselten TTL-Store bauen. Fehlt der
                # Schluessel, wirft QiStateStore beim Konstruieren -> fail-closed
                # beim START (kein unverschluesselter Weiterbetrieb). qi_state
                # wird LAZY importiert, damit dieses Modul ohne cryptography
                # importierbar bleibt, solange der QI-Layer aus ist.
                import qi_state as qs

                ttl = (
                    int(qi_state_ttl_seconds)
                    if qi_state_ttl_seconds is not None
                    else int(os.getenv("DATENSCHLEUSE_STATE_TTL_SECONDS", qs.DEFAULT_TTL_SECONDS))
                )
                self._qi_store = qs.QiStateStore(
                    db_path=qi_state_db or os.getenv("DATENSCHLEUSE_STATE_DB"),
                    fernet_key=qi_state_key or os.getenv("DATENSCHLEUSE_STATE_KEY"),
                    ttl_seconds=ttl,
                )
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

    # ---- Presidio Image Redactor (Bild-Parts) -----------------------------
    async def _redact_image(self, data_url: str) -> str:
        """Schickt ein ``data:``-Bild durch ``POST /redact`` und gibt die
        geschwaerzte Fassung als neue ``data:``-URL zurueck.

        Fail-closed wie ``_analyze``: jeder Fehler wird zu DatenschleuseBlocked,
        damit nie ein ungepruefres Bild durchrutscht.

        GRENZE, die man kennen muss: Der Image-Redactor bringt seine EIGENE
        Presidio-Instanz mit und kennt deshalb die deutschen Custom-Recognizer
        aus presidio/recognizers-config.yml NICHT. Im Bild werden also die
        eingebauten Typen erkannt (Namen, E-Mail, Telefon, IBAN, ...), aber
        z.B. ein deutsches Aktenzeichen nicht zwingend. Das ist der Grund,
        warum 'block' fuer sensible Setups die ehrlichere Wahl bleibt.
        """
        mime, raw = _split_data_url(data_url)
        if raw is None:
            # _split_data_url liefert (mime, None) in DREI unterschiedlichen
            # Faellen, die je eine zutreffende Meldung verdienen (kein
            # Bildinhalt/Base64-Fragment in der Meldung -- Gesetz 5). mime
            # allein reicht NICHT als Unterscheidungsmerkmal (nur binaer),
            # deshalb zusaetzlich pruefen, ob nach dem Komma ueberhaupt ein
            # Payload vorlag -- ohne dessen Inhalt in die Meldung zu uebernehmen:
            # - mime leer: es war ueberhaupt keine ``data:``-URL (z.B. eine
            #   externe http/https-URL), die das Modell serverseitig abrufen
            #   wuerde -- also am Proxy vorbei.
            # - mime gesetzt, kein Payload nach dem Komma: eine eingebettete
            #   data:-URL ohne jeden Bildinhalt (leeres Base64-Feld).
            # - mime gesetzt, Payload vorhanden: der data:-Header wurde
            #   erkannt, aber das Base64-Payload liess sich nicht dekodieren
            #   (kaputte/beschaedigte Daten).
            if not mime:
                raise DatenschleuseBlocked(
                    "Bild-Part verweist auf eine externe URL statt auf eingebettete "
                    "Daten; der Inhalt kann nicht geprueft werden (fail-closed)."
                )
            payload = data_url.partition(",")[2] if isinstance(data_url, str) else ""
            if not payload:
                raise DatenschleuseBlocked(
                    "Bild-Part ist eine eingebettete data:-URL ohne Payload "
                    "(leeres Base64-Feld); der Inhalt kann nicht geprueft "
                    "werden (fail-closed)."
                )
            raise DatenschleuseBlocked(
                "Bild-Part enthaelt eine data:-URL mit ungueltigem oder "
                "beschaedigtem Base64-Payload; der Inhalt kann nicht "
                "dekodiert werden (fail-closed)."
            )
        try:
            files = {"image": ("upload", raw, mime or "application/octet-stream")}
            async with httpx.AsyncClient(timeout=self.request_timeout) as client:
                resp = await client.post(
                    f"{self.image_redactor_url}/redact",
                    files=files,
                    data={"data": '{"color_fill": "0"}'},
                )
            resp.raise_for_status()
            redacted = resp.content
            if not redacted:
                raise ValueError("leere Antwort vom Image-Redactor")
        except DatenschleuseBlocked:
            raise
        except Exception as exc:  # fail-closed
            raise DatenschleuseBlocked(
                f"Presidio Image Redactor nicht erreichbar/fehlerhaft ({exc}); "
                f"Request blockiert (fail-closed, kein ungeprueftes Bild)."
            ) from exc
        return _to_data_url(redacted, mime or "image/png")

    async def _handle_image_part(self, part: Dict[str, Any]) -> None:
        """Wendet die konfigurierte Bild-Policy auf einen ``image_url``-Part an.
        Mutiert den Part in-place (wie der Text-Pfad auch)."""
        if self.image_policy == "pass":
            return
        if self.image_policy == "block":
            raise DatenschleuseBlocked(
                "Bild-Anhaenge sind blockiert (image_policy='block'). Die "
                "Datenschleuse maskiert Text; Bilder muessten geschwaerzt "
                "werden, wofuer der Image-Redactor-Dienst noetig ist."
            )
        url = _image_part_url(part)
        if not url:
            raise DatenschleuseBlocked(
                "Bild-Part ohne lesbare URL — Inhalt nicht pruefbar (fail-closed)."
            )
        redacted = await self._redact_image(url)
        target = part.get("image_url")
        if isinstance(target, dict):
            target["url"] = redacted
        else:
            part["image_url"] = redacted

    # ---- Pre-Call: PII maskieren ------------------------------------------
    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict:
        """Der Eingang -- und die Zusicherung, dass auch ein BLOCK sauber
        endet.

        Duenner Mantel um ``_pre_call_guarded``. Er existiert fuer genau
        einen Fall: der Re-Sync des Logging-Schnappschusses lief nur auf dem
        ERFOLGSPFAD. Wird ein Request geblockt, blieb der unmaskierte
        Schnappschuss stehen und ging an die FAILURE-Callbacks. Der
        Provider-Call war verhindert, das Log-Leck nicht.

        Und zwar ausgerechnet bei den schutzwuerdigsten Daten: geblockt
        wird, was zu sensibel zum Rauslassen ist (Stufe 2/3) oder was die
        Guardrail nicht pruefen kann. Ein Request, der zu heikel fuer das
        Modell ist, darf nicht ungeschuetzt im Log stehen.

        Der Mantel faengt NICHTS ab -- jede Ausnahme fliegt unveraendert
        weiter, der Block bleibt ein Block. Er raeumt nur den Schnappschuss
        auf, bevor er sie weiterreicht.
        """
        try:
            return await self._pre_call_guarded(
                user_api_key_dict, cache, data, call_type
            )
        except BaseException:
            # Bewusst BaseException und bewusst ohne Filter auf unsere
            # eigenen Ausnahmetypen: WARUM abgebrochen wurde, ist fuer die
            # Frage "steht da noch Klartext" egal. Ein Fehlerpfad, den
            # jemand spaeter hinzufuegt, ist damit automatisch mit abgedeckt
            # -- dieselbe Logik wie beim Neubau des Schnappschusses statt
            # feldweisem Nachziehen.
            try:
                self._redact_logging_snapshot(data)
            except Exception:  # pragma: no cover - der Aufraeumer selbst
                # Der Aufraeumer darf die urspruengliche Ausnahme NIE
                # verdraengen: aus einem sauberen DatenschleuseBlocked
                # wuerde sonst ein opaker Fehler, und waehrend einer
                # Cancellation ein verschluckter Abbruch. Bewusst still --
                # ein Log an dieser Stelle koennte selbst wieder werfen.
                pass
            raise

    async def _pre_call_guarded(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict:
        """Maskiert PII in allen Chat-Messages und legt das Re-Id-Mapping in
        den Metadaten ab. Nur fuer Chat-/Text-Completions relevant."""
        # Route-Pruefung VOR allem anderen (DATENSCHLE-69). Frueher stand hier
        # ein ``return data`` fuer alles Unbekannte -- also unmaskiertes
        # Durchreichen. Jetzt blockt jede Route, die die Guardrail nicht
        # nachweislich beherrscht.
        self._validate_call_type(call_type)

        # Danach die FORM des Payloads (DATENSCHLE-69, zweite Ebene). Der
        # call_type sagt nur, WELCHE Route spricht -- nicht, WIE ihr Body
        # aussieht. Vorher registrierte der Hook die Route und liess die
        # FELDER dieser Route ungeprueft: ``suffix`` neben einem sauberen
        # ``prompt`` und ``tools[].function.description`` neben sauberen
        # ``messages`` gingen unmaskiert hinaus.
        # Kein ``PAYLOAD_ROUTES[call_type]``: ein fehlender Eintrag waere ein
        # KeyError aus dem Hook heraus -- ein unkontrollierter Fehlerpfad
        # statt fail-closed (gleiche Klasse Befund wie MAX_JSON_DEPTH,
        # Security-Audit F7). Passieren kann das nur, wenn jemand eine Route
        # in ALLOWED_CALL_TYPES aufnimmt, ohne ihr ein Payload-Schema zu
        # geben -- genau dann muss sie blocken, nicht ungeprueft laufen.
        route = PAYLOAD_ROUTES.get(call_type)
        if route is None:  # pragma: no cover - Register-Inkonsistenz
            raise DatenschleuseBlocked(
                "Die Route ist zwar zugelassen, hat aber kein hinterlegtes "
                "Payload-Schema -- ihr Body kann deshalb nicht geprueft "
                "werden und der Request ist blockiert (fail-closed)."
            )
        self._validate_payload_shape(data, route)
        self._validate_messages_count(data)
        # Die FORM des Logging-Schnappschusses vor jeder Maskierung
        # (Security-F1): was wir am Ende nicht neu bauen koennen, duerfen wir
        # gar nicht erst maskiert glauben.
        self._validate_snapshot_shape(data)

        messages = data.get("messages")
        masker = Masker()

        # --- Schutzklassen: Metadaten fuer explizite Stufe + Freigabe-Flag ---
        meta_in = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        # Die STUFE darf ein Client weiter setzen: sie kann nur ERHOEHEN
        # (monotone max()-Regel im Klassifizierer), also ist sie kein
        # Bypass-Kanal -- ein Client, der sich hoeher einstuft, schaerft die
        # Pruefung nur.
        requested_level = meta_in.get(sc.SENSITIVITY_LEVEL_KEY)

        # Die FREIGABE darf er NICHT (DATENSCHLE-69, Security-F2). Frueher
        # stand hier ``sc.is_release_approved(meta_in)`` -- also der
        # Request-Body. Damit konnte der Kontrollierte sein eigenes
        # Kontroll-Gate abschalten (gemessen: aus BLOCKED wurde PASSED).
        # Ein Gate, das der Kontrollierte selbst abschalten kann, ist kein
        # Gate.
        # Ein client-gesetztes Re-Id-Siegel zuerst weg -- vor JEDEM Lesen.
        # Ein fremdes, gueltiges Siegel waere sonst ein Orakel auf fremde
        # PII (Replay, siehe _strip_body_reid_map).
        if self._strip_body_reid_map(data):
            _LOG.warning(
                "Re-Id-Siegel im Request-Body gefunden und entfernt. Das "
                "Mapping setzt ausschliesslich die Guardrail selbst; ein "
                "mitgeschicktes Siegel waere die Wiederverwendung eines "
                "fremden (Gesetz 5)."
            )

        if self._strip_body_approval(data):
            # Kein stiller No-op: ein Client, der die Freigabe in den Body
            # schreibt, glaubt sonst, sie wirke. Geloggt wird nur die
            # TATSACHE, nie ein Wert (Gesetz 5). Die Blockmeldung selbst nennt
            # die beiden gueltigen Betreiber-Wege.
            _LOG.warning(
                "Freigabe-Flag im Request-Body gefunden und ignoriert "
                "(entfernt). Freigeben kann nur der Betreiber ueber "
                "Key-Konfiguration oder Header-Geheimnis (Security-F2)."
            )
        approved = self._operator_approved(data, user_api_key_dict)

        # QI-Typen werden nur dann aus der direkten Maskierung herausgehalten,
        # wenn der QI-Layer aktiv ist. Sonst laufen sie wie jeder andere
        # erkannte Identifier durch den Masker (harmloser Platzhalter-Roundtrip).
        qi_types = qig.QI_ENTITY_TYPES if self.qi_enabled else frozenset()

        # Ueber ALLE Messages des Requests gesammelte QI-Instanzen dieses Turns
        # (Typ, Rohwert) + die Text-Slots, in denen sie ggf. generalisiert werden.
        turn_qi: List[Tuple[str, str]] = []
        text_slots: List[Tuple[Any, Any]] = []  # (container, key) auf maskierten Text

        # --- Route /v1/completions: der Text steht in ``prompt`` -----------
        # Eigener Payload, eigener Pfad (DATENSCHLE-69). Danach faellt die
        # Verarbeitung in denselben gemeinsamen Abschluss wie der Chat-Pfad
        # (Mapping in die Metadaten, QI-Layer) -- die messages-Schleife unten
        # laeuft nicht, weil ein /v1/completions-Payload kein ``messages``
        # hat (und ein trotzdem mitgeschicktes ``messages`` blockt, siehe
        # _mask_text_prompt).
        if call_type in CALL_TYPES_TEXT_PROMPT:
            await self._mask_text_prompt(
                data, masker, requested_level, approved, qi_types,
                turn_qi, text_slots,
            )

        # Der messages-Container selbst (DATENSCHLE-66): ist ``messages``
        # vorhanden, aber keine Liste, lief der Request bisher komplett
        # ungeprueft durch -- die Schleife wurde einfach nicht betreten.
        # Dieselbe Bauart wie die content-Container-Luecke (DATENSCHLE-64).
        # Fehlt der Key ganz (None), ist das kein Chat-Request -> unveraendert.
        if messages is not None and not isinstance(messages, list):
            raise DatenschleuseBlocked(
                f"messages vom Typ {type(messages).__name__!r} wird von der "
                "Datenschleuse nicht geprueft und ist deshalb blockiert "
                "(fail-closed). Erlaubt ist nur eine Liste von Nachrichten."
            )

        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    # Bisher: stillschweigend uebersprungen -- also ungeprueft
                    # ans Modell weitergereicht. Was nicht geprueft werden
                    # kann, passiert nicht (Gesetz: fail-closed).
                    raise DatenschleuseBlocked(
                        f"Nachricht vom Typ {type(msg).__name__!r} wird von der "
                        "Datenschleuse nicht geprueft und ist deshalb blockiert "
                        "(fail-closed). Erlaubt sind nur Nachrichten-Objekte."
                    )

                # Form-Pruefung VOR jeder Verarbeitung: unbekannte Felder,
                # fremde Rollen und Nicht-Identifier in ID-Feldern blocken,
                # bevor ueberhaupt ein Analyzer-Call passiert.
                self._validate_message_shape(msg)

                content = msg.get("content")
                if isinstance(content, str):
                    original = content
                    entities = await self._analyze(original)

                    # Schutzklassen: klassifizieren BEVOR irgendetwas maskiert
                    # oder Richtung Cloud aufbereitet wird. Stufe 3 blockt hart
                    # (kein Bypass), Stufe 2 ohne Freigabe blockt ebenfalls.
                    classification = self.classifier.classify(
                        original, entities=entities, requested_level=requested_level,
                    )
                    try:
                        sc.enforce_tier_3_block(classification)
                        sc.enforce_tier_2_gate(classification, approved)
                    except (sc.Tier3Blocked, sc.Tier2ApprovalRequired) as exc:
                        raise DatenschleuseBlocked(str(exc)) from exc

                    direct, qi = self._split_entities(entities, qi_types)
                    msg["content"] = masker.mask(original, direct)
                    # QI-Rohwerte aus dem ORIGINAL (vor Maskierung) ziehen.
                    turn_qi.extend(self._extract_qi_values(original, qi))
                    text_slots.append((msg, "content"))
                elif isinstance(content, list):
                    # Multimodal: Text-Parts maskieren, Bild-Parts nach Policy
                    # schwaerzen/blocken (frueher liefen sie hier unveraendert
                    # durch — genau das war die Luecke). ALLES ANDERE wird
                    # blockiert (Allowlist statt Denylist, DATENSCHLE-57):
                    # ``file``-Parts (hochgeladene PDFs/Dokumente),
                    # ``input_audio``, Parts ohne ``type``-Feld und jeder der
                    # Guardrail unbekannte/kuenftige Typ liefen bislang
                    # ungeprueft durch. Statt jeden bekannten unsicheren Typ
                    # einzeln aufzuzaehlen, gilt: nur was hier explizit als
                    # geprueft-und-sicher erkannt wird, passiert -- alles
                    # Uebrige blockt fail-closed, auch ein Part-Typ, den die
                    # OpenAI-API erst morgen einfuehrt.
                    for part in content:
                        part_type = part.get("type") if isinstance(part, dict) else None
                        if part_type == "image_url":
                            await self._handle_image_part(part)
                            continue
                        if part_type == "text" and isinstance(part.get("text"), str):
                            original = part["text"]
                            entities = await self._analyze(original)

                            classification = self.classifier.classify(
                                original, entities=entities, requested_level=requested_level,
                            )
                            try:
                                sc.enforce_tier_3_block(classification)
                                sc.enforce_tier_2_gate(classification, approved)
                            except (sc.Tier3Blocked, sc.Tier2ApprovalRequired) as exc:
                                raise DatenschleuseBlocked(str(exc)) from exc

                            direct, qi = self._split_entities(entities, qi_types)
                            part["text"] = masker.mask(original, direct)
                            turn_qi.extend(self._extract_qi_values(original, qi))
                            text_slots.append((part, "text"))
                            continue
                        # Nicht auf der Allowlist -> nicht pruefbar -> blocken.
                        # KORREKTUR (Security-Review, DATENSCHLE-64 zweites
                        # Finding): part_type ist NICHT unbedenklich -- es ist
                        # ``part.get("type")``, also ein Wert, den der Client
                        # voll kontrolliert: beliebiger Inhalt, beliebiger Typ
                        # (auch dict/list), beliebige Laenge. Der Auditor hat
                        # belegt, dass eine IBAN, eine Diagnose oder 5000
                        # Flooding-Zeichen ueber genau dieses Feld in die
                        # Meldung durchschlagen -- und DatenschleuseBlocked
                        # wird von LiteLLM geloggt/an den Client zurueckgegeben,
                        # laeuft also potenziell in Logging-Callbacks (Gesetz
                        # 5). Deshalb wird NIE der Wert selbst ausgegeben,
                        # sondern ausschliesslich sein Python-Typname (z.B.
                        # "str", "dict", "NoneType") -- kurz, konstant lang,
                        # ohne jeden Client-Inhalt.
                        raise DatenschleuseBlocked(
                            "Content-Part mit nicht erlaubtem Typ "
                            f"({type(part_type).__name__}) wird von der "
                            "Datenschleuse nicht geprueft und ist deshalb "
                            "blockiert (fail-closed). Erlaubt sind nur "
                            "'text' (mit String-Inhalt) und 'image_url'."
                        )
                elif content is not None:
                    # DATENSCHLE-64 (QA-Folgefund zu DATENSCHLE-57): dieselbe
                    # Luecke wie bei den Parts, nur eine Ebene hoeher. Ein
                    # einzelner Content-Part als dict OHNE umschliessende
                    # Liste -- z.B. {"type": "text", "text": "..."} statt
                    # [{"type": "text", "text": "..."}] -- ist weder
                    # isinstance(content, str) noch isinstance(content, list)
                    # und lief bislang komplett ungeprueft durch (kein
                    # Maskieren, kein Block). Ebenso jede andere Form (Zahl,
                    # bool, ...). Konsequente Allowlist wie bei den Parts: nur
                    # String und Liste sind als pruefbar erkannt, der Rest
                    # blockt fail-closed.
                    #
                    # AUSNAHME, nach erstem Security-Review korrigiert:
                    # content is None (bzw. ein fehlender content-Key, liefert
                    # ueber msg.get() ebenfalls None) ist KEIN Bypass, sondern
                    # spezifikationsgemaess legitim -- eine Assistant-Message
                    # mit ``tool_calls`` hat im OpenAI-Format kein content.
                    # Es gibt dort nichts zu maskieren oder zu leaken; ein
                    # Block wuerde Tool-Calling komplett brechen, ein
                    # normales, spezifiziertes Nutzungsmuster. Deshalb
                    # ``elif content is not None`` statt ``else`` -- None
                    # faellt durch und bleibt unveraendert.
                    #
                    # type(content).__name__ ist ein kurzer, konstant
                    # harmloser Typname -- nie der Wert selbst -- in der
                    # Meldung (Gesetz 5; siehe auch die Korrektur der
                    # Part-Fehlermeldung weiter oben, DATENSCHLE-64 zweites
                    # Finding).
                    raise DatenschleuseBlocked(
                        f"Nachricht mit content vom Typ "
                        f"{type(content).__name__!r} wird von der "
                        "Datenschleuse nicht geprueft und ist deshalb "
                        "blockiert (fail-closed). Erlaubt sind nur String- "
                        "oder Listen-content."
                    )

                # --- Alle uebrigen Textfelder der Message (DATENSCHLE-66) ---
                # content war nie das ganze Problem: fuer agentische Clients
                # ist ``tool_calls[].function.arguments`` der Normalbetrieb,
                # und genau dort stehen regelmaessig Kundendaten.
                await self._mask_message_fields(msg, masker, requested_level, approved)

        # --- Uebrige Top-Level-Felder der Route (DATENSCHLE-69, F1/F3) -----
        # Laeuft NACH messages/prompt und VOR dem Ablegen des Mappings: alles
        # geht durch DENSELBEN Masker, also in dasselbe reid_map.
        await self._mask_payload_fields(
            data, route, masker, requested_level, approved, qi_types,
            turn_qi, text_slots,
        )

        # Mapping im EIGENEN Metadata-Key ablegen (nicht LiteLLMs Interna).
        metadata = data.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
            data["metadata"] = metadata
        # VERSIEGELT, nicht im Klartext (Security-F4). ``metadata`` geht an
        # litellms Logging-Callbacks; ein Klartext-Mapping waere dort die
        # komplette PII-Tabelle im Log. Siehe seal_reid_map.
        metadata[REID_MAP_KEY] = seal_reid_map(masker.reid_map)

        # Anonymisierungs-Hinweis nur einfuegen, wenn tatsaechlich etwas
        # maskiert wurde (kein Overhead fuer PII-freie Requests) -- und nur
        # dann, wenn messages ueberhaupt eine Liste ist (defensiv, s.o.).
        if masker.reid_map:
            if isinstance(messages, list):
                self._inject_anonymization_notice(messages)
            elif route is TEXT_PAYLOAD_ROUTE:
                # F5: /v1/completions hat keine Messages, in die der Hinweis
                # passt -- deshalb lief er hier bisher gar nicht. Ein Modell,
                # dem niemand die Platzhalter erklaert, halluziniert
                # erfahrungsgemaess um sie herum. Der Hinweis wird nur bei
                # tatsaechlicher Maskierung vorangestellt: ein PII-freier
                # FIM-/Code-Completion-Prompt bleibt damit unangetastet.
                self._inject_prompt_notice(data)

        # --- QI-Layer: Akkumulation ueber die Session + Generalisierung -------
        # WICHTIG (fail-Semantik): ein Fehler im QI-Layer darf die bereits
        # erfolgte direkte-PII-Maskierung NICHT zunichte machen und den Request
        # NICHT blocken (anders als die Presidio-Erreichbarkeit, die hart
        # fail-closed ist). Deshalb defensiv abfangen + loggen.
        #
        # AUSNAHME (DATENSCHLE-69 F2): ein fail-closed-Block aus dem QI-Layer
        # ist KEIN "QI-Fehler, der ignoriert werden darf" -- er ist die
        # Entscheidung, nichts Ungepruefstes rauszulassen. Wuerde dieses
        # ``except`` ihn schlucken, waere jeder Block hier drin kosmetisch und
        # der Slot liefe wieder still durch. Deshalb faengt der Handler ihn
        # ausdruecklich NICHT.
        if self.qi_enabled and self._qi_store is not None and turn_qi:
            try:
                self._process_qi(data, user_api_key_dict, turn_qi, text_slots)
            except DatenschleuseBlocked:
                raise
            except Exception as exc:  # pragma: no cover - defensiv
                print(
                    f"[datenschleuse] QI-Layer-Fehler ignoriert (direkte Maskierung "
                    f"bleibt aktiv, Request nicht geblockt): {exc}",
                    flush=True,
                )

        # --- Logging-Schnappschuss nachziehen (Security-F1) ---------------
        # BEWUSST der letzte Schritt: erst hier steht der endgueltige,
        # maskierte UND QI-vergroeberte Payload fest. Jeder frueher gebaute
        # Schnappschuss waere wieder veraltet -- also genau der Defekt.
        self._resync_logging_snapshot(data)

        return data

    # ---- Deployment-Pfad (DATENSCHLE-69, Security-F3) ---------------------
    async def async_pre_call_deployment_hook(
        self, kwargs: Dict[str, Any], call_type: Any
    ) -> Optional[dict]:
        """Der zweite Eingang der Guardrail -- NACH der Routing-Entscheidung.

        Wir uebernehmen litellms komplette Vorlogik unveraendert (Marker
        ``_pre_call_hook_already_ran``, ``should_run_guardrail``, Bau des
        ``UserAPIKeyAuth``) und setzen ausschliesslich einen Merker, damit
        ``_validate_payload_shape`` weiss, dass die Deployment-FORM erlaubt
        ist. Kein Nachbau der Vorlogik: ein zweiter, leicht abweichender
        Nachbau waere genau die Sorte Folgedefekt, die dieser Guardrail
        wiederholt produziert hat.

        Warum ueberhaupt maskiert wird und nicht bloss durchgereicht: laeuft
        die Guardrail nur auf Modell-Ebene (``litellm_params.guardrails``) oder
        im SDK ohne Proxy, ist DIESER Hook die einzige Maskierungsstelle. Ein
        blosses Durchreichen waere dort ein stilles Leck -- schlimmer als der
        Block, den wir gerade beheben.
        """
        token = _DEPLOYMENT_PATH.set(True)
        try:
            return await super().async_pre_call_deployment_hook(kwargs, call_type)
        finally:
            _DEPLOYMENT_PATH.reset(token)

    # ---- Betreiber-Freigabe (DATENSCHLE-69, Security-F2) ------------------
    #: Ersatzwert fuer das redigierte Header-Geheimnis. Konstant, damit er nie
    #: mit einem Client-Wert verwechselt werden kann.
    APPROVAL_HEADER_REDACTED = "<redacted-by-datenschleuse>"

    def _strip_body_approval(self, data: Dict[str, Any]) -> bool:
        """Entfernt das Freigabe-Flag aus BEIDEN Metadaten-Kanaelen des
        Request-Bodys und meldet, ob eines gesetzt war.

        Ignorieren allein reicht nicht. Bliebe das Flag stehen, wanderte es
        durch den Logging-Kanal weiter und saehe fuer jeden spaeteren Leser
        aus, als HAETTE eine Freigabe vorgelegen -- eine Falschaussage im
        Audit-Trail.

        Beide Kanaele, weil litellm je nach Codepfad ``metadata`` ODER
        ``litellm_metadata`` propagiert. Ein Fix, der nur einen abdeckt, waere
        derselbe Alias-Fehler wie seinerzeit ``headers``/``extra_headers``.

        Und beide NAMEN (Security-F2b). Hier wurde nur
        ``SENSITIVITY_APPROVAL_KEY`` entfernt -- ein client-gesetztes
        ``metadata[OPERATOR_APPROVAL_KEY]`` blieb stehen. Kein Bypass:
        ``_operator_approved`` liest ``data["metadata"]`` nie. Aber genau
        der Schaden, den dieser Docstring oben beschreibt -- und
        ausgerechnet unter dem Namen, den ein spaeterer Leser fuer den
        ECHTEN Betreiber-Kanal haelt. Ein falscher Eintrag im Audit-Trail
        ist schlimmer, wenn er glaubwuerdig aussieht.
        """
        gesetzt = False
        for meta_key in ("metadata", "litellm_metadata"):
            meta = data.get(meta_key)
            if not isinstance(meta, dict):
                continue
            for approval_key in (
                sc.SENSITIVITY_APPROVAL_KEY,
                sc.OPERATOR_APPROVAL_KEY,
            ):
                if approval_key in meta:
                    meta.pop(approval_key, None)
                    gesetzt = True
        return gesetzt

    @staticmethod
    def _validate_messages_count(data: Dict[str, Any]) -> None:
        """Begrenzt die Anzahl Messages -- VOR der ersten Analyse.

        Steht im Validate-Pfad und nicht in der Maskierungsschleife: eine
        Grenze, die erst nach 400 Analyzer-Calls zuschlaegt, verhindert genau
        das nicht, wogegen sie gebaut ist.

        In der Meldung erscheint nur die GRENZE, nie ein Inhalt (Gesetz 5).
        """
        messages = data.get("messages")
        if isinstance(messages, list) and len(messages) > PAYLOAD_MAX_MESSAGES:
            raise DatenschleuseBlocked(
                f"messages enthaelt mehr als {PAYLOAD_MAX_MESSAGES} "
                "Eintraege -- blockiert (fail-closed). Jede Message kostet "
                "eine eigene Analyse; ein unbegrenztes Gespraech belegt den "
                "Worker beliebig lange."
            )

    @staticmethod
    def _strip_body_reid_map(data: Dict[str, Any]) -> bool:
        """Entfernt ein CLIENT-gesetztes Re-Id-Siegel aus dem Request-Body.

        Das Gegenstueck zu ``_strip_body_approval`` -- fuer den
        Mapping-Schluessel gab es keines, und das war eine Luecke.

        WARUM DAS NOETIG IST, obwohl das Siegel verschluesselt ist:
        Verschluesselung schuetzt gegen FAELSCHEN, nicht gegen
        WIEDERVERWENDEN. Das Siegel reist in ``metadata`` und geht damit an
        die Logging-Callbacks -- es ist nicht geheim. Wer eines aus einem Log
        fischt, braucht den Schluessel nicht: er schickt es in seiner EIGENEN
        Anfrage mit, dazu einen Text mit ``<PERSON_0>``, und laesst sich die
        fremden Klartextwerte in seine Antwort hinein-re-identifizieren. Ein
        Orakel auf fremde PII.

        GEMESSEN: ueber ``metadata`` scheiterte der Angriff, weil der Hook
        diesen Slot spaeter ueberschreibt -- Glueck, keine Absicht. Ueber
        ``litellm_metadata`` gelang er, weil dorthin nie geschrieben wird.
        Auf ein zufaellig dichtes Loch verlaesst sich diese Guardrail nicht.

        Laeuft ganz am ANFANG des Hooks, vor jedem Lesen: was der Client
        gesetzt hat, existiert danach nicht mehr. Das ist die Ursache; die
        deterministische Lesereihenfolge in ``_read_reid_map`` ist die
        zweite Schranke.

        NICHT gewaehlt: eine kryptografische Bindung des Siegels an den
        konkreten Request. Sie braeuchte einen Wert, den die Guardrail in
        pre_call UND post_call kennt und den der Client nicht kontrolliert.
        Die Kandidaten (``litellm_call_id`` und Verwandte) reisen selbst im
        Body und sind damit potenziell client-gesetzt -- die Bindung
        brauchte also erst wieder genau dieses Strippen, um zu tragen. Sie
        wuerde zusaetzlich still brechen, wenn der Wert zwischen pre_call und
        post_call abweicht (Router, Retry): der Nutzer bekaeme Platzhalter
        statt Klartext. Mehr Mechanik, neues Ausfallrisiko, kein zusaetzlich
        geschlossenes Loch, sobald der Client den Schluessel gar nicht mehr
        setzen kann.
        """
        gesetzt = False
        for meta_key in ("metadata", "litellm_metadata"):
            meta = data.get(meta_key)
            if isinstance(meta, dict) and REID_MAP_KEY in meta:
                meta.pop(REID_MAP_KEY, None)
                gesetzt = True
        # Auch der geflachte Weg -- ``_read_reid_map`` liest ihn ebenfalls.
        if REID_MAP_KEY in data:
            data.pop(REID_MAP_KEY, None)
            gesetzt = True
        return gesetzt

    def _operator_approved(
        self, data: Dict[str, Any], user_api_key_dict: Any
    ) -> bool:
        """Die Stufe-2-Freigabe -- ausschliesslich aus Betreiber-Quellen.

        Weg 1: Key-/Team-Konfiguration. Sie stammt aus der Proxy-Datenbank und
        wird vom Betreiber beim Anlegen des Virtual Key gesetzt. litellm
        strippt client-gesetzte ``user_api_key_*``-Metadaten selbst, mit
        woertlich derselben Begruendung, die wir hier fuehren.

        Weg 2: Header MIT betreiberseitig konfiguriertem Geheimnis. Ohne
        konfiguriertes Geheimnis ist dieser Weg AUS -- nicht "offen fuer
        alle". Das Geheimnis wird konstantzeitig verglichen und danach
        redigiert, damit es nicht ueber den Logging-Kanal weiterwandert
        (Gesetz 5: Secrets werden nie geloggt).
        """
        for quelle in ("metadata", "team_metadata"):
            if sc.is_operator_release_approved(
                self._field(user_api_key_dict, quelle)
            ):
                return True

        if not self.approval_header_secret:
            return False

        psr = data.get("proxy_server_request")
        if not isinstance(psr, dict):
            return False
        headers = psr.get("headers")
        if not isinstance(headers, dict):
            return False

        # HTTP-Header sind case-insensitiv; der Proxy reicht sie mal so, mal
        # so durch. Ein Vergleich nur auf Kleinschreibung waere ein stiller
        # Fehlschlag beim Betreiber -- und der schaltet dann die Guardrail ab.
        treffer = [
            name for name in headers
            if isinstance(name, str) and name.lower() == sc.APPROVAL_HEADER
        ]
        freigegeben = False
        try:
            for name in treffer:
                wert = headers.get(name)
                if not isinstance(wert, str):
                    continue
                try:
                    kandidat = wert.encode("utf-8")
                except UnicodeEncodeError:
                    # Ein Header-Wert, der sich nicht als UTF-8 darstellen
                    # laesst, kann das konfigurierte Geheimnis nicht sein
                    # (das ist beim Start als UTF-8-darstellbar geprueft).
                    # Also: kein Treffer -- aber auch kein Absturz.
                    continue
                if hmac.compare_digest(kandidat, self._approval_secret_bytes):
                    freigegeben = True
        except Exception as exc:
            # Ein unkontrollierter Fehlerpfad ist kein fail-closed (Grundbuch).
            # Ein roher TypeError aus dem Vergleich wird von litellm zu einem
            # opaken 500 -- der Betreiber sieht einen Ausfall statt eines
            # Blocks. Genannt wird NUR der Typname: der Text einer Ausnahme
            # kann den verglichenen Wert mitfuehren (Gesetz 5).
            raise DatenschleuseBlocked(
                "Die Betreiber-Freigabe ueber den Header konnte nicht "
                f"geprueft werden ({type(exc).__name__}) -- Request "
                "blockiert (fail-closed). Eine Freigabe, deren Pruefung "
                "scheitert, ist keine Freigabe."
            ) from exc
        finally:
            # Redigieren im ``finally`` und nicht im Schleifenrumpf: die
            # Redaktion darf NICHT am Erfolg des Vergleichs haengen. Genau
            # daran hing sie -- ein Wurf mitten in der Schleife liess das
            # Geheimnis unredigiert im Logging-Kanal stehen (F2, gemessen).
            # Auch ein FALSCHES Geheimnis ist ein Geheimnisversuch und hat
            # im Log nichts zu suchen.
            for name in treffer:
                headers[name] = self.APPROVAL_HEADER_REDACTED
        return freigegeben

    # ---- Logging-Schnappschuss (DATENSCHLE-69, Security-F1) ---------------
    @staticmethod
    def _validate_snapshot_shape(data: Dict[str, Any]) -> None:
        """Prueft die FORM von ``proxy_server_request``, BEVOR irgendetwas
        maskiert wird.

        Dieselbe Doktrin wie ueberall: was wir nicht neu bauen koennen,
        koennen wir auch nicht dicht machen -> fail-closed blocken statt
        stillschweigend stehen lassen. Ein ``body`` als roher JSON-String
        traegt denselben Klartext, ist aber keine Struktur, in die wir den
        maskierten Payload zurueckschreiben koennen.

        Gesetz 5: kein Client-Wert in der Meldung, nur Typnamen und Namen aus
        unseren eigenen Konstanten.
        """
        psr = data.get("proxy_server_request")
        if psr is None:
            return
        if not isinstance(psr, dict):
            raise DatenschleuseBlocked(
                f"proxy_server_request vom Typ {type(psr).__name__!r} wird von "
                "der Datenschleuse nicht geprueft und ist deshalb blockiert "
                "(fail-closed). Erlaubt ist nur ein Objekt."
            )
        if "body" not in psr:
            return
        body = psr["body"]
        if body is not None and not isinstance(body, dict):
            raise DatenschleuseBlocked(
                f"proxy_server_request.body vom Typ {type(body).__name__!r} "
                "kann nicht mit dem maskierten Payload abgeglichen werden und "
                "ist deshalb blockiert (fail-closed). Erlaubt ist nur ein "
                "Objekt -- ein roher String traegt denselben Klartext, laesst "
                "sich aber nicht neu aufbauen."
            )

    @staticmethod
    def _resync_logging_snapshot(data: Dict[str, Any]) -> None:
        """Baut litellms Logging-Schnappschuss aus dem MASKIERTEN Payload neu.

        Laeuft als LETZTER Schritt des Hooks -- nach der Maskierung UND nach
        dem QI-Layer. Die Reihenfolge ist nicht kosmetisch: der QI-Layer
        vergroebert Texte NACH der Maskierung (PLZ, Geburtsjahr). Ein
        Schnappschuss vor dem QI-Layer truege die feiner aufgeloesten Werte
        ins Log -- maskiert zwar, aber praeziser als das, was der Provider
        sieht. Was das Modell nicht sehen darf, darf das Log erst recht nicht
        sehen.

        Neu BAUEN statt feldweise nachziehen: siehe die ausfuehrliche
        Begruendung bei PAYLOAD_FIELDS_RESYNCED. Kurz -- ein feldweiser
        Abgleich deckt nur ab, woran jemand gedacht hat.

        Der Schnappschuss wird nicht geleert: ``spend_tracking_utils`` und
        ``standard_logging_payload`` lesen ihn. Ein leerer Body waere dicht,
        wuerde aber die Kostenerfassung des Betreibers kaputtmachen -- ein Fix,
        der einen anderen Defekt erzeugt.
        """
        psr = data.get("proxy_server_request")
        if not isinstance(psr, dict) or "body" not in psr:
            return
        psr["body"] = {
            key: value
            for key, value in data.items()
            if key not in LOGGING_SNAPSHOT_EXCLUDE
        }

    #: Was im Schnappschuss eines GEBLOCKTEN Requests stehen bleibt.
    #: Eine Konstante, kein Rest des Payloads -- alles andere waere wieder
    #: eine Liste von Feldern, an die jemand gedacht hat.
    BLOCKED_SNAPSHOT_BODY = {
        "datenschleuse": "request blocked -- body withheld from logging"
    }

    #: Ersatzwert fuer die Nutzfelder eines geblockten Requests.
    BLOCKED_FIELD_MARKER = "<withheld-by-datenschleuse: request blocked>"

    #: Ersatz fuer eine Message-Liste. Eine LISTE mit einem gueltigen
    #: Message-Dict, kein String (Runde 4, F7): ``messages`` stand in
    #: _ALLE_MASKIERTEN_FELDER und wurde damit zu einem String. Ein String
    #: ist iterierbar -- Konsumenten stuerzen daran nicht ab, sie lesen
    #: ZEICHEN. Und der Zweig ``if isinstance(data.get("messages"), list)``
    #: war damit toter Code.
    BLOCKED_MESSAGE = {"role": "user", "content": BLOCKED_FIELD_MARKER}

    @classmethod
    def _redact_logging_snapshot(cls, data: Any) -> None:
        """Ersetzt den Logging-Schnappschuss eines geblockten Requests.

        ERSETZEN statt maskieren: der Block bedeutet, dass dieser Payload
        NICHT geprueft werden konnte oder nicht hinausgehen darf. Ihn
        nachtraeglich maskieren zu wollen hiesse, genau die Pruefung
        nachzuholen, die gerade fehlgeschlagen ist.

        Es geht dabei nichts verloren: die Kostenerfassung lebt vom
        Provider-Call, und den hat es nicht gegeben. Ein Dict bleibt es
        trotzdem -- ``standard_logging_payload`` und die Failure-Callbacks
        lesen den Schnappschuss auch im Fehlerfall, und ein ``None`` waere
        ein Fix, der einen anderen Defekt erzeugt.
        """
        if not isinstance(data, dict):
            return
        psr = data.get("proxy_server_request")
        if isinstance(psr, dict) and "body" in psr:
            psr["body"] = dict(cls.BLOCKED_SNAPSHOT_BODY)

        # Der Schnappschuss ist nur EINER von mehreren Klartext-Kanaelen.
        # ``post_call_failure_hook`` bekommt ``request_data`` selbst, und das
        # darin haengende ``litellm_logging_obj`` haelt die Nutzfelder ein
        # zweites Mal. Der Block trifft mitten in der Message-Schleife --
        # alles danach ist voellig unmaskiert.
        #
        # WIE GENAU es sie haelt, ist entscheidend fuer die Bauart des Fixes
        # (Runde 4, F1; belegt am Quelltext von litellm 1.97.0):
        #
        #   litellm_logging.py:317   _input = messages          -> KEINE Kopie
        #   litellm_logging.py:333   self.messages = copy.copy(messages)
        #
        # Also: ``model_call_details["input"]`` ist die IDENTISCHE Liste,
        # ``logging_obj.messages`` eine ANDERE Liste mit DENSELBEN Dicts.
        # (Eine frueherere Fassung dieses Kommentars sprach von "derselben
        # messages-Liste" -- das war ungenau und hat den Fix in die Irre
        # gefuehrt.)
        #
        # Daraus folgt, warum hier NICHTS per Rebinding redigiert wird:
        #
        #   data[feld] = MARKER   erreicht per Konstruktion keinen Alias.
        #   messages[:] = [...]   erreicht die identische Liste, aber NICHT
        #                         die flache Kopie -- die hat eine eigene
        #                         aeussere Liste.
        #
        # Nur das In-place-Leeren der Message-DICTS erreicht beide Wege.
        # Deshalb dreiteilig: Dicts leeren, aeussere Liste kuerzen, und das
        # Logging-Objekt ausdruecklich neutralisieren.
        for feld in _ALLE_MASKIERTEN_FELDER:
            if feld in data:
                data[feld] = cls._redact_wert(data[feld])

        # ``messages`` bekommt seine FORM zurueck: eine Liste mit einer
        # gueltigen Message (F7). Erst hier, nach dem generischen Leeren --
        # die alten Dicts sind zu diesem Zeitpunkt bereits ausgeraeumt und
        # damit auch fuer den haltenden Alias harmlos.
        if isinstance(data.get("messages"), list):
            data["messages"][:] = [dict(cls.BLOCKED_MESSAGE)]

        cls._redact_logging_obj(data.get("litellm_logging_obj"))

    @classmethod
    def _redact_wert(cls, wert: Any) -> Any:
        """Neutralisiert einen Nutzwert IN PLACE und gibt den Ersatz zurueck.

        In place UND Rueckgabe: das eine erreicht die Aliase (wer dieses
        Dict/diese Liste noch haelt, haelt danach nichts mehr), das andere
        den Slot im ``data`` selbst. Beides zusammen ist der Fix; jedes
        allein war der Befund.
        """
        if isinstance(wert, dict):
            # Leeren statt neu bauen: ein neues Dict laesst das alte
            # unberuehrt im Alias stehen.
            wert.clear()
            return wert
        if isinstance(wert, list):
            for eintrag in wert:
                cls._redact_wert(eintrag)
            wert[:] = []
            return wert
        return cls.BLOCKED_FIELD_MARKER

    @classmethod
    def _redact_logging_obj(cls, obj: Any) -> None:
        """Neutralisiert litellms Logging-Objekt -- den zweiten Halter der
        Nutzfelder.

        Hier ist ein Rebinding richtig, anders als beim ``data``: wir halten
        das OBJEKT selbst, nicht eine Kopie davon. Ein Attribut auf dem
        geteilten Objekt zu setzen erreicht jeden, der das Objekt hat --
        einen dict-SCHLUESSEL zu setzen erreicht niemanden sonst. Das ist
        genau der Unterschied, den der Befund aufgedeckt hat.
        """
        if obj is None:
            return
        ersatz = [dict(cls.BLOCKED_MESSAGE)]

        # 1. Die offizielle API zuerst (litellm_logging.py:616-623). Ihr
        #    Docstring sieht sie ausdruecklich fuer pre-call-Hooks vor
        #    ("Allows pre-call hooks to update the messages before the call
        #    is made") und sie setzt self.messages UND
        #    model_call_details["messages"].
        update = getattr(obj, "update_messages", None)
        if callable(update):
            try:
                update(list(ersatz))
            except Exception:  # pragma: no cover - Fremdcode
                # Bewusst weiter statt werfen: Schritt 2 unten ist die
                # eigentliche Zusicherung und laeuft unabhaengig davon.
                # Auch bewusst ohne Log -- ein Log an dieser Stelle koennte
                # selbst werfen und wuerde dann Schritt 2 verhindern.
                pass

        # 2. Direkt -- und AUCH dann, wenn (1) gelaufen ist:
        #    ``model_call_details["input"]`` ist die identische Liste
        #    (:317) und wird von ``update_messages`` NICHT beruehrt.
        mcd = getattr(obj, "model_call_details", None)
        if isinstance(mcd, dict):
            for key in ("input", "messages"):
                if key in mcd:
                    mcd[key] = list(ersatz)
        if getattr(obj, "messages", None) is not None:
            obj.messages = list(ersatz)
        # ``messages`` ist eine Liste von Dicts -- der Marker ersetzt sie
        # ganz. Ein Weiterreichen der Struktur mit geleerten Werten waere
        # wieder eine Liste von Feldern, an die jemand gedacht hat.
        if isinstance(data.get("messages"), list):
            data["messages"] = [
                {"role": "user", "content": cls.BLOCKED_FIELD_MARKER}
            ]

    # ---- Route-Register (DATENSCHLE-69) -----------------------------------
    @staticmethod
    def _validate_call_type(call_type: Any) -> None:
        """Prueft die ROUTE gegen das Call-Type-Register.

        Konsequente Allowlist wie eine Ebene tiefer beim Message-Feld-Register:
        was hier nicht steht, ist ein Payload-Schema, dessen Inhalt niemand
        geprueft hat -- und damit ein Durchlass. Vorher endete dieser Pfad in
        einem ``return data``: unmaskiert weiter ans Modell.

        Die Typpruefung steht bewusst HIER im Validate-Pfad und nicht als
        ``isinstance``-Guard im Verarbeitungspfad. Ein Guard, der bei
        unerwartetem Typ still ueberspringt, ist immer ein Durchlass -- das
        war das schwerste Audit-Finding von DATENSCHLE-66 und wird hier nicht
        eine Ebene hoeher wiederholt.

        In der Meldung erscheint NIE der Wert selbst (er ist client-
        kontrolliert: beliebiger Inhalt, beliebiger Typ, beliebige Laenge und
        Blockmeldungen laufen durch LiteLLMs Logging, Gesetz 5), sondern nur
        sein Python-Typname bzw. ein Name aus der konstanten Liste
        KNOWN_UNSUPPORTED_CALL_TYPES."""
        # Typpruefung ZUERST, nicht erst beim Nachschlagen: ein ``list``- oder
        # ``dict``-call_type ist nicht hashbar und wuerde ``in frozenset``
        # mit einem TypeError sprengen. Ein unkontrollierter Fehlerpfad ist
        # kein fail-closed (gleiche Klasse Befund wie MAX_JSON_DEPTH,
        # Security-Audit F7).
        #
        # ``None`` stand frueher explizit auf der Liste und lief damit
        # ungeprueft durch. litellm 1.97.0 uebergibt nie None -- die Signatur
        # von CustomLogger.async_pre_call_hook ist ``CallTypesLiteral``, nicht
        # optional. Ein None ist also ein fremder Aufrufer oder ein Fehler;
        # beides ist nicht pruefbar.
        if not isinstance(call_type, str):
            raise DatenschleuseBlocked(
                f"Aufruf ohne lesbaren call_type (Typ "
                f"{type(call_type).__name__!r}) wird von der Datenschleuse "
                "nicht geprueft und ist deshalb blockiert (fail-closed). "
                f"Geprueft werden: {_ALLOWED_CALL_TYPES_HINT}."
            )

        if call_type in ALLOWED_CALL_TYPES:
            return

        if call_type in KNOWN_UNSUPPORTED_CALL_TYPES:
            # Nur hier darf der Name genannt werden -- er stammt aus unserer
            # eigenen konstanten Liste, nicht aus dem Request.
            raise DatenschleuseBlocked(
                f"Die Route {call_type!r} wird von der Datenschleuse noch "
                "nicht geprueft und ist deshalb blockiert (fail-closed). Ihr "
                "Payload hat ein eigenes Schema, das die Maskierung nicht "
                "abdeckt -- ungeprueftes Durchreichen waere ein PII-Leck bei "
                "zugesichertem Schutz. Geprueft werden: "
                f"{_ALLOWED_CALL_TYPES_HINT}."
            )

        raise DatenschleuseBlocked(
            "Aufruf ueber eine der Datenschleuse unbekannte Route wird nicht "
            "geprueft und ist deshalb blockiert (fail-closed). Geprueft "
            f"werden: {_ALLOWED_CALL_TYPES_HINT}."
        )

    # ---- Top-Level-Feld-Register des Payloads (DATENSCHLE-69) -------------
    @staticmethod
    def _validate_payload_shape(data: Any, route: "_PayloadRoute") -> None:
        """Prueft die FORM des Payloads gegen das Top-Level-Feld-Register.

        Konsequente Allowlist wie eine Ebene tiefer beim Message-Feld-Register:
        was hier nicht steht, ist ein Feld, dessen Inhalt niemand geprueft hat
        -- und in litellm 1.97.0 nachweislich ein Ausgangskanal (unbekannte
        Keys landen in ``extra_body``). Der Routen-Fix registrierte nur die
        Route; erst diese Pruefung schliesst die Ebene darunter.

        Gesetz 5: in keiner Meldung steht ein Client-Wert -- auch ein FELDNAME
        ist Client-Inhalt. Ausgegeben werden nur Anzahl, Python-Typname,
        Namen aus unseren eigenen konstanten Listen und Fingerprints.
        """
        if not isinstance(data, dict):
            raise DatenschleuseBlocked(
                f"Payload vom Typ {type(data).__name__!r} ist nicht pruefbar "
                "und deshalb blockiert (fail-closed)."
            )

        # a) Mehrdeutigkeit -- der Body passt auf ZWEI Routen gleichzeitig.
        #    Die Text-Route blockte das schon; die Chat-Route nicht. Die Regel
        #    aus security-baseline.md gilt in beide Richtungen.
        if data.get(route.forbidden) is not None:
            raise DatenschleuseBlocked(
                f"Request der Route {route.name} mit zusaetzlichem "
                f"{route.forbidden}-Feld ist mehrdeutig und wird deshalb "
                "blockiert (fail-closed). Erlaubt ist entweder prompt "
                "(/v1/completions) oder messages (/v1/chat/completions), "
                "nicht beides."
            )

        # b) Ohne Traegerfeld gibt es keinen Anwendertext, den wir pruefen
        #    koennten -- und der Rest des Bodys liefe trotzdem hinaus.
        if data.get(route.required) is None:
            raise DatenschleuseBlocked(
                f"Request der Route {route.name} ohne {route.required}-Feld "
                "ist nicht pruefbar und deshalb blockiert (fail-closed)."
            )

        # c) Jedes Feld, das die Datenschleuse nicht kennt, blockt.
        erlaubt = (
            set(route.masked)
            | set(route.validated)
            | PAYLOAD_FIELDS_INFRASTRUCTURE
            | PAYLOAD_FIELDS_RESYNCED
        )
        # Auf dem Deployment-Pfad kommen die vom ROUTER aufgeloesten Keys
        # dazu (DATENSCHLE-69, Security-F3). Der Merker steht nur, solange wir
        # nachweislich in unserem eigenen Deployment-Hook stehen -- der
        # Client-Pfad sieht dieses Register nie.
        im_deployment = _DEPLOYMENT_PATH.get()
        if im_deployment:
            erlaubt = erlaubt | PAYLOAD_FIELDS_DEPLOYMENT
        unbekannt = [key for key in data if key not in erlaubt]
        if unbekannt:
            benannt = sorted(
                key for key in unbekannt
                if isinstance(key, str) and key in KNOWN_UNSUPPORTED_PAYLOAD_FIELDS
            )
            fremd = [key for key in unbekannt if key not in benannt]
            teile = []
            if benannt:
                teile.append("bekannt, aber nicht im Register: " + ", ".join(benannt))
            if fremd:
                teile.append(
                    "unbekannt (Fingerprint): "
                    + ", ".join(sorted(_field_fingerprint(k) for k in fremd))
                )
            diagnose = "; ".join(teile)
            _LOG.warning(
                "Payload blockiert -- ungepruefte Top-Level-Felder [%s]. "
                "Werte werden bewusst nicht geloggt (Gesetz 5).", diagnose,
            )
            # Den KONTEXT nennen, sonst sucht ein Betreiber an der falschen
            # Stelle: auf dem Deployment-Pfad stammen die Keys vom Router,
            # nicht vom Client -- und die Abhilfe ist eine andere.
            kontext = (
                " Der Block stammt vom DEPLOYMENT-Pfad (nach der "
                "Routing-Entscheidung): die Keys setzt dort litellms Router, "
                "nicht der Client. Eine neue litellm-Version kann hier neue "
                "Keys einfuehren -- dann gehoert der Key nach Pruefung in "
                "PAYLOAD_FIELDS_DEPLOYMENT."
                if im_deployment else ""
            )
            raise DatenschleuseBlocked(
                f"Payload enthaelt {len(unbekannt)} Top-Level-Feld(er), die "
                f"die Datenschleuse nicht prueft ({diagnose}) -- deshalb "
                f"blockiert (fail-closed). Geprueft werden auf der Route "
                f"{route.name} ausschliesslich: "
                f"{_PAYLOAD_FIELDS_HINT[route.name]}.{kontext}"
            )

        # d) Bekanntes Feld, falscher Typ -- derselbe Defekt (DATENSCHLE-66 F1).
        for feld, pruefer in route.validated.items():
            wert = data.get(feld)
            if wert is not None:
                _PAYLOAD_VALIDATORS[pruefer](wert, feld)

    async def _mask_payload_fields(
        self,
        data: Dict[str, Any],
        route: "_PayloadRoute",
        masker: Masker,
        requested_level: Any,
        approved: bool,
        qi_types: Any,
        turn_qi: List[Tuple[str, str]],
        text_slots: List[Tuple[Any, Any]],
    ) -> None:
        """Maskiert die registrierten Top-Level-Freitextfelder AUSSER dem
        Traegerfeld (``messages``/``prompt``) -- das erledigen die bestehenden
        Pfade im Hook.

        Alles laeuft ueber DENSELBEN ``masker`` und damit dasselbe
        ``reid_map``: derselbe Wert bekommt in prompt, suffix und tools
        denselben Platzhalter, und der Rueckweg findet ihn wieder. Ein
        zweites Mapping waere ein zweiter, unvollstaendiger Rueckweg.

        Die Reihenfolge folgt der Deklaration im Register, damit die
        Platzhalter-Nummerierung deterministisch bleibt.
        """
        for feld in route.masked:
            if feld == route.required:
                continue  # messages/prompt: bereits behandelt
            wert = data.get(feld)
            if wert is None:
                continue

            if feld == "suffix":
                # Wie ein prompt-String behandeln -- inklusive QI-Slot, damit
                # der QI-Layer auch hier groebern kann.
                if not isinstance(wert, str):
                    raise DatenschleuseBlocked(
                        f"suffix vom Typ {type(wert).__name__!r} wird von der "
                        "Datenschleuse nicht geprueft und ist deshalb "
                        "blockiert (fail-closed). Erlaubt ist nur ein String."
                    )
                data[feld] = await self._mask_prompt_text(
                    wert, masker, requested_level, approved, qi_types, turn_qi
                )
                text_slots.append((data, feld))
                continue

            if feld == "stop":
                data[feld] = await self._mask_stop(
                    wert, masker, requested_level, approved
                )
                continue

            if feld == "user":
                # Endnutzer-Kennung. Sie geht als Provider-Parameter hinaus und
                # traegt in der Praxis regelmaessig eine E-Mail-Adresse oder
                # einen Klarnamen. Maskiert statt validiert: ein Block wuerde
                # legitime Betreiber-Setups brechen, und ein Platzhalter ist
                # als Kennung genauso brauchbar wie der Klartext.
                if not isinstance(wert, str):
                    raise DatenschleuseBlocked(
                        f"user vom Typ {type(wert).__name__!r} wird von der "
                        "Datenschleuse nicht geprueft und ist deshalb "
                        "blockiert (fail-closed). Erlaubt ist nur ein String."
                    )
                data[feld] = await self._mask_text_value(
                    wert, masker, requested_level, approved
                )
                continue

            # tools / tool_choice / functions / function_call / response_format:
            # verschachtelte Strukturen mit Freitext an beliebiger Tiefe
            # (``description``, ``enum``-Werte, Schema-Titel). Strukturerhaltend
            # maskieren -- der Aufruf muss beim Zielmodell benutzbar bleiben.
            data[feld] = await self._mask_payload_structure(
                wert, feld, masker, requested_level, approved
            )

    async def _mask_stop(
        self, value: Any, masker: Masker, requested_level: Any, approved: bool
    ) -> Any:
        """``stop`` ist Freitext, der als Provider-Parameter hinausgeht.

        Maskiert statt geblockt, weil die Stop-Sequenz nach der Maskierung
        genau zu dem Text passt, den das Modell zu sehen bekommt: der
        ausgehende Text traegt Platzhalter, also muss die Stop-Sequenz sie
        ebenfalls tragen. In der Praxis stehen dort ohnehin Marker wie
        ``\\n\\n`` -- fuer die ist die Maskierung ein No-op."""
        if isinstance(value, str):
            return await self._mask_text_value(
                value, masker, requested_level, approved
            )
        if isinstance(value, list):
            if len(value) > PAYLOAD_MAX_LIST_ITEMS:
                raise DatenschleuseBlocked(
                    f"stop enthaelt mehr als {PAYLOAD_MAX_LIST_ITEMS} "
                    "Eintraege -- blockiert (fail-closed)."
                )
            out = []
            for item in value:
                if not isinstance(item, str):
                    raise DatenschleuseBlocked(
                        f"stop-Eintrag vom Typ {type(item).__name__!r} wird "
                        "von der Datenschleuse nicht geprueft und ist deshalb "
                        "blockiert (fail-closed). Erlaubt sind nur Strings."
                    )
                out.append(
                    await self._mask_text_value(
                        item, masker, requested_level, approved
                    )
                )
            return out
        raise DatenschleuseBlocked(
            f"stop vom Typ {type(value).__name__!r} wird von der Datenschleuse "
            "nicht geprueft und ist deshalb blockiert (fail-closed). Erlaubt "
            "sind nur String- oder Listen-Werte."
        )

    async def _mask_payload_structure(
        self,
        value: Any,
        field: str,
        masker: Masker,
        requested_level: Any,
        approved: bool,
    ) -> Any:
        """Strukturerhaltende Maskierung eines verschachtelten Top-Level-Felds
        (``tools``, ``tool_choice``, ``functions``, ``function_call``,
        ``response_format``).

        Nutzt denselben JSON-Knoten-Masker wie ``tool_calls[].function.
        arguments`` -- inklusive Tiefenbegrenzung, Schutzklassen-Gate ueber die
        gesammelten Entity-Typen und Verifikationsdurchlauf auf dem Ergebnis.
        Der Verifikationsdurchlauf ist die einzige Pruefung, die NICHT
        pfadgebunden ist: findet der Analyzer im Resultat noch etwas, blockt
        der Request, statt es hinauszulassen.

        Bewusst in Kauf genommen: schlaegt die Erkennung in einem Feld an, das
        der Provider formal einschraenkt (``response_format.json_schema.name``
        erlaubt nur ``[A-Za-z0-9_-]``), wird der Request vom Provider
        abgelehnt statt still mit PII ausgeliefert. Ein gebrochenes Schema ist
        sichtbar, ein Leck nicht -- dieselbe Abwaegung wie beim Typwechsel
        Zahl -> String in ``_mask_json_node``."""
        collected: List[Dict[str, Any]] = []
        masked = await self._mask_json_node(value, masker, collected)
        if collected:
            # Signalwort und Personen-Referenz stehen typischerweise in
            # VERSCHIEDENEN Feldern der Struktur -- pro Feld einzeln
            # klassifiziert wuerde die Kombination nie erkannt. Deshalb ueber
            # die Gesamtstruktur, wie bei ``arguments``.
            self._enforce_sensitivity(
                json.dumps(value, ensure_ascii=False, default=str),
                [{"entity_type": e.get("entity_type")} for e in collected],
                requested_level,
                approved,
            )
        await self._verify_no_pii_left(
            json.dumps(masked, ensure_ascii=False, default=str), masker
        )
        return masked

    @staticmethod
    def _inject_prompt_notice(
        data: Dict[str, Any], notice: str = ANONYMIZATION_NOTICE
    ) -> None:
        """Stellt den Anonymisierungs-Hinweis dem ``prompt`` voran (F5).

        Der Chat-Pfad legt ihn in eine System-Message; /v1/completions hat
        keine, also fuehrt an einem Praefix kein Weg vorbei. Bei einer
        Batch-Liste bekommt JEDER Eintrag den Hinweis: die Eintraege sind
        eigenstaendige Completions, ein Hinweis nur im ersten wuerde die
        uebrigen unerklaert lassen.

        Wird nur bei tatsaechlicher Maskierung aufgerufen -- ein PII-freier
        FIM-/Code-Completion-Prompt bleibt dadurch unveraendert."""
        prompt = data.get("prompt")
        if isinstance(prompt, str):
            data["prompt"] = f"{notice}\n\n{prompt}"
            return
        if isinstance(prompt, list):
            for index, item in enumerate(prompt):
                if isinstance(item, str):
                    prompt[index] = f"{notice}\n\n{item}"

    # ---- Route /v1/completions: Payload mit ``prompt`` (DATENSCHLE-69) ----
    async def _mask_text_prompt(
        self,
        data: Dict[str, Any],
        masker: Masker,
        requested_level: Any,
        approved: bool,
        qi_types: Any,
        turn_qi: List[Tuple[str, str]],
        text_slots: List[Tuple[Any, Any]],
    ) -> None:
        """Maskiert den Anwendertext von /v1/completions.

        Gleiche Behandlung wie ein ``content``-String im Chat-Pfad: derselbe
        Masker (also DASSELBE reid_map -- Voraussetzung dafuer, dass die
        Re-Identifikation auf dem Rueckweg greift), dasselbe Schutzklassen-
        Gate, dieselbe QI-Aufteilung.

        Der Payload wird zusaetzlich auf seine FORM geprueft. Der call_type
        sagt nur, welche Route spricht -- nicht, wie ihr Body aussieht. Was
        hier nicht als pruefbar erkannt wird, blockt."""
        # Ein /v1/completions-Request hat kein ``messages``. Kommt es trotzdem
        # mit, ist der Payload mehrdeutig: die Route wertet ihn als
        # Text-Completion, im Body steht aber zusaetzlich ein Chat-Kanal, den
        # dieser Pfad nicht verarbeitet. Genau so entsteht ein ungeprueftes
        # Feld -> blocken statt eines der beiden stillschweigend ignorieren.
        if data.get("messages") is not None:
            raise DatenschleuseBlocked(
                "Text-Completion-Request mit zusaetzlichem messages-Feld ist "
                "mehrdeutig und wird deshalb blockiert (fail-closed). "
                "Erlaubt ist entweder prompt (/v1/completions) oder messages "
                "(/v1/chat/completions), nicht beides."
            )

        if "prompt" not in data:
            raise DatenschleuseBlocked(
                "Text-Completion-Request ohne prompt-Feld ist nicht pruefbar "
                "und deshalb blockiert (fail-closed)."
            )

        prompt = data["prompt"]

        if isinstance(prompt, str):
            data["prompt"] = await self._mask_prompt_text(
                prompt, masker, requested_level, approved, qi_types, turn_qi
            )
            text_slots.append((data, "prompt"))
            return

        # Die OpenAI-API erlaubt auch eine Liste von Prompts (Batch). Jeder
        # Eintrag muss ein String sein -- eine Liste von Token-IDs ist zwar
        # ebenfalls spezifiziert, aber kein analysierbarer Text: Presidio
        # kann darin nichts finden, und die IDs tragen den Klartext trotzdem
        # (sie sind nur eine andere Kodierung desselben Satzes). Deshalb
        # blockt sie, statt "geprueft" zu heissen, ohne geprueft worden zu
        # sein. Kein still ueberspringender isinstance-Guard.
        if isinstance(prompt, list):
            # Die Grenze ZUERST -- vor dem ersten Analyzer-Call. Ein Limit,
            # das erst nach der Arbeit zuschlaegt, verhindert genau das
            # nicht, wogegen es gebaut ist.
            if len(prompt) > PAYLOAD_MAX_PROMPT_ITEMS:
                raise DatenschleuseBlocked(
                    f"prompt enthaelt mehr als {PAYLOAD_MAX_PROMPT_ITEMS} "
                    "Eintraege -- blockiert (fail-closed). Jeder Eintrag "
                    "kostet eine eigene Analyse; ein unbegrenzter Batch "
                    "belegt den Worker beliebig lange."
                )
            for index, item in enumerate(prompt):
                if not isinstance(item, str):
                    raise DatenschleuseBlocked(
                        f"prompt-Eintrag vom Typ {type(item).__name__!r} wird "
                        "von der Datenschleuse nicht geprueft und ist deshalb "
                        "blockiert (fail-closed). Erlaubt sind nur Strings -- "
                        "Token-ID-Listen sind kein analysierbarer Text."
                    )
                prompt[index] = await self._mask_prompt_text(
                    item, masker, requested_level, approved, qi_types, turn_qi
                )
                text_slots.append((prompt, index))
            return

        raise DatenschleuseBlocked(
            f"prompt vom Typ {type(prompt).__name__!r} wird von der "
            "Datenschleuse nicht geprueft und ist deshalb blockiert "
            "(fail-closed). Erlaubt sind nur String- oder Listen-prompts."
        )

    async def _mask_prompt_text(
        self,
        text: str,
        masker: Masker,
        requested_level: Any,
        approved: bool,
        qi_types: Any,
        turn_qi: List[Tuple[str, str]],
    ) -> str:
        """Ein einzelner Prompt-String -- exakt die Schrittfolge des
        content-Pfads: analysieren, klassifizieren (Stufe 3 blockt hart,
        Stufe 2 ohne Freigabe ebenfalls), QI abspalten, maskieren."""
        entities = await self._analyze(text)
        self._enforce_sensitivity(text, entities, requested_level, approved)
        direct, qi = self._split_entities(entities, qi_types)
        masked = masker.mask(text, direct)
        turn_qi.extend(self._extract_qi_values(text, qi))
        return masked

    # ---- Message-Felder jenseits von content (DATENSCHLE-66) --------------
    @staticmethod
    def _validate_message_shape(msg: Dict[str, Any]) -> None:
        """Prueft die FORM einer Message gegen das Feld-Register.

        Konsequente Allowlist wie auf Part- und Container-Ebene: jedes Feld,
        das die Guardrail nicht kennt, ist ein Kanal, dessen Inhalt niemand
        geprueft hat -> fail-closed blocken. Damit erzwingt ein neues Feld der
        OpenAI-API eine bewusste Entscheidung im Register, statt still ein Leck
        zu oeffnen.

        Gesetz 5: in keiner Meldung stehen Client-Werte -- auch ein FELDNAME
        ist Client-Inhalt (eine IBAN als Feldname ist trivial konstruierbar).
        Ausgegeben werden nur Anzahl, Python-Typname und die konstante Liste
        der erlaubten Felder.
        """
        unknown = [key for key in msg if key not in ALLOWED_MESSAGE_FIELDS]
        if unknown:
            # QA-Audit: ein Betreiber sah bisher nur eine ANZAHL und hatte
            # keine Chance herauszufinden, was ihn blockiert -- ausser
            # Trial-and-Error gegen die Allowlist. Jetzt: bekannte
            # Provider-Felder beim Namen (konstantes Vokabular aus DIESER
            # Datei, nie aus dem Request), alles Uebrige als Fingerprint.
            benannt = sorted(
                key for key in unknown
                if isinstance(key, str) and key in KNOWN_UNSUPPORTED_MESSAGE_FIELDS
            )
            fremd = [key for key in unknown if key not in benannt]
            teile = []
            if benannt:
                teile.append(
                    "bekannt, aber nicht im Register: " + ", ".join(benannt)
                )
            if fremd:
                teile.append(
                    "unbekannt (Fingerprint): "
                    + ", ".join(sorted(_field_fingerprint(k) for k in fremd))
                )
            diagnose = "; ".join(teile)
            _LOG.warning(
                "Nachricht blockiert -- ungepruefte Felder [%s]. "
                "Werte werden bewusst nicht geloggt (Gesetz 5).", diagnose,
            )
            raise DatenschleuseBlocked(
                f"Nachricht enthaelt {len(unknown)} Feld(er), die die "
                f"Datenschleuse nicht prueft ({diagnose}) -- deshalb blockiert "
                f"(fail-closed). Geprueft werden ausschliesslich: "
                f"{_ALLOWED_FIELDS_HINT}."
            )

        role = msg.get("role")
        if role is not None and (not isinstance(role, str) or role not in ALLOWED_ROLES):
            raise DatenschleuseBlocked(
                f"Nachricht mit unbekannter Rolle (Typ {type(role).__name__!r}) "
                "wird von der Datenschleuse nicht geprueft und ist deshalb "
                f"blockiert (fail-closed). Erlaubt: {', '.join(sorted(ALLOWED_ROLES))}."
            )

        # F1 (Security-Audit): das Register blockte bisher unbekannte FELDER,
        # aber nicht den falschen TYP in einem bekannten Feld. Die Masker-Pfade
        # waren durchweg ``if isinstance(..., str)`` -- ein dict in ``name``
        # oder ``refusal`` fiel damit STILL durch und ging verbatim ans
        # Zielmodell. Genau das Muster, das dieses Register beenden soll.
        # Lehre: ein isinstance-Guard im Mask-Pfad ist immer ein stiller
        # Durchlass. Die Typpruefung gehoert hierher und muss blocken.
        for field in ("name", "refusal", "reasoning_content"):
            DatenschleuseGuardrail._validate_text_field(msg.get(field), field)

        DatenschleuseGuardrail._validate_cache_control(msg.get("cache_control"))

        DatenschleuseGuardrail._validate_opaque_id(msg.get("tool_call_id"), "tool_call_id")

        tool_calls = msg.get("tool_calls")
        if tool_calls is not None:
            if not isinstance(tool_calls, list):
                raise DatenschleuseBlocked(
                    f"tool_calls vom Typ {type(tool_calls).__name__!r} ist nicht "
                    "pruefbar und deshalb blockiert (fail-closed). Erlaubt ist "
                    "nur eine Liste."
                )
            for call in tool_calls:
                DatenschleuseGuardrail._validate_tool_call(call)

        function_call = msg.get("function_call")
        if function_call is not None:
            DatenschleuseGuardrail._validate_function_payload(function_call, "function_call")

    @staticmethod
    def _validate_text_field(value: Any, field: str) -> None:
        """Ein Textfeld ist ein String oder gar nicht da. Alles andere ist
        nicht maskierbar -> blocken statt still durchreichen."""
        if value is None or isinstance(value, str):
            return
        raise DatenschleuseBlocked(
            f"{field} vom Typ {type(value).__name__!r} ist kein Text und damit "
            "nicht maskierbar -- blockiert (fail-closed). Erlaubt ist nur ein "
            "String (oder das Feld ganz weglassen)."
        )

    @staticmethod
    def _validate_cache_control(value: Any) -> None:
        """``cache_control`` ist ein Schalter, kein Freitext-Kanal.

        Deshalb validiert statt maskiert -- der Marker muss den Provider
        unveraendert erreichen, sonst greift das Prompt-Caching nicht. Und
        deshalb ENG validiert: waere hier ein ``isinstance``-Guard im
        Verarbeitungspfad statt einer Pruefung, die blockt, waere das exakt
        die Type-Confusion-Luecke (F1) an neuer Stelle."""
        if value is None:
            return
        if not isinstance(value, dict):
            raise DatenschleuseBlocked(
                f"cache_control vom Typ {type(value).__name__!r} ist kein "
                "Caching-Marker -- blockiert (fail-closed). Erlaubt ist nur "
                "ein Objekt wie {'type': 'ephemeral'}."
            )
        unknown = sum(1 for key in value if key not in CACHE_CONTROL_ALLOWED_FIELDS)
        if unknown:
            raise DatenschleuseBlocked(
                f"cache_control enthaelt {unknown} ungepruefte(s) Feld(er) -- "
                "blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(CACHE_CONTROL_ALLOWED_FIELDS))}."
            )
        marker = value.get("type")
        if not isinstance(marker, str) or marker not in CACHE_CONTROL_TYPES:
            raise DatenschleuseBlocked(
                f"cache_control.type (Typ {type(marker).__name__!r}) ist kein "
                "bekannter Caching-Marker -- blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(CACHE_CONTROL_TYPES))}."
            )
        ttl = value.get("ttl")
        if ttl is not None and (not isinstance(ttl, str) or ttl not in CACHE_CONTROL_TTLS):
            raise DatenschleuseBlocked(
                f"cache_control.ttl (Typ {type(ttl).__name__!r}) ist kein "
                "bekannter Wert -- blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(CACHE_CONTROL_TTLS))}."
            )

    @staticmethod
    def _validate_opaque_id(value: Any, field: str) -> None:
        """IDs (``tool_call_id``, ``tool_calls[].id``) sind opake Korrelations-
        Tokens, kein Freitext. Sie werden bewusst NICHT maskiert -- ihr Wert
        muss byte-identisch bleiben, sonst findet das Modell das Ergebnis
        eines Tool-Aufrufs nicht mehr zu seinem Aufruf. Genau deshalb muessen
        sie eng validiert werden, sonst waeren sie der bequemste
        Schmuggelkanal, den die Nachricht zu bieten hat."""
        if value is None:
            return
        if not isinstance(value, str) or not OPAQUE_ID_PATTERN.fullmatch(value):
            raise DatenschleuseBlocked(
                f"{field} ist kein zulaessiger Identifier (Typ "
                f"{type(value).__name__!r}) -- als Freitext-Kanal blockiert "
                "(fail-closed). Erlaubt: bis zu 128 Zeichen aus "
                "A-Z a-z 0-9 _ . : -"
            )

    @staticmethod
    def _validate_tool_call(call: Any) -> None:
        if not isinstance(call, dict):
            raise DatenschleuseBlocked(
                f"tool_call vom Typ {type(call).__name__!r} ist nicht pruefbar "
                "und deshalb blockiert (fail-closed)."
            )
        unknown = sum(1 for key in call if key not in TOOL_CALL_ALLOWED_FIELDS)
        if unknown:
            raise DatenschleuseBlocked(
                f"tool_call enthaelt {unknown} ungepruefte(s) Feld(er) -- "
                "blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(TOOL_CALL_ALLOWED_FIELDS))}."
            )
        DatenschleuseGuardrail._validate_opaque_id(call.get("id"), "tool_calls[].id")

        call_type = call.get("type")
        # ``type`` fehlt bei manchen Clients -- historisch impliziert das
        # "function". Ein ANDERER Typ ist dagegen ein uns unbekanntes Format
        # mit unbekannten Feldern -> blocken.
        if call_type is not None and (
            not isinstance(call_type, str) or call_type not in ALLOWED_TOOL_CALL_TYPES
        ):
            raise DatenschleuseBlocked(
                f"tool_call mit nicht erlaubtem Typ (Typ {type(call_type).__name__!r}) "
                "wird von der Datenschleuse nicht geprueft und ist deshalb "
                f"blockiert (fail-closed). Erlaubt: {', '.join(sorted(ALLOWED_TOOL_CALL_TYPES))}."
            )

        index = call.get("index")
        if index is not None and not isinstance(index, int):
            raise DatenschleuseBlocked(
                f"tool_calls[].index vom Typ {type(index).__name__!r} ist kein "
                "Index -- blockiert (fail-closed)."
            )

        function = call.get("function")
        if function is not None:
            DatenschleuseGuardrail._validate_function_payload(function, "tool_calls[].function")

    @staticmethod
    def _validate_function_payload(function: Any, field: str) -> None:
        if not isinstance(function, dict):
            raise DatenschleuseBlocked(
                f"{field} vom Typ {type(function).__name__!r} ist nicht pruefbar "
                "und deshalb blockiert (fail-closed)."
            )
        unknown = sum(1 for key in function if key not in TOOL_CALL_FUNCTION_ALLOWED_FIELDS)
        if unknown:
            raise DatenschleuseBlocked(
                f"{field} enthaelt {unknown} ungepruefte(s) Feld(er) -- blockiert "
                f"(fail-closed). Erlaubt: "
                f"{', '.join(sorted(TOOL_CALL_FUNCTION_ALLOWED_FIELDS))}."
            )
        # F1: ``arguments`` als dict/Liste statt als JSON-String lief bisher
        # ungeprueft durch -- verifizierter PoC des Security-Audits.
        for name in ("name", "arguments"):
            DatenschleuseGuardrail._validate_text_field(
                function.get(name), f"{field}.{name}"
            )

    def _enforce_sensitivity(
        self,
        text: str,
        entities: List[Dict[str, Any]],
        requested_level: Any,
        approved: bool,
    ) -> None:
        """Schutzklassen-Gate fuer die Felder neben content -- identisch zum
        content-Pfad: Stufe 3 blockt hart, Stufe 2 ohne Freigabe ebenfalls.
        Das Gate darf nicht am content-Feld enden, sonst waere eine Diagnose
        in ``arguments`` weniger geschuetzt als dieselbe Diagnose im Fliesstext."""
        classification = self.classifier.classify(
            text, entities=entities, requested_level=requested_level,
        )
        try:
            sc.enforce_tier_3_block(classification)
            sc.enforce_tier_2_gate(classification, approved)
        except (sc.Tier3Blocked, sc.Tier2ApprovalRequired) as exc:
            raise DatenschleuseBlocked(str(exc)) from exc

    async def _mask_text_value(
        self, text: Any, masker: Masker, requested_level: Any, approved: bool
    ) -> Any:
        """Maskiert einen einzelnen Textwert ueber DENSELBEN Masker wie der
        content-Pfad -- kein zweites Mapping, damit die Re-Identifikation auf
        dem Rueckweg unveraendert funktioniert.

        Anders als im content-Pfad wird hier NICHT nach QI-Typen aufgeteilt:
        QI-Werte werden direkt maskiert statt generalisiert. Das ist strenger
        (ein Platzhalter gibt weniger preis als ein generalisierter Wert),
        nie laxer -- und haelt den QI-Slot-Mechanismus aus Strukturen heraus,
        in denen es keinen zusammenhaengenden Textslot gibt."""
        if not isinstance(text, str) or not text.strip():
            return text
        entities = await self._analyze(text)
        self._enforce_sensitivity(text, entities, requested_level, approved)
        return masker.mask(text, entities)

    async def _mask_json_node(
        self,
        node: Any,
        masker: Masker,
        collected: List[Dict[str, Any]],
        depth: int = 0,
    ) -> Any:
        """Maskiert rekursiv alle Textwerte eines geparsten JSON-Baums und
        laesst die STRUKTUR unangetastet (Akzeptanzkriterium: der Tool-Aufruf
        muss beim Zielmodell benutzbar bleiben).

        Auch SCHLUESSEL werden maskiert: ein JSON-Schluessel ist genauso ein
        Kanal ans Modell wie ein Wert. Maskieren statt Blocken haelt die
        Struktur gueltig.

        Zahlen/Bools: eine Zahl kann PII sein (Telefonnummer, Kundennummer als
        JSON-Zahl). Sie wird deshalb als Text geprueft -- aber nur DANN durch
        einen Platzhalter ersetzt, wenn tatsaechlich etwas erkannt wurde. Der
        damit einhergehende Typwechsel (Zahl -> String) ist bewusst in Kauf
        genommen: ein gebrochenes Tool-Schema ist sichtbar, ein Leck nicht."""
        if depth > MAX_JSON_DEPTH:
            # Ohne Grenze lief hier ein RecursionError aus dem Hook heraus --
            # ein unkontrollierter Fehlerpfad statt fail-closed (F7).
            raise DatenschleuseBlocked(
                f"arguments ueberschreitet die zulaessige Verschachtelungstiefe "
                f"({MAX_JSON_DEPTH}) und wird nicht geprueft -- blockiert "
                "(fail-closed)."
            )
        if isinstance(node, str):
            if not node.strip():
                return node
            entities = await self._analyze(node)
            collected.extend(entities)
            return masker.mask(node, entities)
        if isinstance(node, list):
            return [
                await self._mask_json_node(item, masker, collected, depth + 1)
                for item in node
            ]
        if isinstance(node, dict):
            masked: Dict[Any, Any] = {}
            for key, value in node.items():
                new_key = await self._mask_json_node(key, masker, collected, depth + 1)
                masked[new_key] = await self._mask_json_node(
                    value, masker, collected, depth + 1
                )
            return masked
        if node is None or isinstance(node, bool):
            # Tragen keinen Text -> nichts zu maskieren (bewusste Entscheidung).
            return node
        if isinstance(node, (int, float)):
            as_text = str(node)
            entities = await self._analyze(as_text)
            if not entities:
                return node
            collected.extend(entities)
            return masker.mask(as_text, entities)
        return node

    async def _verify_no_pii_left(self, text: Any, masker: Masker) -> None:
        """Verifikationsdurchlauf auf dem ERGEBNIS (Security-Audit F1).

        Alle Einzelpruefungen oben sind Pfad-gebunden: sie greifen nur, wenn
        ein Wert den Weg nimmt, den jemand vorhergesehen hat. Diese Pruefung
        ist die einzige, die unabhaengig davon greift -- der fertig maskierte
        String geht noch einmal durch den Analyzer. Findet der dort noch
        Entitaeten, ist irgendwo etwas durchgerutscht und der Request wird
        blockiert, statt die PII rauszulassen.

        Die bekannten Platzhalter werden vorher durch ein neutrales Zeichen
        ersetzt: sonst wuerde die Erkennung womoeglich den Platzhalter selbst
        (``<PERSON_0>``) als Namen lesen und jeden korrekt maskierten
        Tool-Aufruf blocken."""
        if not isinstance(text, str) or not text.strip():
            return
        probe = text
        for placeholder in sorted(masker.reid_map, key=len, reverse=True):
            probe = probe.replace(placeholder, _PLACEHOLDER_PROBE_FILLER)
        leftovers = await self._analyze(probe)
        if leftovers:
            types = sorted({str(e.get("entity_type")) for e in leftovers})
            # Nur die Entity-TYPEN nennen (Presidio-Vokabular, kein
            # Client-Inhalt) -- nie den Fundtext selbst (Gesetz 5).
            # Formulierung bewusst ehrlich (QA-Audit): ein Restbefund ist
            # NICHT zwingend ein Fehler im Maskierungspfad. Er entsteht auch
            # durch Grenzfaelle der Erkennung selbst -- derselbe Analyzer
            # findet an derselben Stelle im zweiten Durchlauf etwas, das er
            # im ersten uebersehen hat, weil sich der umgebende Kontext durch
            # die Ersetzung veraendert hat. Belegt am Beispiel
            # "Digitalisierung Rathaus Muenchen" + "Frau Schmidt". Eine
            # Meldung, die dem Betreiber einen Code-Fehler unterstellt, waere
            # in diesen Faellen schlicht falsch.
            raise DatenschleuseBlocked(
                "Nach der Maskierung wurden weiterhin personenbezogene Daten "
                f"erkannt ({', '.join(types)}) -- Request blockiert "
                "(fail-closed). Ursache ist entweder eine Luecke im "
                "Maskierungspfad oder ein Grenzfall der Erkennung, bei dem "
                "erst der zweite Durchlauf anschlaegt. In beiden Faellen "
                "gilt: im Zweifel nicht rauslassen."
            )

    async def _mask_arguments(
        self, raw: Any, masker: Masker, requested_level: Any, approved: bool
    ) -> Any:
        """Maskiert einen ``arguments``-JSON-String strukturerhaltend."""
        if not isinstance(raw, str) or not raw.strip():
            return raw
        try:
            parsed = json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except _UnsafeJson as exc:
            # Mehrdeutiges bzw. nicht standardkonformes JSON: nicht zuverlaessig
            # pruefbar -> blocken. Die Meldung traegt bewusst keinen Fundwert.
            raise DatenschleuseBlocked(
                f"arguments ist nicht eindeutig pruefbar ({exc}) -- blockiert "
                "(fail-closed)."
            ) from exc
        except RecursionError as exc:
            raise DatenschleuseBlocked(
                "arguments ist zu tief verschachtelt, um geprueft zu werden -- "
                "blockiert (fail-closed)."
            ) from exc
        except (ValueError, TypeError):
            # Modelle liefern gelegentlich kaputte ``arguments``. Nicht
            # parsebar heisst NICHT ungeprueft -- dann wird der Rohstring als
            # Freitext maskiert. (Maskieren ist nie ein Leck; ein Block waere
            # hier die haertere, aber unnoetige Reaktion.)
            result = await self._mask_text_value(
                raw, masker, requested_level, approved
            )
            await self._verify_no_pii_left(result, masker)
            return result

        collected: List[Dict[str, Any]] = []
        masked = await self._mask_json_node(parsed, masker, collected)

        # Schutzklassen auf dem GESAMTEN Rohstring: das Signalwort ("Diagnose")
        # und die Personen-Referenz stehen typischerweise in VERSCHIEDENEN
        # JSON-Feldern -- pro Feld einzeln klassifiziert wuerde die Kombination
        # nie erkannt. Uebergeben werden nur die Entity-TYPEN der gesammelten
        # Treffer: der Klassifizierer nutzt von den Entities ausschliesslich
        # den Typ (Personen-Referenz), und feld-lokale Offsets waeren auf den
        # Rohstring bezogen schlicht falsch.
        self._enforce_sensitivity(
            raw,
            [{"entity_type": e.get("entity_type")} for e in collected],
            requested_level,
            approved,
        )
        if masked == parsed:
            # Nichts erkannt -> Original unveraendert weiterreichen (keine
            # kosmetische Re-Serialisierung eines fremden JSON-Strings).
            # ACHTUNG: auch dieser Pfad muss durch die Verifikation -- genau
            # hier ging beim Duplicate-Key-Fund der Rohstring mit PII hinaus.
            result = raw
        else:
            try:
                result = json.dumps(masked, ensure_ascii=False, allow_nan=False)
            except ValueError as exc:
                raise DatenschleuseBlocked(
                    "arguments liess sich nicht als striktes JSON serialisieren "
                    "-- blockiert (fail-closed)."
                ) from exc
        await self._verify_no_pii_left(result, masker)
        return result

    async def _mask_function_payload(
        self, function: Any, masker: Masker, requested_level: Any, approved: bool
    ) -> None:
        """Maskiert ``name`` und ``arguments`` eines Function-/Tool-Calls."""
        if not isinstance(function, dict):
            return
        if isinstance(function.get("name"), str):
            function["name"] = await self._mask_text_value(
                function["name"], masker, requested_level, approved
            )
        if isinstance(function.get("arguments"), str):
            function["arguments"] = await self._mask_arguments(
                function["arguments"], masker, requested_level, approved
            )

    async def _mask_message_fields(
        self, msg: Dict[str, Any], masker: Masker, requested_level: Any, approved: bool
    ) -> None:
        """Maskiert alle Textfelder einer Message AUSSER ``content`` (das
        erledigt der bestehende Pfad im Hook). Reihenfolge der Felder ist
        stabil, damit die Platzhalter-Nummerierung deterministisch bleibt."""
        for field in ("name", "refusal", "reasoning_content"):
            value = msg.get(field)
            if isinstance(value, str):
                msg[field] = await self._mask_text_value(
                    value, masker, requested_level, approved
                )

        tool_calls = msg.get("tool_calls")
        if isinstance(tool_calls, list):
            for call in tool_calls:
                if isinstance(call, dict):
                    await self._mask_function_payload(
                        call.get("function"), masker, requested_level, approved
                    )

        # Legacy-Format (vor tool_calls): dieselbe Nutzlast, andere Stelle.
        await self._mask_function_payload(
            msg.get("function_call"), masker, requested_level, approved
        )

    # ---- Anonymisierungs-Hinweis -------------------------------------------
    @staticmethod
    def _inject_anonymization_notice(
        messages: List[Any], notice: str = ANONYMIZATION_NOTICE
    ) -> None:
        """Fuegt ``notice`` (Default: ANONYMIZATION_NOTICE) in die erste
        System-Message ein (haengt an, falls schon eine existiert) oder legt
        eine neue System-Message an Position 0 an, falls keine vorhanden ist.
        Mutiert ``messages`` in place (wie der Rest von async_pre_call_hook).

        ``notice`` ist optional parametrisierbar, damit Aufrufer (z. B. die
        Cockpit-preview-api) einen nutzerseitig ueberschriebenen Text
        einfuegen koennen, OHNE diese Platzierungs-/Formatierungslogik zu
        duplizieren (Drift-Vermeidung — siehe preview-api/app/masking.py::
        inject_anonymization_notice)."""
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "system":
                content = msg.get("content")
                if isinstance(content, str):
                    msg["content"] = f"{content}\n\n{notice}"
                    return
                if isinstance(content, list):
                    # Multimodale System-Message: als zusaetzlichen Text-Part anhaengen.
                    content.append({"type": "text", "text": notice})
                    return
                # Unbekannter/leerer content -> als String ueberschreiben statt
                # stillschweigend zu verwerfen.
                msg["content"] = notice
                return
        # Keine System-Message vorhanden -> neue an Position 0 einfuegen.
        messages.insert(0, {"role": "system", "content": notice})

    # ---- QI-Layer-Helfer ---------------------------------------------------
    @staticmethod
    def _split_entities(
        entities: List[Dict[str, Any]], qi_types: "frozenset"
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Teilt Analyzer-Entities in (direkte Identifier, Quasi-Identifier)."""
        if not qi_types:
            return list(entities), []
        direct: List[Dict[str, Any]] = []
        qi: List[Dict[str, Any]] = []
        for ent in entities:
            if ent.get("entity_type") in qi_types:
                qi.append(ent)
            else:
                direct.append(ent)
        return direct, qi

    @staticmethod
    def _extract_qi_values(
        original: str, qi_entities: List[Dict[str, Any]]
    ) -> List[Tuple[str, str]]:
        """(Typ, Rohwert)-Paare der QI-Entities aus dem ORIGINALTEXT (vor
        Maskierung; nur dort stimmen die Presidio-Offsets)."""
        out: List[Tuple[str, str]] = []
        for ent in qi_entities:
            etype = ent.get("entity_type")
            start, end = ent.get("start"), ent.get("end")
            if (
                etype
                and isinstance(start, int)
                and isinstance(end, int)
                and 0 <= start < end <= len(original)
            ):
                out.append((etype, original[start:end]))
        return out

    def _process_qi(
        self,
        data: dict,
        user_api_key_dict: Any,
        turn_qi: List[Tuple[str, str]],
        text_slots: List[Tuple[Any, Any]],
    ) -> None:
        """Kernstueck: Session-Key aufloesen, akkumulierte QI-Typen laden,
        Schwellwert pruefen, State aktualisieren und ggf. die QI-Rohwerte in
        den bereits maskierten Text-Slots durch ihre generalisierte Form
        ersetzen.

        Wird nur bei aktivem QI-Layer und vorhandenen QI-Instanzen aufgerufen.
        Session-Key: bevorzugt eine echte, client-gelieferte Session-ID; sonst
        (grob) der API-Key-Hash. Fehlt beides, ist keine Session-uebergreifende
        Akkumulation moeglich -- dann zaehlt nur der aktuelle Turn.
        """
        import qi_state as qs

        session_key, coarse = qs.resolve_session_key(data, user_api_key_dict)

        if session_key is None:
            # Keine Session-Zuordnung moeglich: nur den aktuellen Turn bewerten
            # (kein persistenter State). Das deckt den Single-Shot-Fall ab, in
            # dem z.B. unter `paranoid` schon eine einzelne QI generalisiert
            # werden soll, ohne dass wir etwas speichern koennten.
            seen_before: set = set()
            generalize_now, _ = qig.decide_generalization(
                seen_before, turn_qi, self.qi_threshold
            )
            if generalize_now:
                self._apply_qi_to_slots(text_slots, turn_qi)
            return

        store = self._qi_store
        seen_before = store.get_seen_types(session_key)
        generalize_now, _after = qig.decide_generalization(
            seen_before, turn_qi, self.qi_threshold
        )

        # State aktualisieren: pro QI-Typ nur die GENERALISIERTE Kategorie
        # (nie der Rohwert) verschluesselt ablegen.
        store.record_many(
            session_key,
            [(etype, qig.state_category(etype, value)) for etype, value in turn_qi],
        )

        if generalize_now:
            self._apply_qi_to_slots(text_slots, turn_qi)

    @staticmethod
    def _apply_qi_to_slots(
        text_slots: List[Tuple[Any, Any]], turn_qi: List[Tuple[str, str]]
    ) -> None:
        """Wendet die Generalisierung auf jeden Text-Slot an (wert-basiert;
        QI-Werte, die in einem Slot nicht vorkommen, sind schlicht No-ops).

        Ein Slot ist ein ``(Container, Schluessel)``-Paar. Es gibt genau zwei
        Bauarten, weil der Hook genau zwei registriert:
          * ``(dict, str)``  -- Message/Part/Payload-Feld,
          * ``(list, int)``  -- Eintrag einer ``prompt``-Batch-Liste.

        F2 (DATENSCHLE-69): hier stand
        ``container.get(key) if isinstance(container, dict) else None``.
        Fuer Listen war ``current`` damit immer ``None`` und der Slot wurde
        STILL uebersprungen -- exakt der ``isinstance``-Guard im
        Verarbeitungspfad, den security-baseline.md verbietet und den der
        Guardrail selbst als schwerstes Finding von DATENSCHLE-66 zitiert.

        Die Folge war kein kosmetischer Mangel: Quasi-Identifier werden vom
        Masker BEWUSST nicht ersetzt, weil dieser Layer sie groebern soll.
        Faellt er aus, gehen PLZ und Geburtsjahr in VOLLER Aufloesung hinaus.
        Und ``prompt: ["...", "..."]`` ist die von OpenAI spezifizierte
        Batch-Form -- also gerade der Fall mit vielen Betroffenen.

        Deshalb: kein neuer still ueberspringender Zweig. Ein Container-Typ
        oder ein Slot-Inhalt, den dieser Layer nicht bedienen kann, BLOCKT.
        """
        for container, key in text_slots:
            if isinstance(container, dict):
                current = container.get(key)
            elif isinstance(container, list):
                if not isinstance(key, int) or not 0 <= key < len(container):
                    raise DatenschleuseBlocked(
                        "QI-Generalisierung kann einen registrierten Text-Slot "
                        "nicht adressieren (Listenindex ausserhalb des "
                        "Containers) -- blockiert (fail-closed), statt den "
                        "Slot still zu ueberspringen."
                    )
                current = container[key]
            else:
                raise DatenschleuseBlocked(
                    f"QI-Generalisierung kennt den Slot-Container "
                    f"{type(container).__name__!r} nicht und kann ihn deshalb "
                    "nicht groebern -- blockiert (fail-closed). Ein still "
                    "uebersprungener Slot laesst Quasi-Identifier in voller "
                    "Aufloesung hinaus."
                )
            if not isinstance(current, str):
                raise DatenschleuseBlocked(
                    f"QI-Generalisierung erwartet in einem Text-Slot einen "
                    f"String, fand aber {type(current).__name__!r} -- "
                    "blockiert (fail-closed)."
                )
            container[key] = qig.apply_generalizations(current, turn_qi)

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
        # tool_call-Fragmente kommen in EIGENEN Feldern (delta.tool_calls[i].
        # function.arguments), nicht in delta.content -- und sie sind
        # genauso ueber Chunk-Grenzen zerlegt. Deshalb pro Tool-Call ein
        # eigener Sliding-Window-Prozessor. Fuer ``arguments`` mit
        # JSON-escapten Werten, weil das Fragment INNERHALB eines
        # JSON-Strings landet, den der Client wieder zusammensetzt.
        escaped_map = json_escaped_mapping(reid_map)
        tool_states: Dict[Any, Dict[str, Any]] = {}
        # Reasoning-Modelle streamen ihre Gedankenkette in einem EIGENEN
        # Delta-Feld, nicht in delta.content. Ohne eigenen Prozessor sah der
        # Nutzer dort rohe <PERSON_0>-Tokens: kein Leck, aber AK3 verlangt,
        # dass die Re-Identifikation "ebenso greift wie beim Textkanal" --
        # und Streaming-Reasoning ist ein beworbenes Client-Kernfeature.
        text_processors = {
            field: ReidStreamProcessor(reid_map, margin=self.placeholder_margin)
            for field in STREAM_TEXT_DELTA_FIELDS
        }
        text_templates: Dict[str, Any] = {}

        last_content_chunk = None
        try:
            async for chunk in response:
                self._stream_reidentify_tool_calls(
                    chunk, tool_states, escaped_map, reid_map
                )
                for field in self._stream_reidentify_text_deltas(
                    chunk, text_processors
                ):
                    text_templates[field] = chunk
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
                # Security-Audit: ohne dieses Leeren wandert ein Reasoning-,
                # refusal- oder tool_call-Fragment, das DERSELBE Chunk trug,
                # unveraendert in den Klon -- und ist zu dem Zeitpunkt bereits
                # ausgeliefert. Folge: doppelter Text und, bei tool_calls,
                # deterministisch kaputtes JSON im zusammengesetzten
                # ``arguments``. Der Fix aus der Vorrunde traf nur zwei der
                # drei Tail-Pfade; dieser hier fehlte.
                self._blank_stream_fragments(final_chunk)
                self._set_delta(final_chunk, tail)
                self._clear_finish_reason(final_chunk)
                yield final_chunk
            # Dasselbe fuer die zurueckgehaltenen Enden der tool_call-Puffer:
            # ohne diesen Flush fehlt dem Client das Ende von ``arguments``
            # und das JSON des Tool-Aufrufs ist abgeschnitten.
            for key, state in tool_states.items():
                tails = {
                    field: state[field].flush() for field in ("arguments", "name")
                }
                if state["template"] is None or not any(tails.values()):
                    continue
                yield self._build_tool_tail_chunk(state["template"], key, tails)
            # Und der Rest des Reasoning-Puffers -- ohne diesen Flush fehlt
            # dem Nutzer das Ende der Gedankenkette.
            for field, processor in text_processors.items():
                text_tail = processor.flush()
                template = text_templates.get(field)
                if text_tail and template is not None:
                    yield self._build_text_tail_chunk(template, field, text_tail)

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
                # /v1/completions antwortet mit ``choices[].text`` statt
                # ``choices[].message.content`` (DATENSCHLE-69). Ohne diesen
                # Zweig bekaeme der Client dort rohe Platzhalter zurueck --
                # kein Leck, aber die Route waere nur halb unterstuetzt, und
                # AK 6 verlangt den Rueckweg fuer JEDE unterstuetzte Route.
                text = self._field(choice, "text")
                if isinstance(text, str):
                    self._set_field(choice, "text", reidentify_full(text, reid_map))

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
                # Der Rueckweg muss dieselben Felder abdecken wie der Hinweg
                # (DATENSCHLE-66): gibt das Modell tool_calls zurueck, stehen
                # die Platzhalter in ``arguments`` -- ohne Ersetzung bekaeme
                # der Client <PERSON_0> statt des echten Werts und der
                # Tool-Aufruf liefe auf einem Platzhalter.
                self._reidentify_message_fields(message, reid_map)
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

        Das Mapping ist VERSIEGELT unterwegs (Security-F4) und wird hier
        geoeffnet. Ein Klartext-dict wird nicht mehr angenommen -- siehe
        ``open_reid_map``.
        """
        if not isinstance(request_data, dict):
            return {}
        # DETERMINISTISCH: der erste Kanal, der den Schluessel TRAEGT,
        # gewinnt -- unabhaengig davon, ob er sich oeffnen laesst.
        #
        # Hier stand ``if geoeffnet: return geoeffnet``, also ein Durchfallen
        # auf den naechsten Kanal, wenn das Mapping leer war. Ein LEERES
        # Mapping ist aber ein gueltiges Ergebnis (PII-freier Request), kein
        # "nichts gefunden, weitersuchen". Der Hook schreibt nur nach
        # ``metadata``; ein Angreifer konnte deshalb ein fremdes Siegel in
        # ``litellm_metadata`` legen und es bei jedem PII-freien Request
        # gewinnen lassen -- fremde Klartextwerte in der eigenen Antwort.
        # Zusammen mit dem Strippen in _strip_body_reid_map (die Ursache)
        # ist dieser Weg zu.
        for meta_key in ("metadata", "litellm_metadata"):
            meta = request_data.get(meta_key)
            if isinstance(meta, dict) and REID_MAP_KEY in meta:
                return open_reid_map(meta[REID_MAP_KEY])
        # Fallback: direkt im request_data (manche Codepfade flatten Metadaten).
        if REID_MAP_KEY in request_data:
            return open_reid_map(request_data[REID_MAP_KEY])
        return {}

    @staticmethod
    def _field(obj: Any, name: str) -> Any:
        """Liest ein Feld robust aus dict ODER Objekt (LiteLLM liefert je nach
        Codepfad das eine oder das andere)."""
        if isinstance(obj, dict):
            return obj.get(name)
        return getattr(obj, name, None)

    @staticmethod
    def _set_field(obj: Any, name: str, value: Any) -> None:
        if isinstance(obj, dict):
            obj[name] = value
        else:
            setattr(obj, name, value)

    def _reidentify_function_payload(self, function: Any, reid_map: Dict[str, str]) -> None:
        if function is None:
            return
        name = self._field(function, "name")
        if isinstance(name, str):
            self._set_field(function, "name", reidentify_full(name, reid_map))
        arguments = self._field(function, "arguments")
        if isinstance(arguments, str):
            self._set_field(
                function, "arguments", reidentify_json_arguments(arguments, reid_map)
            )

    def _reidentify_message_fields(self, message: Any, reid_map: Dict[str, str]) -> None:
        """Re-Identification fuer alle Antwort-Felder neben ``content``."""
        for field in ("refusal", "reasoning_content"):
            value = self._field(message, field)
            if isinstance(value, str):
                self._set_field(message, field, reidentify_full(value, reid_map))

        tool_calls = self._field(message, "tool_calls")
        if isinstance(tool_calls, list):
            for call in tool_calls:
                self._reidentify_function_payload(self._field(call, "function"), reid_map)

        self._reidentify_function_payload(self._field(message, "function_call"), reid_map)

    @staticmethod
    def _chunk_delta(chunk: Any) -> Any:
        choices = getattr(chunk, "choices", None)
        if choices is None and isinstance(chunk, dict):
            choices = chunk.get("choices")
        if not choices:
            return None
        first = choices[0]
        delta = getattr(first, "delta", None)
        if delta is None and isinstance(first, dict):
            delta = first.get("delta")
        return delta

    def _iter_stream_functions(self, chunk: Any) -> List[Tuple[Any, Any]]:
        """Liefert (Schluessel, function-Payload) fuer jedes Tool-/Function-Call-
        Fragment eines Chunks. Der Schluessel identifiziert den Tool-Call ueber
        die Streams hinweg (``index``), damit die Fragmente eines Aufrufs im
        richtigen Puffer landen."""
        found: List[Tuple[Any, Any]] = []
        delta = self._chunk_delta(chunk)
        if delta is None:
            return found
        tool_calls = self._field(delta, "tool_calls")
        if isinstance(tool_calls, list):
            for position, call in enumerate(tool_calls):
                index = self._field(call, "index")
                key = ("tool_calls", index if isinstance(index, int) else position)
                found.append((key, self._field(call, "function")))
        function_call = self._field(delta, "function_call")
        if function_call is not None:
            found.append((("function_call", 0), function_call))
        return found

    def _stream_reidentify_tool_calls(
        self,
        chunk: Any,
        states: Dict[Any, Dict[str, Any]],
        escaped_map: Dict[str, str],
        reid_map: Dict[str, str],
    ) -> None:
        """Ersetzt Platzhalter in den tool_call-Fragmenten EINES Chunks
        (in-place) und puffert dabei wie im Text-Kanal nur einen kleinen Tail."""
        for key, function in self._iter_stream_functions(chunk):
            if function is None:
                continue
            state = states.get(key)
            if state is None:
                state = {
                    "arguments": ReidStreamProcessor(
                        escaped_map, margin=self.placeholder_margin
                    ),
                    "name": ReidStreamProcessor(
                        reid_map, margin=self.placeholder_margin
                    ),
                    "template": None,
                }
                states[key] = state
            for field in ("arguments", "name"):
                value = self._field(function, field)
                if isinstance(value, str):
                    self._set_field(function, field, state[field].feed(value))
            state["template"] = chunk

    def _stream_reidentify_text_deltas(
        self, chunk: Any, processors: Dict[str, ReidStreamProcessor]
    ) -> List[str]:
        """Ersetzt Platzhalter in den Freitext-Deltas neben ``content``
        (in-place) und liefert die Felder zurueck, die dieser Chunk trug --
        die taugen dann als Vorlage fuer den jeweiligen Abschluss-Chunk."""
        carried: List[str] = []
        delta = self._chunk_delta(chunk)
        if delta is None:
            return carried
        for field, processor in processors.items():
            value = self._field(delta, field)
            if not isinstance(value, str):
                continue
            self._set_field(delta, field, processor.feed(value))
            carried.append(field)
        return carried

    def _blank_stream_fragments(self, chunk: Any) -> None:
        """Leert in einem GEKLONTEN Chunk alle Fragmente, die der Client
        bereits bekommen hat. Ohne das wuerde ein Abschluss-Chunk den Inhalt
        seiner Vorlage ein zweites Mal ausliefern."""
        self._set_delta(chunk, "")
        delta = self._chunk_delta(chunk)
        if delta is not None:
            for field in STREAM_TEXT_DELTA_FIELDS:
                if isinstance(self._field(delta, field), str):
                    self._set_field(delta, field, "")
        for _key, function in self._iter_stream_functions(chunk):
            if function is None:
                continue
            for field in ("arguments", "name"):
                if isinstance(self._field(function, field), str):
                    self._set_field(function, field, "")

    def _build_tool_tail_chunk(
        self, template: Any, key: Any, tails: Dict[str, str]
    ) -> Any:
        """Baut den Abschluss-Chunk fuer die Rest-Puffer eines Tool-Calls.

        Wie beim Content-Tail wird ein echter Chunk GEKLONT statt ein
        LiteLLM-Typ konstruiert (versionsagnostisch). Alle bereits emittierten
        Fragmente im Klon werden geleert, damit nichts doppelt beim Client
        ankommt -- uebrig bleibt genau der Rest."""
        final_chunk = copy.deepcopy(template)
        self._blank_stream_fragments(final_chunk)
        for other_key, function in self._iter_stream_functions(final_chunk):
            if function is None or other_key != key:
                continue
            for field in ("arguments", "name"):
                if isinstance(self._field(function, field), str):
                    self._set_field(function, field, tails.get(field, ""))
        self._clear_finish_reason(final_chunk)
        return final_chunk

    def _build_text_tail_chunk(self, template: Any, field: str, tail: str) -> Any:
        """Abschluss-Chunk fuer den Restpuffer eines Freitext-Deltas --
        gleiche Mechanik wie beim Content- und Tool-Call-Tail."""
        final_chunk = copy.deepcopy(template)
        self._blank_stream_fragments(final_chunk)
        delta = self._chunk_delta(final_chunk)
        if delta is not None:
            self._set_field(delta, field, tail)
        self._clear_finish_reason(final_chunk)
        return final_chunk

    @staticmethod
    def _delta_target(chunk: Any) -> Optional[Tuple[Any, str]]:
        """Liefert (Container, Feldname) des Text-Kanals eines Chunks.

        Zwei Formen, weil die Datenschleuse zwei Routen bedient
        (DATENSCHLE-69):

        * Chat-Completions streamen ``choices[0].delta.content``.
        * /v1/completions streamt ``choices[0].text`` -- es gibt dort gar kein
          ``delta``-Objekt.

        Lesen und Schreiben gehen bewusst durch DIESELBE Funktion. Wuerden
        Extract und Set die Stelle unabhaengig voneinander bestimmen, koennte
        ein Chat-Chunk ein fremdes ``text``-Feld bekommen (oder umgekehrt) --
        also Text an einer Stelle landen, die der Client nicht liest, waehrend
        der Platzhalter an der gelesenen stehen bleibt."""
        choices = getattr(chunk, "choices", None)
        if choices is None and isinstance(chunk, dict):
            choices = chunk.get("choices")
        if not choices:
            return None
        first = choices[0]
        delta = getattr(first, "delta", None)
        if delta is None and isinstance(first, dict):
            delta = first.get("delta")
        if delta is not None:
            return (delta, "content")
        # Text-Completion-Chunk: der Text haengt direkt an der Choice.
        if isinstance(first, dict):
            if "text" in first:
                return (first, "text")
            return None
        if hasattr(first, "text"):
            return (first, "text")
        return None

    @classmethod
    def _extract_delta(cls, chunk: Any) -> Optional[str]:
        """Holt das Text-Delta eines Chunks. Gibt None zurueck, wenn keines
        vorhanden ist (dann Chunk unveraendert lassen)."""
        try:
            target = cls._delta_target(chunk)
            if target is None:
                return None
            container, field = target
            value = cls._field(container, field)
            return value if isinstance(value, str) else None
        except Exception:
            return None

    @classmethod
    def _set_delta(cls, chunk: Any, value: str) -> None:
        """Setzt das Text-Delta eines Chunks -- an genau der Stelle, aus der
        ``_extract_delta`` gelesen haette."""
        target = cls._delta_target(chunk)
        if target is None:
            return
        container, field = target
        cls._set_field(container, field, value)

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
