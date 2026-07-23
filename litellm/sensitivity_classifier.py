"""Datenschleuse — Schutzklassen-Modell (Sensitivitaets-Klassifizierer).

Zweck
-----
Weist JEDER eingehenden Anfrage VOR der eigentlichen PII-Maskierung eine
Sensitivitaetsstufe zu und setzt bei der hoechsten Stufe einen HARTEN Block
durch — der Cloud-Call wird komplett verweigert, auch anonymisiert.

Drei-Stufen-Modell
------------------
- **Stufe 1 (TIER_1) — niedrig sensibel:** normaler Inhalt. Geht nach der
  normalen PII-Maskierung an die Cloud.
- **Stufe 2 (TIER_2) — vertraulich:** braucht Anonymisierung UND eine explizite
  Freigabe (Human-in-the-loop). Ohne Freigabe-Flag: blockiert (sicherer
  Default, nicht durchlassen).
- **Stufe 3 (TIER_3) — hoechst sensibel:** wird NIE an die Cloud geschickt,
  auch nicht anonymisiert. Das ist eine Code-Level-Garantie im Kontrollpfad
  (siehe ``enforce_tier_3_block``), KEINE Config-Option. Sie darf nicht durch
  Config, Header oder Freigabe-Flag umgehbar sein.

Design-Prinzipien (analog datenschleuse_guardrail.py)
-----------------------------------------------------
1. **Reine, framework-freie Logik.** Dieses Modul hat KEINE Presidio-/LiteLLM-
   Abhaengigkeit im Kern. Die Personen-Erkennung bekommt die Presidio-
   ``/analyze``-Entities als Eingabe uebergeben (genau wie ``Masker`` in
   datenschleuse_guardrail.py), statt Presidio selbst aufzurufen. Dadurch ist
   der Klassifizierer ohne laufende Services unit-testbar.
2. **Regelbasiert, transparent, deterministisch.** Bewusst KEIN ML-Klassifikator
   — eine Stufe-3-Hard-Block-Garantie muss reproduzierbar und nachpruefbar sein.
3. **Nachvollziehbarkeit statt Blackbox.** Jede Einstufung liefert eine
   Begruendung (welche Regel/welches Muster gegriffen hat), nicht nur eine Zahl.
   Wichtig fuer Audit eines Sicherheits-Gates.
4. **Fail-closed.** Bei Unsicherheit (Analyse-/Klassifizierungsfehler) wird zur
   STRENGEREN Stufe tendiert, nie zur laxeren (Projekt-Konvention, CLAUDE.md).
5. **Monotone Nutzer-Markierung.** Ein Nutzer kann die Stufe nur ERHOEHEN, nie
   senken: die finale Stufe ist ``max(heuristik, nutzer_wunsch)``. Eine als
   Stufe 3 erkannte Anfrage bleibt Stufe 3 — egal wodurch sie erkannt wurde.

Verhaeltnis zur PII-Maskierung
------------------------------
Die Klassifizierung passiert VOR der Maskierung (Vorschlag), damit ein
Stufe-3-Block greift, bevor ueberhaupt maskiert/weitergereicht wird. Details
und ein konkretes Integrations-Beispiel: docs/SENSITIVITY-INTEGRATION.md.
"""

from __future__ import annotations

import enum
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


# ---------------------------------------------------------------------------
# Stufen-Enum. IntEnum, damit max()/Vergleiche direkt funktionieren
# (TIER_3 > TIER_2 > TIER_1) — Basis fuer die monotone "nur erhoehen"-Regel.
# ---------------------------------------------------------------------------
class Tier(enum.IntEnum):
    TIER_1 = 1  # niedrig sensibel  -> nach Maskierung an die Cloud
    TIER_2 = 2  # vertraulich       -> Maskierung + explizite Freigabe noetig
    TIER_3 = 3  # hoechst sensibel  -> HARTER Block, nie an die Cloud


# ---------------------------------------------------------------------------
# Metadata-Keys im Request (data["metadata"][...]).
# Wir verwenden — wie datenschleuse_guardrail.py mit REID_MAP_KEY — einen
# EIGENEN Metadata-Namespace, statt uns auf LiteLLM-Interna zu verlassen.
# ---------------------------------------------------------------------------
# Explizite Nutzer-Markierung der Stufe (int 1/2/3 oder "1"/"2"/"3").
SENSITIVITY_LEVEL_KEY = "sensitivity_level"
# Human-in-the-loop-Freigabe fuer Stufe 2 (bool true).
SENSITIVITY_APPROVAL_KEY = "sensitivity_approval"


# ---------------------------------------------------------------------------
# Exceptions — analog zu DatenschleuseBlocked im Guardrail.
# ---------------------------------------------------------------------------
class Tier3Blocked(Exception):
    """Wird geworfen, wenn eine Anfrage als Stufe 3 (hoechst sensibel)
    klassifiziert wurde. Im pre_call-Hook geworfen behandelt LiteLLM das als
    Guardrail-Block -> der Request geht NICHT ans LLM (auch nicht maskiert).

    Das ist der Kern der Hard-Block-Garantie. Siehe ``enforce_tier_3_block``."""


class Tier2ApprovalRequired(Exception):
    """Wird geworfen, wenn eine Anfrage als Stufe 2 (vertraulich) klassifiziert
    wurde, aber die explizite Freigabe fehlt. Sicherer Default: ohne Freigabe
    kein (auch kein anonymisierter) Cloud-Call."""


class SensitivityConfigError(Exception):
    """Konfiguration (sensitivity-keywords.yml) konnte nicht geladen werden.

    Ein Sicherheits-Gate, das seine Regeln nicht laden kann, wuerde blind
    klassifizieren und Stufe-3-Inhalte womoeglich als Stufe 1 durchwinken.
    Deshalb fail-closed BEIM START: der Klassifizierer verweigert die
    Konstruktion, statt ohne Regeln zu laufen."""


# ===========================================================================
# Ergebnisobjekt — nachvollziehbar (Prinzip: kein Blackbox-Gate).
# ===========================================================================
@dataclass
class Classification:
    """Ergebnis einer Klassifizierung.

    - ``tier``: die finale, durchzusetzende Stufe (nach der monotonen
      max(heuristik, nutzer)-Regel).
    - ``heuristic_tier``: was die Heuristik allein ergab (fuer Audit/Debug).
    - ``requested_level``: die vom Nutzer explizit markierte Stufe (falls
      vorhanden), sonst None.
    - ``reasons``: menschenlesbare Begruendungen auf KATEGORIE-Ebene (z.B.
      "art9:gesundheit + person_reference"). Bewusst OHNE PII-Klartext, damit
      Begruendungen audit-/log-tauglich sind (Projekt-Prinzip: kein PII in
      Logs).
    - ``matched_signals``: die konkret getroffenen Signalwoerter/Muster-Namen
      (z.B. "Diagnose"). Debug-Hilfe. Sind KEINE PII an sich, koennen aber
      sensibel sein — der Integrator entscheidet, ob er sie loggt.
    """

    tier: Tier
    heuristic_tier: Tier
    requested_level: Optional[int]
    reasons: List[str] = field(default_factory=list)
    matched_signals: List[str] = field(default_factory=list)

    @property
    def is_tier_3(self) -> bool:
        return self.tier is Tier.TIER_3

    @property
    def is_tier_2(self) -> bool:
        return self.tier is Tier.TIER_2

    def summary(self) -> str:
        """Kurze, log-taugliche Zusammenfassung OHNE PII-Klartext."""
        why = "; ".join(self.reasons) if self.reasons else "keine Regel gegriffen"
        return f"Stufe {int(self.tier)} ({self.tier.name}): {why}"


# ===========================================================================
# Default-Pfad zur Config. Prioritaet: Argument > ENV > Repo-Default.
# ===========================================================================
_DEFAULT_CONFIG_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "presidio", "sensitivity-keywords.yml")
)


def _load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Laedt die Keyword-/Muster-Config aus YAML. Fail-closed: jeder Fehler
    (Datei fehlt, YAML kaputt, PyYAML nicht installiert) wird zu
    SensitivityConfigError eskaliert — lieber gar nicht starten als blind
    klassifizieren."""
    path = config_path or os.getenv("SENSITIVITY_KEYWORDS_PATH") or _DEFAULT_CONFIG_PATH
    try:
        import yaml  # lokal importiert, damit der reine-Logik-Teil ohne PyYAML testbar bleibt (Config als dict injizierbar)
    except Exception as exc:  # pragma: no cover
        raise SensitivityConfigError(
            f"PyYAML nicht verfuegbar, kann {path} nicht laden ({exc})."
        ) from exc
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:
        raise SensitivityConfigError(
            f"Sensitivitaets-Config nicht ladbar ({path}): {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise SensitivityConfigError(
            f"Sensitivitaets-Config hat unerwartetes Format ({path}): {type(data)!r}"
        )
    return data


# ===========================================================================
# Kern: der Klassifizierer.
# ===========================================================================
class SensitivityClassifier:
    """Regelbasierter, deterministischer Sensitivitaets-Klassifizierer.

    Konstruktion (einmalig, z.B. beim Guardrail-Init):
        clf = SensitivityClassifier()                    # laedt Repo-Default-Config
        clf = SensitivityClassifier(config_path="...")   # eigener Pfad
        clf = SensitivityClassifier(config={...})        # Config direkt (Tests)

    Klassifizierung (pro Anfrage):
        result = clf.classify(text, entities=presidio_entities,
                              requested_level=metadata.get("sensitivity_level"))
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[str] = None,
        fail_closed_tier: Tier = Tier.TIER_2,
    ) -> None:
        # fail_closed_tier: auf welche Stufe eine EINZELNE fehlgeschlagene
        # Klassifizierung faellt. Default TIER_2 = nichts geht automatisch
        # durch (Freigabe noetig), ohne den harten Dauer-Block von TIER_3 zu
        # verhaengen (ein transienter Fehler soll den Dienst nicht permanent
        # totlegen). Wer maximal streng will, setzt Tier.TIER_3.
        if fail_closed_tier not in (Tier.TIER_2, Tier.TIER_3):
            raise ValueError("fail_closed_tier muss TIER_2 oder TIER_3 sein (nicht laxer als TIER_2).")
        self.fail_closed_tier = fail_closed_tier

        cfg = config if config is not None else _load_config(config_path)

        # --- Art.-9-/Art.-10-Kategorien (Stufe 3) ---
        raw_cats = cfg.get("tier3_special_categories") or {}
        if not isinstance(raw_cats, dict) or not raw_cats:
            raise SensitivityConfigError("tier3_special_categories fehlt oder ist leer — Gate waere blind.")
        # {kategorie -> [kompilierte Wortgrenzen-Regexes]}
        self._tier3: Dict[str, List[re.Pattern]] = {
            str(cat): [_compile_wordish(w) for w in (words or [])]
            for cat, words in raw_cats.items()
        }

        # --- Stufe-2-Kontextwoerter + Muster ---
        self._tier2_context: List[re.Pattern] = [
            _compile_wordish(w) for w in (cfg.get("tier2_context_words") or [])
        ]
        raw_patterns = cfg.get("tier2_patterns") or {}
        self._tier2_patterns: Dict[str, re.Pattern] = {
            str(name): re.compile(rx, re.IGNORECASE)
            for name, rx in raw_patterns.items()
        }

        # --- Personen-Referenz ---
        self._person_entities = {
            str(e).upper() for e in (cfg.get("person_linking_entities") or [])
        }
        self._person_indicators: List[re.Pattern] = [
            _compile_wordish(w) for w in (cfg.get("person_indicators") or [])
        ]

    # -----------------------------------------------------------------------
    # Oeffentliche API
    # -----------------------------------------------------------------------
    def classify(
        self,
        text: str,
        entities: Optional[Sequence[Dict[str, Any]]] = None,
        requested_level: Any = None,
    ) -> Classification:
        """Ordnet ``text`` einer Stufe 1/2/3 zu.

        Parameter
        ---------
        text : str
            Der zu pruefende (Klartext-)Nachrichtentext.
        entities : Liste von Presidio-/analyze-Dicts, optional
            Ergebnis von Presidio (``entity_type``/``start``/``end``). Wird nur
            fuer die Personen-Referenz genutzt (kein Presidio-Call hier).
        requested_level : int/str, optional
            Explizite Nutzer-Markierung (metadata.sensitivity_level).

        Rueckgabe
        ---------
        Classification (nachvollziehbar; finale Stufe = max(heuristik, nutzer)).
        """
        try:
            return self._classify_impl(text, entities, requested_level)
        except Exception as exc:  # fail-closed: Unsicherheit -> strengere Stufe
            return Classification(
                tier=self.fail_closed_tier,
                heuristic_tier=self.fail_closed_tier,
                requested_level=_parse_level(requested_level),
                reasons=[f"classification_error_fail_closed ({type(exc).__name__})"],
            )

    # -----------------------------------------------------------------------
    # Interne Klassifizierungslogik
    # -----------------------------------------------------------------------
    def _classify_impl(
        self,
        text: str,
        entities: Optional[Sequence[Dict[str, Any]]],
        requested_level: Any,
    ) -> Classification:
        text = text or ""
        reasons: List[str] = []
        matched: List[str] = []

        user_level = _parse_level(requested_level)

        # 1) Personen-Referenz bestimmen (Presidio-Entities + Text-Fallback).
        person_ref, person_reason = self._has_person_reference(text, entities)

        # 2) Heuristik: Stufe 3 (Art. 9 / Art. 10) — nur mit Personen-Referenz.
        heuristic = Tier.TIER_1
        art9_cats = self._scan_tier3(text, matched)
        if art9_cats:
            if person_ref:
                heuristic = Tier.TIER_3
                reasons.append(
                    "art9: " + ", ".join(sorted(art9_cats)) + " + " + person_reason
                )
            else:
                # Besondere Kategorie ohne Personenbezug (z.B. allgemeine
                # Wissensfrage "Was ist HIV?") -> kein Personendatum.
                reasons.append(
                    "art9-signal ohne Personen-Referenz -> nicht Stufe 3: "
                    + ", ".join(sorted(art9_cats))
                )

        # 3) Heuristik: Stufe 2 (vertraulich) — nur wenn nicht schon Stufe 3.
        if heuristic < Tier.TIER_3:
            tier2_hits = self._scan_tier2(text, matched)
            if tier2_hits and person_ref:
                heuristic = max(heuristic, Tier.TIER_2)
                reasons.append(
                    "vertraulich: " + ", ".join(sorted(tier2_hits)) + " + " + person_reason
                )
            elif tier2_hits and not person_ref:
                reasons.append(
                    "vertraulich-signal ohne Personen-Referenz -> nicht Stufe 2: "
                    + ", ".join(sorted(tier2_hits))
                )

        # 4) Explizite Nutzer-Markierung einrechnen — MONOTON (nur erhoehen).
        #    Der Nutzer kann die Stufe hochsetzen, aber nie unter die Heuristik
        #    druecken. Damit ist eine als Stufe 3 erkannte Anfrage nicht
        #    "weg-konfigurierbar".
        final = heuristic
        if user_level is not None:
            user_tier = Tier(user_level)
            if user_tier > heuristic:
                reasons.append(f"nutzer-markierung erhoeht auf Stufe {int(user_tier)}")
            elif user_tier < heuristic:
                reasons.append(
                    f"nutzer-markierung Stufe {int(user_tier)} ignoriert "
                    f"(Heuristik strenger: Stufe {int(heuristic)})"
                )
            final = max(heuristic, user_tier)

        if final is Tier.TIER_1 and not reasons:
            reasons.append("keine Sensitivitaets-Signale gefunden -> Stufe 1")

        return Classification(
            tier=final,
            heuristic_tier=heuristic,
            requested_level=user_level,
            reasons=reasons,
            matched_signals=matched,
        )

    # -----------------------------------------------------------------------
    # Bausteine
    # -----------------------------------------------------------------------
    def _has_person_reference(
        self, text: str, entities: Optional[Sequence[Dict[str, Any]]]
    ) -> tuple[bool, str]:
        """True, wenn der Text sich auf eine konkrete Person bezieht.

        Primaer: eine Presidio-Entity aus ``person_linking_entities``.
        Fallback: ein textbasierter Personen-Indikator (z.B. 'Patient')."""
        if entities:
            for ent in entities:
                if not isinstance(ent, dict):
                    continue
                etype = str(ent.get("entity_type", "")).upper()
                if etype in self._person_entities:
                    return True, f"person_reference (entity:{etype})"
        for rx in self._person_indicators:
            if rx.search(text):
                return True, "person_reference (indikator)"
        return False, ""

    def _scan_tier3(self, text: str, matched: List[str]) -> List[str]:
        """Gibt die Namen der getroffenen Art.-9-/Art.-10-Kategorien zurueck."""
        hit_categories: List[str] = []
        for category, patterns in self._tier3.items():
            for rx in patterns:
                m = rx.search(text)
                if m:
                    hit_categories.append(category)
                    matched.append(m.group(0))
                    break  # eine Kategorie einmal zaehlen reicht
        return hit_categories

    def _scan_tier2(self, text: str, matched: List[str]) -> List[str]:
        """Gibt die getroffenen Stufe-2-Signale (Kontextwort- oder Musternamen)
        zurueck."""
        hits: List[str] = []
        for rx in self._tier2_context:
            m = rx.search(text)
            if m:
                hits.append("kontextwort")
                matched.append(m.group(0))
                break
        for name, rx in self._tier2_patterns.items():
            m = rx.search(text)
            if m:
                hits.append(name)
                matched.append(m.group(0))
        return hits


# ---------------------------------------------------------------------------
# Freigabe-Gate (Stufe 2) und Hard-Block (Stufe 3)
# ---------------------------------------------------------------------------
def enforce_tier_3_block(classification: Classification) -> None:
    """HARTE Stufe-3-Garantie. Wirft ``Tier3Blocked``, wenn die Anfrage als
    Stufe 3 klassifiziert wurde.

    !!! WICHTIG FUER SPAETERE ENTWICKLER !!!
    Diese Funktion nimmt BEWUSST NUR das Classification-Objekt entgegen und
    KEINE weiteren Parameter. Fuege NIEMALS ein Bypass-Argument hinzu — kein
    ``force=True``, kein ``override_tier3``, kein ``allow=...``, keinen
    Freigabe-/Header-/Config-Parameter. Stufe 3 ist eine Code-Level-Zusage
    ("wird NIE an die Cloud geschickt"), keine Konfiguration. Der einzige Weg,
    Stufe 3 nicht auszuloesen, ist, dass die Anfrage gar nicht erst als Stufe 3
    klassifiziert wird — nicht, sie nachtraeglich "durchzuwinken".

    Ein Umgehungsversuch (leeres Freigabe-Flag, manipulierte Metadaten,
    gesetztes Approval, gesenkte Nutzer-Stufe) darf hier NICHTS aendern: die
    Funktion schaut ausschliesslich auf ``classification.tier``.
    """
    if classification.tier is Tier.TIER_3:
        raise Tier3Blocked(
            "Anfrage als Stufe 3 (hoechst sensibel, Art. 9/10 DSGVO) "
            "klassifiziert und wird NICHT an die Cloud gesendet — auch nicht "
            "anonymisiert. Harte Code-Garantie, nicht konfigurierbar. "
            f"Begruendung: {classification.summary()}"
        )


def is_release_approved(metadata: Any) -> bool:
    """Liest das Stufe-2-Freigabe-Flag aus den Request-Metadaten.

    Erwartet ``metadata[SENSITIVITY_APPROVAL_KEY] is True`` (echtes bool True
    oder die Strings 'true'/'1'/'yes'/'ja', case-insensitiv). Alles andere —
    fehlend, None, False, leerer String, beliebiger Text — gilt als NICHT
    freigegeben (sicherer Default)."""
    if not isinstance(metadata, dict):
        return False
    val = metadata.get(SENSITIVITY_APPROVAL_KEY)
    if val is True:
        return True
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes", "ja")
    return False


def enforce_tier_2_gate(classification: Classification, approved: bool) -> None:
    """Freigabe-Gate fuer Stufe 2. Wirft ``Tier2ApprovalRequired``, wenn die
    Anfrage Stufe 2 ist und KEINE explizite Freigabe vorliegt.

    Ohne Freigabe wird NICHT durchgelassen ("Freigabe fehlt" ist der sichere
    Default). Stufe 1 und Stufe 3 sind hier no-ops — Stufe 3 wird separat und
    zuerst durch ``enforce_tier_3_block`` behandelt (der harte Block darf nie
    von einem Freigabe-Flag beeinflussbar sein)."""
    if classification.tier is Tier.TIER_2 and not approved:
        raise Tier2ApprovalRequired(
            "Anfrage als Stufe 2 (vertraulich) klassifiziert. Es fehlt die "
            f"explizite Freigabe (metadata.{SENSITIVITY_APPROVAL_KEY} = true). "
            "Ohne Freigabe wird der (auch anonymisierte) Cloud-Call blockiert. "
            f"Begruendung: {classification.summary()}"
        )


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
def _compile_wordish(word: str) -> re.Pattern:
    """Kompiliert ein Signalwort/eine Phrase mit Wortgrenzen und
    case-insensitiv. Lookarounds ``(?<!\\w)``/``(?!\\w)`` funktionieren auch bei
    Umlauten (Python-``\\w`` ist unter str unicode-aware), sodass z.B.
    'Religion' nicht faelschlich in 'Religionsunterricht' matcht, aber
    'Diagnose:' (Satzzeichen) sauber greift."""
    return re.compile(r"(?<!\w)" + re.escape(word) + r"(?!\w)", re.IGNORECASE)


def _parse_level(value: Any) -> Optional[int]:
    """Parst eine explizite Nutzer-Stufe robust zu 1/2/3 oder None.

    Fail-closed: ein UNGUELTIGER, aber gesetzter Wert (z.B. 0, 4, "hoch")
    wird NICHT ignoriert (das waere lax), sondern auf die strengste Stufe 3
    gehoben — wer eine kaputte Stufenangabe schickt, bekommt den strengen
    Default, nicht den laxen."""
    if value is None:
        return None
    try:
        lvl = int(str(value).strip())
    except (ValueError, TypeError):
        return int(Tier.TIER_3)
    if lvl in (1, 2, 3):
        return lvl
    return int(Tier.TIER_3)
