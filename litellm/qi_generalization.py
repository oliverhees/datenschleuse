"""Datenschleuse — Quasi-Identifier-Generalisierung (reine, framework-freie Logik).

Hintergrund
-----------
Direkte Identifier (Name, IBAN, Steuer-ID, ...) werden vom bestehenden
``Masker`` in ``datenschleuse_guardrail.py`` zuverlaessig durch Platzhalter
ersetzt. **Quasi-Identifier (QI)** sind ein anderes Problem: einzeln harmlos,
in Kombination re-identifizierend (Sweeney-Klassiker: PLZ + Geburtsdatum +
Geschlecht identifiziert 87 % der US-Buerger eindeutig -- direkt auf DE
uebertragbar). Presidio ist zustandslos und sieht jede Nachricht isoliert;
die Gefahr entsteht erst ueber die AKKUMULATION mehrerer Nachrichten hinweg.

Dieses Modul enthaelt ausschliesslich die REINE Logik:

  * die Menge der QI-Entitaetstypen (``QI_ENTITY_TYPES``),
  * die Risiko-Presets / Schwellwerte (``RISK_PRESETS``),
  * die Generalisierungs-Hierarchie pro QI-Typ (statt Loeschung: Praezision
    reduzieren, Rest-Nutzwert erhalten),
  * die Schwellwert-Entscheidung (``decide_generalization``) und
  * die textuelle Anwendung (``apply_generalizations``).

Der zustandsbehaftete, verschluesselte TTL-Store lebt getrennt in
``qi_state.py``; der LiteLLM-Adapter (``datenschleuse_guardrail.py``) verdrahtet
beide. So bleibt dieses Modul ohne jede Fremd-Abhaengigkeit unit-testbar.

Design-Entscheidung: Maskierung vs. Generalisierung
---------------------------------------------------
Ein QI-Wert wird NICHT wie ein direkter Identifier zu ``<...>`` maskiert,
sondern GENERALISIERT (``84028`` -> ``Region Bayern (Sued)/...``). Grund:
Maskierung wuerde den Nutzwert komplett zerstoeren (das LLM saehe nichts),
Generalisierung erhaelt grobe, nicht-re-identifizierende Kontext-Information.
Deshalb werden die QI-Typen bewusst aus dem direkten Masker herausgehalten und
hier separat behandelt.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Set, Tuple


# ---------------------------------------------------------------------------
# QI-Typen und Risiko-Presets
# ---------------------------------------------------------------------------

# Die Entitaetstypen, die von den EIGENEN QI-Recognizern (presidio/recognizers-
# config.yml) kommen. Genau diese werden aus der direkten Maskierung
# ausgeschlossen und hier generalisiert. LOCATION ist bewusst NICHT dabei:
# es ist ein Standard-Presidio-Identifier und wird weiterhin direkt maskiert
# (das schuetzt den Ort staerker als jede Generalisierung). Fuer die
# Beruf+Ort-Kombination zaehlt DE_BERUF zum Risiko; der Ort selbst bleibt durch
# die direkte Maskierung geschuetzt (siehe generalize()/Modul-Doku im Guardrail).
QI_ENTITY_TYPES: frozenset = frozenset(
    {
        "DE_PLZ",
        "DE_GEBURTSJAHR",
        "DE_TVOED_STUFE",
        "DE_GENDER",
        "DE_BERUF",
    }
)

# Risiko-Regler: Schwellwert = Anzahl UNTERSCHIEDLICHER QI-Typen in einer
# Session, ab der jede neu auftretende QI-Instanz generalisiert wird.
#   utility  -> permissiv, mehr Kontext bleibt erhalten
#   balanced -> Default
#   paranoid -> jede einzelne erkannte QI wird sofort generalisiert
RISK_PRESETS: Dict[str, int] = {
    "utility": 5,
    "balanced": 3,
    "paranoid": 1,
}
DEFAULT_RISK_PRESET = "balanced"


def threshold_for_preset(preset: Optional[str]) -> int:
    """Schwellwert (Anzahl distinkter QI-Typen) fuer ein Preset.

    Unbekannte/leere Presets fallen auf ``balanced`` zurueck (defensiv, damit
    ein Tippfehler in der Config nicht versehentlich die permissivste oder
    strengste Stufe aktiviert).
    """
    if not preset:
        return RISK_PRESETS[DEFAULT_RISK_PRESET]
    return RISK_PRESETS.get(str(preset).strip().lower(), RISK_PRESETS[DEFAULT_RISK_PRESET])


# ---------------------------------------------------------------------------
# Generalisierungs-Hierarchie pro QI-Typ
# ---------------------------------------------------------------------------

# DE_PLZ -> deutsche Grossregion ueber die ERSTE PLZ-Ziffer.
# WICHTIG: das ist eine GROBE Naeherung. Die PLZ-Leitregionen folgen NICHT den
# Bundesland-Grenzen (eine Leitregion kann ueber Landesgrenzen reichen und
# umgekehrt). Die Zuordnung ist die etablierte Standard-Grobgliederung der
# deutschen Leitzonen 0-9 -- bewusst unscharf gehalten, damit generalisiert und
# nicht praezise verortet wird.
PLZ_FIRST_DIGIT_TO_REGION: Dict[str, str] = {
    "0": "Region Sachsen/Thüringen",
    "1": "Region Berlin/Brandenburg/Mecklenburg-Vorpommern",
    "2": "Region Hamburg/Schleswig-Holstein/Nord-Niedersachsen",
    "3": "Region Niedersachsen/Sachsen-Anhalt",
    "4": "Region Nordrhein-Westfalen (Ruhrgebiet)",
    "5": "Region Nordrhein-Westfalen (Süd)/Rheinland-Pfalz (Nord)",
    "6": "Region Hessen/Rheinland-Pfalz (Süd)/Saarland",
    "7": "Region Baden-Württemberg (Nord/Ost)",
    "8": "Region Bayern (Süd)/Baden-Württemberg (Süd)",
    "9": "Region Bayern (Nord/Ost)",
}


def _first_digit(value: str) -> Optional[str]:
    for ch in value:
        if ch.isdigit():
            return ch
    return None


def generalize_plz(value: str) -> str:
    """``84028`` -> ``Region Bayern (Süd)/...``. Fallback bei unbrauchbarem
    Input: neutraler Marker (kein Roh-Leak)."""
    digit = _first_digit(value or "")
    if digit is None:
        return "Region in Deutschland"
    return PLZ_FIRST_DIGIT_TO_REGION.get(digit, "Region in Deutschland")


def generalize_geburtsjahr(value: str) -> str:
    """``1979`` -> ``Ende der 1970er``.

    Dekade + grobe Positionierung: erste 3 Jahre "Anfang", mittlere 4 "Mitte",
    letzte 3 "Ende" (1970-1972 Anfang, 1973-1976 Mitte, 1977-1979 Ende).
    """
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    if len(digits) < 4:
        return "unbekanntes Jahrzehnt"
    year = int(digits[:4])
    decade_start = (year // 10) * 10
    pos_in_decade = year - decade_start  # 0..9
    if pos_in_decade <= 2:
        phase = "Anfang"
    elif pos_in_decade <= 6:
        phase = "Mitte"
    else:
        phase = "Ende"
    return f"{phase} der {decade_start}er"


# DE_TVOed / Besoldung -> grobe 3-stufige Einkommensband-Kategorie.
# Bewusst KEINE Cent-genaue Gehaltslogik (Tariftabellen aendern sich jaehrlich
# und haengen von Stufe/Ortszuschlag ab) -- nur unteres/mittleres/gehobenes Band.
# Zuordnung ueber die fuehrende Entgelt-/Besoldungszahl.
def _extract_tvoed_level(value: str) -> Optional[int]:
    digits = ""
    for ch in value or "":
        if ch.isdigit():
            digits += ch
        elif digits:
            break
    return int(digits) if digits else None


def generalize_tvoed_stufe(value: str) -> str:
    """``TVöD E13`` -> ``gehobenes Einkommensband (öffentlicher Dienst)``.

    Grobe 3-Stufen-Kategorisierung anhand der Entgelt-/Besoldungsgruppe:
      1-6   -> unteres Band
      7-11  -> mittleres Band
      12+   -> gehobenes Band
    """
    level = _extract_tvoed_level(value)
    if level is None:
        return "Einkommensband (öffentlicher Dienst)"
    if level <= 6:
        band = "unteres"
    elif level <= 11:
        band = "mittleres"
    else:
        band = "gehobenes"
    return f"{band} Einkommensband (öffentlicher Dienst)"


def generalize_gender(value: str) -> str:
    """Geschlecht hat keine gröbere Kategorie als die Angabe selbst -- die
    einzige echte Generalisierung ist Unterdrückung. Bei erreichtem Schwellwert
    wird die Angabe deshalb durch einen neutralen Marker ersetzt."""
    return "[Geschlecht anonymisiert]"


# Marker fuer die STATE-Speicherung von Typen, die im Text stehen bleiben
# (z.B. DE_BERUF). NIE der Rohwert -- nur die Tatsache "Typ kam vor".
_BERUF_STATE_CATEGORY = "Berufsangabe (Kategorie)"


def generalize(entity_type: str, value: str) -> Optional[str]:
    """Zentraler Dispatcher: gibt die generalisierte TEXT-Ersetzung fuer eine
    QI-Instanz zurueck -- oder ``None``, wenn der Wert im Text stehen bleiben
    soll (DE_BERUF: der Beruf allein ist meist unkritisch, er zaehlt nur zum
    Session-Risiko; der zugehoerige Ort wird ohnehin direkt maskiert)."""
    if entity_type == "DE_PLZ":
        return generalize_plz(value)
    if entity_type == "DE_GEBURTSJAHR":
        return generalize_geburtsjahr(value)
    if entity_type == "DE_TVOED_STUFE":
        return generalize_tvoed_stufe(value)
    if entity_type == "DE_GENDER":
        return generalize_gender(value)
    if entity_type == "DE_BERUF":
        return None
    return None


def state_category(entity_type: str, value: str) -> str:
    """Die (nicht-rohe) Kategorie, die im verschluesselten State abgelegt wird.

    Fuer transformierbare Typen die generalisierte Form, fuer DE_BERUF ein
    generischer Marker. **Niemals** wird hier der Rohwert zurueckgegeben --
    Projekt-Konvention: nur QI-Typ + generalisierte Kategorie persistieren.
    """
    gen = generalize(entity_type, value)
    if gen is not None:
        return gen
    if entity_type == "DE_BERUF":
        return _BERUF_STATE_CATEGORY
    return "Quasi-Identifier (Kategorie)"


# ---------------------------------------------------------------------------
# Schwellwert-Entscheidung + Text-Anwendung
# ---------------------------------------------------------------------------


def distinct_types_after(seen_types_before: Set[str], turn_types: Set[str]) -> Set[str]:
    """Vereinigung der bereits gesehenen und der in diesem Turn neuen QI-Typen."""
    return set(seen_types_before) | set(turn_types)


def decide_generalization(
    seen_types_before: Set[str],
    turn_qi: Sequence[Tuple[str, str]],
    threshold: int,
) -> Tuple[bool, Set[str]]:
    """Entscheidet, ob in DIESEM Turn generalisiert wird.

    Regel (Schwellwert = Anzahl UNTERSCHIEDLICHER QI-Typen der Session):
    zaehle die distinkten Typen nach Hinzunahme dieses Turns; erreicht/ueber-
    schreitet diese Zahl den Schwellwert, wird generalisiert.

    Beispiel (balanced, Schwellwert 3):
      Turn 1 Typ A  -> {A}      (1 < 3) keine Generalisierung
      Turn 2 Typ B  -> {A,B}    (2 < 3) keine Generalisierung
      Turn 3 Typ C  -> {A,B,C}  (3 >= 3) ab jetzt generalisieren

    Returns ``(generalize_now, distinct_types_after)``.
    """
    turn_types = {t for t, _ in turn_qi}
    after = distinct_types_after(seen_types_before, turn_types)
    return (len(after) >= max(1, int(threshold)), after)


def apply_generalizations(text: str, turn_qi: Sequence[Tuple[str, str]]) -> str:
    """Ersetzt die QI-Rohwerte in ``text`` durch ihre generalisierte Form.

    Wert-basiert (str.replace), weil ``text`` zu diesem Zeitpunkt bereits die
    direkte Maskierung durchlaufen hat und die urspruenglichen Zeichen-Offsets
    dadurch verschoben sind. Die QI-Rohwerte selbst ueberleben die Maskierung
    (QI-Typen sind aus dem direkten Masker ausgeschlossen), sind also noch als
    Teilstrings auffindbar. Laengste Werte zuerst, damit ein kurzer Wert nicht
    faelschlich innerhalb eines laengeren matcht.

    DE_BERUF (generalize()==None) bleibt unveraendert im Text stehen.
    """
    if not text or not turn_qi:
        return text
    # Nach Laenge des Rohwerts absteigend, Duplikate zusammenfassen.
    replacements: List[Tuple[str, str]] = []
    seen_values: Set[Tuple[str, str]] = set()
    for entity_type, value in turn_qi:
        gen = generalize(entity_type, value)
        if gen is None or not value:
            continue
        key = (entity_type, value)
        if key in seen_values:
            continue
        seen_values.add(key)
        replacements.append((value, gen))
    for value, gen in sorted(replacements, key=lambda p: len(p[0]), reverse=True):
        if value in text:
            text = text.replace(value, gen)
    return text
