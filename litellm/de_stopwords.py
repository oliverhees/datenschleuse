"""Laedt die deutsche Nicht-PII-Wortliste fuer den Guardrail (DATENSCHLE-82).

WOFUER
======
``presidio/de-stopwords.yml`` unterdrueckt gemessene Fehlzuendungen des
spaCy-NER ueber Presidios ``allow_list``-Mechanismus. Die Liste war gemessen,
auditiert und gemergt -- und wirkte ausschliesslich im Benchmark
(``test/corpus-benchmark.py``). Der laufende Proxy hat sie nie gesendet:

    grep -n "allow_list\\|stopword" litellm/datenschleuse_guardrail.py  ->  0

Damit beschrieben die Zahlen in ``docs/foundation/erkennungsziel.md`` den
erreichbaren, nicht den ausgelieferten Zustand. Dieses Modul schliesst die
Luecke: es laedt die Liste einmalig beim Start und liefert die drei Felder,
die der Guardrail an ``POST /analyze`` haengt.

Eigenes Modul und nicht inline im Guardrail, aus demselben Grund wie
``sensitivity_classifier.py`` und ``custom_rules.py``: Das Laden ist reine,
container-frei testbare Logik, und der Guardrail ist mit ueber 2000 Zeilen
gross genug.

WARUM ``regex_flags`` PFLICHT IST (Security-Finding F1)
======================================================
``AnalyzerRequest`` defaultet ``regex_flags`` auf
``DOTALL | MULTILINE | IGNORECASE``, wenn der Aufrufer sie nicht sendet. Unter
``MULTILINE`` matchen ``^``/``$`` an JEDEM Zeilenumbruch INNERHALB des Spans --
sie sind dann Zeilen-Anker, kein Vollspan-Anker:

    Span "Zahlungsart\\nLoewenstein"
      mit ^zahlungsart$   : Treffer -> ganzer Span weg, Nachname verloren
      mit \\Azahlungsart\\z : kein Treffer -> PERSON 'Loewenstein' bleibt

Genau daran ist die erste Fassung der Liste gescheitert. Deshalb wird der Wert
aus der Datei gelesen und EXPLIZIT mitgesendet; fehlt er, laedt dieses Modul
gar nicht erst.

WARUM ALLES FAIL-CLOSED IST
===========================
Jeder Fehler beim Laden fuehrt zu ``StopwordConfigError`` und damit zu einem
Startfehler des Guardrails -- nie zu "laeuft eben ohne Liste weiter". Ein
stiller Weiterlauf waere eine unbemerkte Verhaltensaenderung: Die Erkennung
verhielte sich anders als gemessen, ohne dass irgendwo etwas dagegen spricht.
Im Betrieb existiert die Datei entweder, oder der Dienst startet nicht.

VORRANG DER BETREIBER-KONFIGURATION
===================================
Presidios ``allow_list`` wirkt NACH der Erkennung: sie entfernt jeden Treffer,
dessen Span sie matcht -- unabhaengig davon, welcher Recognizer ihn erzeugt
hat. Sie trifft damit auch die ``deny_list``-Recognizer aus
``presidio/recognizers-config.yml`` (DE_GENDER, DE_BERUF). Live belegt:

    "Der Buergermeister kommt morgen vorbei."
      ohne allow_list                        -> DE_BERUF 'Buergermeister'
      mit kollidierender allow_list          -> kein Treffer, KEINE Warnung

Eine ``deny_list`` ist eine ausdrueckliche Schutzanweisung des Betreibers, die
Stoppwortliste eine mitgelieferte Vorgabe. Eine Vorgabe darf eine
ausdrueckliche Anweisung nicht still ueberstimmen -- sonst nimmt ein
Datenschleuse-Update lautlos Schutz weg, den der Betreiber selbst konfiguriert
hat, und niemand erfaehrt davon.

Deshalb prueft ``load()`` die Ueberschneidung und scheitert bei einem Treffer.
Ausdruecklich NICHT zulaessig und hier bewusst nicht implementiert: den
kollidierenden Eintrag still ueberspringen oder ihn wirken lassen. Wer beides
konfiguriert hat, hat einen Konflikt, den nur er aufloesen kann; der Dienst
darf ihn nicht fuer ihn entscheiden.

Bindend festgehalten in ``docs/foundation/erkennungsziel.md`` §7 und
``docs/adr/0002-nicht-pii-wortliste.md`` (Konsequenz 2).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

import regex
import yaml

__all__ = [
    "StopwordConfigError",
    "AllowList",
    "default_stopwords_path",
    "default_recognizers_path",
    "load",
]


class StopwordConfigError(Exception):
    """Die Nicht-PII-Wortliste konnte nicht sicher geladen werden.

    Wird vom Guardrail-Konstruktor NICHT gefangen: der Dienst startet dann
    nicht. Das ist beabsichtigt (fail-closed, siehe Modul-Docstring).
    """


class AllowList:
    """Die drei Felder, die an ``POST /analyze`` gehen -- plus die Herkunft.

    Unveraenderlich gehalten, damit die geladene Konfiguration nicht zur
    Laufzeit unter dem Guardrail wegwandern kann.
    """

    __slots__ = ("patterns", "regex_flags", "source")

    def __init__(self, patterns: Tuple[str, ...], regex_flags: int, source: str) -> None:
        object.__setattr__(self, "patterns", tuple(patterns))
        object.__setattr__(self, "regex_flags", int(regex_flags))
        object.__setattr__(self, "source", source)

    def __setattr__(self, *_args: Any) -> None:  # pragma: no cover - Schutz
        raise AttributeError("AllowList ist unveraenderlich.")

    def as_payload(self) -> Dict[str, Any]:
        """Die Felder fuer das ``/analyze``-Payload.

        ``allow_list_match`` und ``regex_flags`` gehoeren untrennbar dazu:
        ohne ``regex`` vergleicht Presidio Literale (die verankerten Muster
        treffen dann nie), ohne explizite Flags greift der gefaehrliche
        Server-Default (F1).
        """
        return {
            "allow_list": list(self.patterns),
            "allow_list_match": "regex",
            "regex_flags": self.regex_flags,
        }

    def __len__(self) -> int:
        return len(self.patterns)

    def __repr__(self) -> str:  # pragma: no cover - Diagnose
        return "AllowList(%d Muster, regex_flags=%d, %s)" % (
            len(self.patterns),
            self.regex_flags,
            self.source,
        )


_HERE = os.path.dirname(os.path.abspath(__file__))


def default_stopwords_path() -> str:
    """Pfad der Wortliste: ENV vor Repo-Layout.

    Das Repo-Layout (``litellm/`` und ``presidio/`` sind Geschwister) stimmt
    im Image NICHT -- dort ist ``/app`` flach. docker-compose.yml mountet die
    Datei deshalb nach ``/app/config/`` und setzt die ENV-Variable; derselbe
    Weg wie bei ``SENSITIVITY_KEYWORDS_PATH``.
    """
    return os.getenv("DATENSCHLEUSE_STOPWORDS_PATH") or os.path.normpath(
        os.path.join(_HERE, "..", "presidio", "de-stopwords.yml")
    )


def default_recognizers_path() -> str:
    """Pfad der Betreiber-Recognizer-Config (fuer die Vorrangspruefung)."""
    return os.getenv("DATENSCHLEUSE_RECOGNIZERS_PATH") or os.path.normpath(
        os.path.join(_HERE, "..", "presidio", "recognizers-config.yml")
    )


def _read_yaml(path: str, was: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except OSError as exc:
        raise StopwordConfigError(
            f"{was} nicht lesbar: {path} ({exc}). Der Guardrail startet "
            f"bewusst nicht ohne sie -- ein stiller Weiterlauf waere eine "
            f"unbemerkte Verhaltensaenderung. Pfad ueber die passende "
            f"ENV-Variable setzen oder die Datei mounten."
        ) from exc
    except yaml.YAMLError as exc:
        raise StopwordConfigError(f"{was} ist kein gueltiges YAML: {path} ({exc}).") from exc


def _parse_stopwords(doc: Any, path: str) -> Tuple[List[str], int]:
    """Strukturpruefung der Wortliste.

    Bewusst dieselben Pruefungen wie ``test/corpus-benchmark.py::
    load_stopwords`` -- der Benchmark misst sonst mit einer anderen Liste als
    der Dienst sendet, und die gemessene Zahl beschriebe wieder nicht den
    ausgelieferten Zustand. ``test_de_stopwords.py`` haelt beide Seiten
    maschinell aneinander.
    """
    if not isinstance(doc, dict):
        raise StopwordConfigError(
            f"Stoppwortliste {path}: erwartet ein Mapping auf oberster Ebene."
        )
    if doc.get("allow_list_match") != "regex":
        raise StopwordConfigError(
            f"Stoppwortliste {path}: allow_list_match muss 'regex' sein "
            f"(gefunden: {doc.get('allow_list_match')!r}). Als Literal-Liste "
            f"wuerden die verankerten Muster nie treffen."
        )
    if "regex_flags" not in doc:
        raise StopwordConfigError(
            f"Stoppwortliste {path}: 'regex_flags' fehlt. Ohne explizite Flags "
            f"defaultet der Analyzer auf DOTALL|MULTILINE|IGNORECASE -- dann "
            f"sind ^/$ Zeilen-Anker und mehrzeilige Spans wie "
            f"'Zahlungsart\\nLoewenstein' werden komplett unterdrueckt, "
            f"inklusive des echten Nachnamens (Security-Finding F1)."
        )
    regex_flags = doc["regex_flags"]
    if not isinstance(regex_flags, int) or isinstance(regex_flags, bool):
        raise StopwordConfigError(
            f"Stoppwortliste {path}: 'regex_flags' muss eine Ganzzahl sein "
            f"(gefunden: {regex_flags!r})."
        )

    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        raise StopwordConfigError(f"Stoppwortliste {path}: 'entries' fehlt oder ist leer.")

    patterns: List[str] = []
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("pattern"), str):
            raise StopwordConfigError(
                f"Stoppwortliste {path}: entries[{idx}] hat kein String-Feld 'pattern'."
            )
        patterns.append(entry["pattern"])

    return patterns, regex_flags


def _compile_joined(patterns: List[str], regex_flags: int, path: str) -> "regex.Pattern[str]":
    """Kompiliert das GEJOINTE Muster -- so, wie der Analyzer es tut.

    ``AnalyzerEngine._remove_allow_list`` joint alle Eintraege mit ``|`` zu
    EINEM Ausdruck. Einzeln kompilierbare Muster koennen gejoint scheitern
    (z.B. globale Inline-Flags nicht am Anfang). Hier scheitern ist besser als
    im Betrieb.
    """
    try:
        return regex.compile("|".join(patterns), flags=regex_flags)
    except Exception as exc:
        raise StopwordConfigError(
            f"Stoppwortliste {path}: das gejointe Muster kompiliert nicht "
            f"({exc}). Der Analyzer joint alle Eintraege mit '|' zu EINEM "
            f"Ausdruck."
        ) from exc


def _deny_list_terms(path: str) -> List[Tuple[str, str]]:
    """Alle ``deny_list``-Terme aus der Recognizer-Config des Betreibers."""
    doc = _read_yaml(path, "Recognizer-Config des Betreibers")
    if not isinstance(doc, dict):
        raise StopwordConfigError(
            f"Recognizer-Config {path}: erwartet ein Mapping auf oberster Ebene. "
            f"Ohne sie ist der Betreiber-Vorrang nicht pruefbar."
        )
    terms: List[Tuple[str, str]] = []
    for rec in doc.get("recognizers") or []:
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("name") or "<ohne Namen>")
        for term in rec.get("deny_list") or []:
            if isinstance(term, str):
                terms.append((name, term))
    return terms


def _assert_operator_precedence(
    matcher: "regex.Pattern[str]",
    deny_terms: List[Tuple[str, str]],
    stopwords_path: str,
    recognizers_path: str,
) -> None:
    """Fail-closed bei Ueberschneidung mit der ``deny_list`` des Betreibers.

    ``search`` und nicht ``fullmatch``, weil der Analyzer selbst ``search``
    aufruft -- die Muster verankern sich mit ``\\A...\\z`` selbst.
    """
    kollisionen = [(name, term) for name, term in deny_terms if matcher.search(term)]
    if not kollisionen:
        return
    beschreibung = ", ".join(f"{term!r} ({name})" for name, term in kollisionen)
    raise StopwordConfigError(
        f"Betreiber-Vorrang verletzt: die Stoppwortliste {stopwords_path} "
        f"unterdrueckt {len(kollisionen)} deny_list-Term(e) aus "
        f"{recognizers_path} -- {beschreibung}. Presidios allow_list wirkt "
        f"NACH der Erkennung und entfernt diese Treffer ohne jede Meldung. "
        f"Eine mitgelieferte Vorgabeliste darf eine ausdrueckliche "
        f"Schutzanweisung des Betreibers nicht still ueberstimmen, deshalb "
        f"startet der Dienst nicht. Aufloesen kann den Konflikt nur der "
        f"Betreiber: den Term aus der deny_list nehmen ODER den passenden "
        f"Eintrag aus der Stoppwortliste. Siehe "
        f"docs/foundation/erkennungsziel.md §7."
    )


def load(
    stopwords_path: Optional[str] = None,
    recognizers_path: Optional[str] = None,
) -> AllowList:
    """Laedt die Wortliste und prueft den Betreiber-Vorrang. Fail-closed.

    :raises StopwordConfigError: bei jedem Problem -- unlesbare oder
        strukturell fehlerhafte Datei, nicht kompilierendes gejointes Muster,
        fehlende Recognizer-Config, Ueberschneidung mit einer ``deny_list``.
    """
    stopwords_path = stopwords_path or default_stopwords_path()
    recognizers_path = recognizers_path or default_recognizers_path()

    doc = _read_yaml(stopwords_path, "Stoppwortliste")
    patterns, regex_flags = _parse_stopwords(doc, stopwords_path)
    matcher = _compile_joined(patterns, regex_flags, stopwords_path)

    # Die Vorrangspruefung braucht die Betreiber-Config. Ist sie nicht lesbar,
    # ist der Vorrang nicht pruefbar -- und "nicht pruefbar" heisst nicht
    # "dann eben nicht pruefen". _read_yaml wirft in diesem Fall.
    _assert_operator_precedence(
        matcher, _deny_list_terms(recognizers_path), stopwords_path, recognizers_path
    )

    return AllowList(tuple(patterns), regex_flags, stopwords_path)
