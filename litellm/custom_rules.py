"""Datenschleuse — eigene Deny-Listen und Regex-Muster (DATENSCHLE-7).

Wozu
----
Die automatische Erkennung findet nie alles. Kundennamen, Projektnamen,
interne Kuerzel, Produktbezeichnungen und Mandantennamen kennt weder das
Sprachmodell noch ein generisches Regex -- sie sind pro Installation
verschieden. Dieses Modul laesst den Anwender solche Begriffe und Muster
SELBST hinterlegen: deterministisch, sofort wirksam, jede Regel testbar.

Ausdruecklich KEIN ML-Finetuning. Es wird nichts trainiert und nichts
gelernt; es wird konfiguriert. Siehe docs/adr/0001-eigene-muster-deny-list.md.

Architektur-Entscheidungen (Kurzfassung, Begruendung im ADR)
------------------------------------------------------------
1. EIGENE Regeldatei statt Erweiterung von presidio/recognizers-config.yml.
   Ein kaputtes Muster in der Presidio-Registry reisst beim Analyzer-Boot die
   GANZE Pipeline mit (der Worker startet nicht mehr) und jede Aenderung dort
   braucht einen Container-Neustart. Beides ist hier ausgeschlossen: Regeln
   werden pro Regel isoliert geladen und die Datei wird im laufenden Betrieb
   per mtime-Pruefung neu eingelesen (Hot-Reload, kein Rebuild, kein Neustart).

2. Treffer werden im Presidio-``/analyze``-Antwortformat geliefert
   (``entity_type``/``start``/``end``/``score``). Dadurch laufen eigene
   Begriffe durch EXAKT denselben Masker und dasselbe reid_map wie jede
   andere Entitaet -- ein zweites Mapping waere eine zweite Fehlerquelle.

3. Jede Regel traegt ihren eigenen Testfall (``examples``) in der Datei. Beim
   Laden wird jede Regel gegen ihr Beispiel selbst verifiziert. Faellt sie
   durch, wird sie NICHT aktiv, sondern sichtbar in Quarantaene gestellt.
   Damit ist "kein ungetestetes Muster in der Pipeline" strukturell erzwungen
   statt nur prozessual gefordert (ISC-24).

4. Fehler-Isolation als Anti-Kriterium (ISC-26): ein fehlerhaftes Muster darf
   ausschliesslich sich selbst lahmlegen. Deshalb wird jede Regel einzeln
   kompiliert, einzeln selbstverifiziert und einzeln ausgefuehrt -- inklusive
   Timeout gegen katastrophales Backtracking (ReDoS).

Datenschutz (ISC-36)
--------------------
Gespeichert werden ausschliesslich die vom Anwender EINGEGEBENEN Muster und
Begriffe -- also Konfiguration. Es werden KEINE Trefferdaten persistiert:
keine Zaehler, keine Beispieltexte aus echten Anfragen, keine Logs mit
Klartext. ``find()`` schreibt nichts auf die Platte. Fehlermeldungen nennen
nur den Regelnamen und eine Fehlerkategorie, nie den Regelwert (der ein
echter Kundenname sein kann) -- siehe ``_safe_reason``.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import yaml

# `regex` statt der stdlib `re`: Presidio nutzt intern dasselbe Modul, und --
# entscheidend fuer ISC-26 -- es unterstuetzt einen ``timeout``-Parameter beim
# Matchen. Ohne den koennte ein einziges Muster mit exponentiellem
# Backtracking (ReDoS) einen Request unbegrenzt anhalten; mit ihm laeuft
# genau diese eine Regel in ein Timeout und alle anderen liefern weiter.
import regex


# Ablageort der Regeldatei. Liegt bewusst in einem eigenen, gemounteten
# Verzeichnis (docker-compose.yml: ./rules -> /app/rules), damit Aenderungen
# den Container ueberleben.
DEFAULT_RULES_PATH = "/app/rules/custom-rules.yml"

# Zeitbudget pro Regel und pro Text. Grosszuegig fuer jedes vernuenftige
# Muster, hart genug, dass ein pathologisches den Request nicht anhaelt.
DEFAULT_MATCH_TIMEOUT = 0.25

# Praefix aller selbst definierten Entitaetstypen. Verhindert Kollisionen mit
# bestehenden und kuenftigen Presidio-Typen und macht im maskierten Text
# sofort sichtbar, dass hier eine eigene Regel gegriffen hat
# (``<CUSTOM_KUNDENNAME_0>``).
ENTITY_PREFIX = "CUSTOM_"

RULE_TYPES = ("term", "regex")

DEFAULT_SCORES = {"term": 0.9, "regex": 0.85}

# Regelnamen sind Bezeichner, keine Freitexte -- sie tauchen in Meldungen und
# in der CLI auf und muessen dort unmissverstaendlich und harmlos sein.
_NAME_PATTERN = regex.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Globale Flags fuer Anwender-Regexe. DOTALL/MULTILINE wie in der
# Presidio-Registry (recognizers-config.yml: global_regex_flags 26); IGNORECASE
# wird NICHT global gesetzt, sondern pro Regel ueber ``case_sensitive``.
_BASE_FLAGS = regex.DOTALL | regex.MULTILINE


class RuleError(ValueError):
    """Eine Regel ist ungueltig oder hat ihren eigenen Testfall nicht bestanden.

    Wird von den schreibenden Operationen (``add_rule``) geworfen, damit eine
    durchgefallene Regel gar nicht erst in die Datei gelangt.
    """


@dataclass
class Rule:
    """Eine geladene, kompilierte und selbst-verifizierte Regel."""

    name: str
    entity: str
    kind: str
    value: str
    score: float
    case_sensitive: bool
    examples: List[str]
    counter_examples: List[str]
    pattern: Any = field(repr=False, default=None)

    @property
    def entity_type(self) -> str:
        return entity_type_for(self.entity)

    def as_dict(self) -> Dict[str, Any]:
        """Anzeige-Form fuer die CLI (ISC-25)."""
        return {
            "name": self.name,
            "entity": self.entity,
            "entity_type": self.entity_type,
            "type": self.kind,
            "value": self.value,
            "score": self.score,
            "case_sensitive": self.case_sensitive,
            "examples": list(self.examples),
            "counter_examples": list(self.counter_examples),
        }


@dataclass
class QuarantinedRule:
    """Eine Regel, die NICHT aktiv ist -- mit dem Grund dafuer.

    Wichtig fuers Vertrauen: eine durchgefallene Regel darf nicht still
    verschwinden, sonst haelt der Anwender sich faelschlich fuer geschuetzt.
    """

    name: str
    reason: str

    def as_dict(self) -> Dict[str, str]:
        return {"name": self.name, "reason": self.reason}


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
def default_rules_path() -> str:
    return os.getenv("DATENSCHLEUSE_CUSTOM_RULES_PATH") or DEFAULT_RULES_PATH


def entity_type_for(entity: str) -> str:
    """Macht aus einer Anwender-Eingabe einen stabilen Entitaetstyp.

    ``"Kundenname"`` -> ``"CUSTOM_KUNDENNAME"``. Der Typ landet woertlich im
    Platzhalter, muss also aus einem engen, vorhersagbaren Zeichenvorrat
    bestehen -- sonst bricht die Platzhalter-Erkennung im Streaming.
    """
    roh = (entity or "").strip().upper()
    sauber = regex.sub(r"[^A-Z0-9]+", "_", roh).strip("_")
    if not sauber:
        raise RuleError("entity ist leer oder enthaelt keine verwertbaren Zeichen")
    return f"{ENTITY_PREFIX}{sauber}"


def _safe_reason(name: str, kategorie: str, detail: str = "",
                 geheim: Optional[List[str]] = None) -> str:
    """Baut eine Meldung, die garantiert keinen Regelwert enthaelt.

    Fehlermeldungen laufen in Logs (Gesetz 5). Ein Regelwert kann ein echter
    Kundenname sein -- er darf dort nie auftauchen. Deshalb: nur Regelname und
    Kategorie, plus ein technisches Detail, aus dem jeder bekannte Geheimtext
    vorsorglich entfernt wird.
    """
    text = f"Regel {name!r}: {kategorie}"
    if detail:
        for wert in geheim or []:
            if wert and wert in detail:
                detail = detail.replace(wert, "[…]")
        text = f"{text} ({detail})"
    return text


def _term_to_pattern(value: str) -> str:
    """Macht aus einem Begriff ein woertliches Muster mit Wortgrenzen.

    Woertlich, weil ein Begriff ein Begriff ist: ein Punkt in ``a.b`` ist ein
    Punkt, kein "beliebiges Zeichen". Wortgrenzen, damit ``Adler`` nicht die
    halbe ``Adlerflug`` maskiert und Text-Truemmer hinterlaesst, die das
    Modell verwirren. Die Grenze wird nur dort gesetzt, wo der Rand des
    Begriffs ueberhaupt ein Wortzeichen ist -- sonst wuerde ``\\b`` bei einem
    Begriff wie ``(intern)`` genau falsch herum greifen.
    """
    kern = regex.escape(value)
    links = r"\b" if value[:1].isalnum() or value[:1] == "_" else ""
    rechts = r"\b" if value[-1:].isalnum() or value[-1:] == "_" else ""
    return f"{links}{kern}{rechts}"


def _as_str_list(raw: Any, feld: str) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raise RuleError(f"{feld} muss eine Liste sein, kein einzelner String")
    if not isinstance(raw, list):
        raise RuleError(f"{feld} muss eine Liste von Texten sein")
    for eintrag in raw:
        if not isinstance(eintrag, str):
            raise RuleError(f"{feld} enthaelt einen Eintrag, der kein Text ist")
    return list(raw)


# ---------------------------------------------------------------------------
# Regel bauen, kompilieren und gegen den eigenen Testfall verifizieren
# ---------------------------------------------------------------------------
def build_rule(raw: Any, match_timeout: float = DEFAULT_MATCH_TIMEOUT) -> Rule:
    """Validiert, kompiliert und SELBST-VERIFIZIERT eine Regel.

    Wirft ``RuleError``, wenn irgendetwas nicht stimmt -- insbesondere, wenn
    die Regel ihren eigenen Testfall nicht besteht. Das ist die eine Stelle,
    an der ISC-24 durchgesetzt wird: es gibt keinen Weg, ein Rule-Objekt zu
    bekommen, ohne dass sein Testfall gruen gelaufen ist.
    """
    if not isinstance(raw, dict):
        raise RuleError("Regel ist kein Objekt (erwartet wird ein YAML-Mapping)")

    name = raw.get("name")
    if not isinstance(name, str) or not _NAME_PATTERN.match(name):
        raise RuleError(
            "name fehlt oder ist ungueltig (erlaubt: Kleinbuchstaben, Ziffern, "
            "'-' und '_', max. 64 Zeichen)"
        )

    entity = raw.get("entity")
    if not isinstance(entity, str) or not entity.strip():
        raise RuleError("entity fehlt (z.B. 'Kundenname', 'Projektname')")
    entity_type_for(entity)  # validiert frueh, wirft bei unbrauchbarem Wert

    kind = raw.get("type", "term")
    if kind not in RULE_TYPES:
        raise RuleError(
            f"type ist unbekannt -- erlaubt sind: {', '.join(RULE_TYPES)}"
        )

    value = raw.get("value")
    if not isinstance(value, str) or not value.strip():
        raise RuleError("value fehlt (der Begriff bzw. das Regex-Muster)")

    case_sensitive = bool(raw.get("case_sensitive", False))

    score_raw = raw.get("score", DEFAULT_SCORES[kind])
    try:
        score = float(score_raw)
    except (TypeError, ValueError):
        raise RuleError("score ist keine Zahl")
    if not 0.0 < score <= 1.0:
        raise RuleError("score muss groesser als 0 und hoechstens 1.0 sein")

    examples = _as_str_list(raw.get("examples"), "examples")
    counter_examples = _as_str_list(raw.get("counter_examples"), "counter_examples")

    # --- ISC-24: ohne Testfall keine Regel ---------------------------------
    if not examples:
        raise RuleError(
            "examples fehlt -- jede Regel braucht mindestens einen Beispieltext, "
            "in dem sie greifen MUSS. Ohne Testfall geht kein Muster live."
        )

    # --- Kompilieren --------------------------------------------------------
    muster = _term_to_pattern(value) if kind == "term" else value
    flags = _BASE_FLAGS if case_sensitive else _BASE_FLAGS | regex.IGNORECASE
    try:
        pattern = regex.compile(muster, flags)
    except Exception as exc:
        # str(exc) des regex-Moduls enthaelt nur Meldung + Position, nicht das
        # Muster selbst (verifiziert) -- trotzdem defensiv durchgereicht.
        raise RuleError(f"Muster laesst sich nicht uebersetzen: {exc}") from exc

    rule = Rule(
        name=name, entity=entity.strip(), kind=kind, value=value, score=score,
        case_sensitive=case_sensitive, examples=examples,
        counter_examples=counter_examples, pattern=pattern,
    )

    # --- Selbstverifikation: der Testfall MUSS gruen sein -------------------
    for beispiel in examples:
        if not _search(rule, beispiel, match_timeout):
            raise RuleError(
                "der eigene Testfall ist rot -- das Muster greift im "
                "hinterlegten Beispiel nicht. Muster oder Beispiel korrigieren."
            )
    for gegen in counter_examples:
        if _search(rule, gegen, match_timeout):
            raise RuleError(
                "ein Gegenbeispiel wird faelschlich getroffen -- das Muster "
                "ist zu weit gefasst."
            )
    return rule


def _search(rule: Rule, text: str, timeout: float) -> bool:
    """Ein einzelner Treffer-Check mit Zeitbudget (nur fuer die Verifikation)."""
    try:
        return rule.pattern.search(text, timeout=timeout) is not None
    except TimeoutError:
        return False


# ---------------------------------------------------------------------------
# Der Regelsatz: laden, hot-reloaden, anwenden
# ---------------------------------------------------------------------------
class RuleSet:
    """Haelt die aktiven Regeln und liefert Treffer im Presidio-Format.

    Der Regelsatz liest seine Datei bei jedem Zugriff neu ein, WENN sie sich
    geaendert hat (mtime + Groesse). Dadurch wirkt ein neu hinterlegtes Muster
    sofort -- ohne Rebuild und ohne Container-Neustart (ISC-23/ISC-27).
    """

    def __init__(self, path: Optional[str] = None,
                 match_timeout: float = DEFAULT_MATCH_TIMEOUT) -> None:
        self.path = path or default_rules_path()
        self.match_timeout = float(match_timeout)
        self._active: List[Rule] = []
        self._quarantined: List[QuarantinedRule] = []
        self._stat_key: Optional[Tuple[int, int]] = None
        self._seen_file = False
        self.load_error: Optional[str] = None
        self._reload_if_changed()

    # -- Zustand ------------------------------------------------------------
    @property
    def active_rules(self) -> List[Rule]:
        self._reload_if_changed()
        return list(self._active)

    @property
    def quarantined(self) -> List[QuarantinedRule]:
        self._reload_if_changed()
        return list(self._quarantined)

    def describe(self) -> Dict[str, Any]:
        """Vollbild fuer die CLI (ISC-25): was ist aktiv, was ist warum nicht."""
        self._reload_if_changed()
        return {
            "path": self.path,
            "exists": os.path.exists(self.path),
            "load_error": self.load_error,
            "active": [r.as_dict() for r in self._active],
            "quarantined": [q.as_dict() for q in self._quarantined],
        }

    # -- Laden --------------------------------------------------------------
    def _reload_if_changed(self) -> None:
        try:
            st = os.stat(self.path)
            key = (st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            if self._seen_file:
                # Die Datei ist WEG, obwohl sie schon mal da war (geloeschter
                # Mount o.ae.). Den letzten guten Stand behalten -- der Schutz
                # darf nicht durch ein verschwundenes Volume ausfallen.
                self.load_error = (
                    f"Regeldatei {self.path} ist nicht mehr lesbar -- der "
                    f"zuletzt gueltige Regelsatz bleibt aktiv."
                )
            else:
                # Nie dagewesen: das Feature wird schlicht nicht genutzt.
                self._active, self._quarantined = [], []
                self.load_error = None
            return
        except OSError as exc:
            self.load_error = f"Regeldatei {self.path} nicht lesbar: {exc}"
            return

        if key == self._stat_key:
            return
        self._stat_key = key
        self._seen_file = True
        self._load(key)

    def _load(self, key: Tuple[int, int]) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:
            # Kaputte Datei: den letzten guten Stand BEHALTEN. Ein Tippfehler
            # beim Handeditieren darf nicht den laufenden Schutz abschalten.
            # Sichtbar wird der Fehler ueber load_error und die CLI.
            self.load_error = (
                f"Regeldatei {self.path} ist nicht lesbar/kein gueltiges YAML "
                f"({type(exc).__name__}) -- der zuletzt gueltige Regelsatz "
                f"bleibt aktiv."
            )
            return

        aktiv: List[Rule] = []
        quarantaene: List[QuarantinedRule] = []

        if doc is None:
            roh_regeln: Any = []
        elif isinstance(doc, dict):
            roh_regeln = doc.get("rules", [])
        elif isinstance(doc, list):
            roh_regeln = doc  # tolerant: nackte Liste ohne 'rules:'-Schluessel
        else:
            roh_regeln = None

        if not isinstance(roh_regeln, list):
            self.load_error = (
                f"Regeldatei {self.path}: erwartet wird eine Liste unter "
                f"'rules:' -- der zuletzt gueltige Regelsatz bleibt aktiv."
            )
            return

        gesehen: Dict[str, int] = {}
        for index, roh in enumerate(roh_regeln):
            name = roh.get("name") if isinstance(roh, dict) else None
            anzeige = name if isinstance(name, str) and name else f"#{index + 1}"
            geheim = _secrets_of(roh)

            if isinstance(name, str) and name in gesehen:
                quarantaene.append(QuarantinedRule(
                    anzeige, _safe_reason(anzeige, "doppelter Regelname -- "
                                          "nur das erste Vorkommen ist aktiv")))
                continue

            # Deaktivierte Regeln: bewusst ausgeschaltet, kein Fehler.
            if isinstance(roh, dict) and roh.get("enabled") is False:
                gesehen[anzeige] = index
                continue

            try:
                regel = build_rule(roh, self.match_timeout)
            except RuleError as exc:
                # ISC-26: diese eine Regel faellt aus, alle anderen laufen.
                quarantaene.append(QuarantinedRule(
                    anzeige, _safe_reason(anzeige, str(exc), geheim=geheim)))
                continue
            except Exception as exc:  # pragma: no cover - defensiv
                quarantaene.append(QuarantinedRule(
                    anzeige, _safe_reason(anzeige, "unerwarteter Fehler beim "
                                          "Laden", type(exc).__name__, geheim)))
                continue

            gesehen[regel.name] = index
            aktiv.append(regel)

        self._active = aktiv
        self._quarantined = quarantaene
        self.load_error = None

    # -- Anwenden -----------------------------------------------------------
    def find(self, text: str) -> List[Dict[str, Any]]:
        """Sucht alle Treffer und liefert sie im Presidio-``/analyze``-Format.

        Schreibt NICHTS auf die Platte und merkt sich keinen Treffer (ISC-36).
        Jede Regel laeuft in ihrem eigenen ``try`` mit eigenem Zeitbudget:
        eine Regel, die scheitert oder in ein Timeout laeuft, kostet
        ausschliesslich ihre eigene Entitaet (ISC-26).
        """
        self._reload_if_changed()
        if not text or not self._active:
            return []

        treffer: List[Dict[str, Any]] = []
        for regel in self._active:
            try:
                for m in regel.pattern.finditer(text, timeout=self.match_timeout):
                    start, end = m.span()
                    if end > start:
                        treffer.append({
                            "entity_type": regel.entity_type,
                            "start": start,
                            "end": end,
                            "score": regel.score,
                            "analysis_explanation": None,
                            "recognition_metadata": {
                                "recognizer_name": f"DatenschleuseCustomRule:{regel.name}",
                            },
                        })
            except TimeoutError:
                # Pathologisches Muster (ReDoS). Nur diese Regel faellt fuer
                # diesen Text aus -- kein Wert wird geloggt (ISC-36).
                print(
                    f"[datenschleuse] Regel {regel.name!r} ueberschritt ihr "
                    f"Zeitbudget und wurde fuer diesen Text uebersprungen; "
                    f"alle anderen Regeln greifen weiter.",
                    flush=True,
                )
            except Exception as exc:  # pragma: no cover - defensiv
                print(
                    f"[datenschleuse] Regel {regel.name!r} fehlgeschlagen "
                    f"({type(exc).__name__}); alle anderen Regeln greifen weiter.",
                    flush=True,
                )
        return treffer


def _secrets_of(roh: Any) -> List[str]:
    """Die Textteile einer Roh-Regel, die niemals in eine Meldung gehoeren."""
    if not isinstance(roh, dict):
        return []
    geheim: List[str] = []
    wert = roh.get("value")
    if isinstance(wert, str):
        geheim.append(wert)
    for feld in ("examples", "counter_examples"):
        eintraege = roh.get(feld)
        if isinstance(eintraege, list):
            geheim.extend(e for e in eintraege if isinstance(e, str))
    return geheim


# ---------------------------------------------------------------------------
# Schreibende Operationen (von der CLI genutzt)
# ---------------------------------------------------------------------------
def load_document(path: str) -> Dict[str, Any]:
    """Liest die Regeldatei als rohes Dokument. Fehlt sie, ist sie leer."""
    if not os.path.exists(path):
        return {"rules": []}
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if doc is None:
        return {"rules": []}
    if isinstance(doc, list):
        return {"rules": doc}
    if not isinstance(doc, dict):
        raise RuleError(f"{path}: unerwartete Struktur (erwartet: 'rules:'-Liste)")
    doc.setdefault("rules", [])
    if not isinstance(doc["rules"], list):
        raise RuleError(f"{path}: 'rules' ist keine Liste")
    return doc


def save_document(path: str, doc: Dict[str, Any]) -> None:
    """Schreibt die Regeldatei atomar und nur fuer den Eigentuemer lesbar.

    Atomar (Temp-Datei + ``os.replace``), damit ein laufender Proxy nie eine
    halb geschriebene Datei einliest. Modus 0600, weil in der Datei echte
    Kundennamen stehen koennen -- sie ist schuetzenswert und gehoert nicht
    ins Repository (siehe .gitignore).
    """
    ordner = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(ordner, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=ordner, prefix=".custom-rules-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(RULES_FILE_HEADER)
            yaml.safe_dump(doc, fh, allow_unicode=True, sort_keys=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


RULES_FILE_HEADER = """# Datenschleuse — eigene Begriffe und Muster (DATENSCHLE-7)
#
# Gepflegt ueber:  ./tools/datenschleuse-rules add|list|test|remove
# Aenderungen wirken SOFORT -- kein Rebuild, kein Container-Neustart.
#
# Jede Regel MUSS mindestens ein 'examples'-Beispiel haben, in dem sie greift.
# Regeln, deren eigener Testfall rot ist, werden NICHT aktiv (sichtbar ueber
# `datenschleuse-rules list`).
#
# ACHTUNG: Diese Datei kann echte Kundennamen enthalten. Sie ist per
# .gitignore vom Repository ausgeschlossen und sollte wie ein Secret
# behandelt werden.
"""


def add_rule(path: str, raw: Dict[str, Any],
             match_timeout: float = DEFAULT_MATCH_TIMEOUT) -> Rule:
    """Verifiziert eine Regel und schreibt sie NUR bei gruenem Testfall weg.

    Das ist die zweite Haelfte von ISC-24: eine durchgefallene Regel landet
    gar nicht erst in der Datei -- sie kann also nie jemanden in falscher
    Sicherheit wiegen.
    """
    doc = load_document(path)
    name = raw.get("name")
    if any(isinstance(r, dict) and r.get("name") == name for r in doc["rules"]):
        raise RuleError(f"Es gibt bereits eine Regel namens {name!r}.")

    regel = build_rule(raw, match_timeout)  # wirft, wenn der Testfall rot ist

    eintrag = {k: v for k, v in raw.items() if v not in (None, [], {})}
    doc["rules"].append(eintrag)
    save_document(path, doc)
    return regel


def remove_rule(path: str, name: str) -> None:
    doc = load_document(path)
    rest = [r for r in doc["rules"]
            if not (isinstance(r, dict) and r.get("name") == name)]
    if len(rest) == len(doc["rules"]):
        raise RuleError(f"Keine Regel namens {name!r} gefunden.")
    doc["rules"] = rest
    save_document(path, doc)
