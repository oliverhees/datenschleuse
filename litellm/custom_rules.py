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
import sys
import tempfile
import time
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

# Ein Kategoriename ist ein Wort, kein Satz. Die Grenze ist bewusst eng: der
# Name landet WOERTLICH im Platzhalter und geht damit an den LLM-Anbieter
# (Security-Finding F7). Wer hier einen ganzen Satz eintraegt, verwechselt
# Kategorie mit Inhalt.
MAX_ENTITY_LENGTH = 40
MAX_ENTITY_WORDS = 3

# Tokens ab dieser Laenge werden beim Leak-Abgleich Kategorie-gegen-Wert
# beruecksichtigt. Kuerzere sind zu generisch, um etwas zu verraten.
MIN_LEAK_TOKEN_LENGTH = 3

# Mindest-Zeitbudget pro Regel. Security-Finding F8: eine reine Aufteilung
# nach ANZAHL (rest/offen) gab der ersten von 30 Regeln nur 1/31 des Budgets,
# obwohl die uebrigen 30 fast nichts brauchten -- eine harmlose term-Regel
# lief bei vielen Treffern ins Timeout, waehrend 96 % des Budgets ungenutzt
# blieben. Der Mindestanteil verteilt nach BEDARF statt nach Kopfzahl:
# gesunde Regeln verbrauchen Mikrosekunden und geben ihren Rest weiter.
MIN_RULE_BUDGET = 0.05

DEFAULT_SCORES = {"term": 0.9, "regex": 0.85}

# Regelnamen sind Bezeichner, keine Freitexte -- sie tauchen in Meldungen und
# in der CLI auf und muessen dort unmissverstaendlich und harmlos sein.
_NAME_PATTERN = regex.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Globale Flags fuer Anwender-Regexe. DOTALL/MULTILINE wie in der
# Presidio-Registry (recognizers-config.yml: global_regex_flags 26); IGNORECASE
# wird NICHT global gesetzt, sondern pro Regel ueber ``case_sensitive``.
_BASE_FLAGS = regex.DOTALL | regex.MULTILINE


class RuleMatchingIncomplete(Exception):
    """Die Regelpruefung konnte fuer diesen Text NICHT vollstaendig laufen.

    Security-Finding F8 (HIGH): Frueher behielt ``find()`` bei einem Timeout
    die bereits gesammelten Treffer und lieferte sie als vollstaendiges
    Ergebnis aus. Der Text sah dadurch korrekt maskiert aus, waehrend ein Teil
    der Vorkommen im KLARTEXT zum Anbieter ging -- gemessen 1187 von 2000
    maskiert, der Rest offen. Genau diese stille Teil-Maskierung ist
    gefaehrlicher als ein sichtbarer Block: niemand sucht nach einem Fehler,
    den er nicht sieht.

    Deshalb gibt es fuer ein unvollstaendiges Ergebnis keinen Rueckgabewert
    mehr, sondern diese Ausnahme. Der Guardrail uebersetzt sie in einen
    fail-closed Block -- dieselbe Regel wie bei nicht erreichbarem Presidio.

    Abgrenzung zu ISC-26: Jenes Kriterium schuetzt vor FEHLERHAFTEN MUSTERN,
    und die werden weiterhin beim LADEN erkannt und einzeln in Quarantaene
    gestellt, ohne die Pipeline zu beruehren. Hier geht es um etwas anderes:
    um ein Ergebnis, dessen VOLLSTAENDIGKEIT unbekannt ist. Unbekannte
    Abdeckung als vollstaendig auszuliefern waere ein Datenleck, kein
    Verfuegbarkeitsgewinn.
    """


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


def _tokens(text: str) -> set:
    """Zerlegt Text in kleingeschriebene Wort-Tokens ab MIN_LEAK_TOKEN_LENGTH."""
    roh = regex.findall(r"[^\W_]+", text or "", flags=regex.UNICODE)
    return {t.lower() for t in roh if len(t) >= MIN_LEAK_TOKEN_LENGTH}


def check_entity_does_not_leak(entity: str, value: str) -> None:
    """Stellt sicher, dass der Kategoriename nicht selbst das Geheimnis ist.

    Security-Finding F7: Der Entitaetsname steht woertlich im Platzhalter
    (``<CUSTOM_NORDWIND_LOGISTIK_GMBH_0>``) und geht damit an den
    LLM-Anbieter. Wer seine Kategorie nach dem Kunden benennt -- die
    naheliegendste Sache der Welt -- maskiert den WERT und verschickt den
    NAMEN trotzdem. Der eigene Schutz waere aufgehoben, ohne dass es jemand
    bemerkt.

    Erkennbar ist der Fall daran, dass Kategorie und Wert sich ein Wort
    teilen: jedes Wort des Werts ist per Definition Teil des Geheimnisses.
    Wirft ``RuleError`` -- OHNE den Wert zu zitieren (Gesetz 5).
    """
    sauber = (entity or "").strip()
    if len(sauber) > MAX_ENTITY_LENGTH:
        raise RuleError(
            f"entity ist zu lang (max. {MAX_ENTITY_LENGTH} Zeichen). Der "
            f"Kategoriename steht im Platzhalter und geht an den "
            f"LLM-Anbieter -- gemeint ist eine Kategorie wie 'Kundenname', "
            f"nicht der Inhalt selbst."
        )
    if len(sauber.split()) > MAX_ENTITY_WORDS:
        raise RuleError(
            f"entity besteht aus zu vielen Woertern (max. "
            f"{MAX_ENTITY_WORDS}). Gemeint ist eine Kategorie wie "
            f"'Kundenname' oder 'Projektnummer', kein Satz."
        )
    geteilt = _tokens(sauber) & _tokens(value)
    if geteilt:
        raise RuleError(
            "entity und value teilen sich ein Wort -- der Kategoriename "
            "waere damit selbst ein Teil des Geheimnisses. Der Name landet "
            "WOERTLICH im Platzhalter und geht an den LLM-Anbieter; der Wert "
            "waere maskiert, der Name nicht. Bitte die KATEGORIE benennen "
            "(z.B. 'Kundenname', 'Projektname'), nicht den Kunden."
        )


def permission_warning(path: str) -> Optional[str]:
    """Warnt, wenn die Regeldatei fuer andere Benutzer lesbar ist.

    Security-Finding F6: save_document schreibt 0600, aber der dokumentierte
    Setup-Weg per ``cp`` erzeugt die Rechte der Umask (typisch 0664). Die
    Datei enthaelt echte Kundennamen -- genau die Daten, die die Datenschleuse
    schuetzen soll. Ohne Hinweis merkt das niemand.

    Gibt ``None`` zurueck, wenn alles in Ordnung ist (oder die Datei fehlt).
    """
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return None
    if mode & 0o077:
        return (
            f"Regeldatei ist fuer andere Benutzer lesbar (Rechte {mode:03o}). "
            f"Sie enthaelt echte Kundennamen und sollte wie ein Secret "
            f"behandelt werden. Beheben mit: chmod 600 {path}"
        )
    return None


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

    # Der Kategoriename geht im Platzhalter an den Anbieter -- er darf das
    # Geheimnis nicht selbst enthalten (Security-Finding F7).
    check_entity_does_not_leak(entity, value)

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
        # Gab es in DIESEM Prozess je einen erfolgreich geladenen Regelsatz?
        # Unterscheidet den Kaltstart (Container-Neustart mit kaputter Datei:
        # es ist NICHTS aktiv) vom Warmlauf (die Datei geht kaputt, waehrend
        # ein guter Satz im Speicher steht). Die beiden Faelle brauchen
        # verschiedene Meldungen -- siehe Security-Finding F3.
        self._has_good_ruleset = False
        # Zuletzt GEMELDETER Fehler, damit die Warnung laut ist, aber nicht
        # bei jedem Request erneut ins Log laeuft.
        self._reported: Optional[str] = None
        self.load_error: Optional[str] = None
        self._reload_if_changed()

    # -- Melden -------------------------------------------------------------
    def _report(self, text: str, level: str = "FEHLER") -> None:
        """Schreibt eine Betriebsmeldung nach stderr (Container-Log).

        stderr statt stdout, weil das hier Stoerungsmeldungen sind und nicht
        Programmausgabe -- und weil ein stiller Ausfall der Maskierungsschicht
        genau der Defekt war, den Security-Finding F3 beschrieben hat.

        Der Schreibvorgang ist gekapselt: ist der Log-Kanal weg (Collector
        beendet, Pipe geschlossen -> BrokenPipeError), darf das nicht in den
        Maskierungspfad zurueckschlagen. Eine Meldung zu verlieren ist
        aergerlich; einen Regelsatz dauerhaft nicht mehr zu laden oder einen
        Request an einer kaputten Pipe scheitern zu lassen, ist schlimmer.
        """
        try:
            print(f"[datenschleuse] {level}: {text}", file=sys.stderr,
                  flush=True)
        except Exception:
            pass

    def _set_load_error(self, text: str) -> None:
        """Setzt den Fehler und meldet ihn EINMAL pro Auftreten."""
        if text != self._reported:
            self._report(text)
            self._reported = text
        self.load_error = text

    def _clear_load_error(self) -> None:
        """Erfolgreich geladen: Fehler loeschen und Erholung melden."""
        if self._reported is not None:
            self._report(
                "Regeldatei ist wieder lesbar -- die eigenen Regeln sind "
                "wieder aktiv.", level="OK",
            )
            self._reported = None
        self.load_error = None

    def _fehlermeldung(self, ursache: str) -> str:
        """Baut die Meldung, die zum tatsaechlichen Zustand PASST.

        Der Unterschied ist nicht kosmetisch: Beim Kaltstart gibt es keinen
        alten Regelsatz, auf den man zurueckfallen koennte -- dann ist die
        eigene Maskierungsschicht schlicht AUS, und die Meldung muss das
        sagen, statt Sicherheit zu suggerieren.
        """
        if self._has_good_ruleset:
            return (
                f"Regeldatei {self.path}: {ursache} -- der zuletzt gueltige "
                f"Regelsatz bleibt aktiv."
            )
        return (
            f"Regeldatei {self.path}: {ursache} -- es sind KEINE eigenen "
            f"Regeln aktiv. Die eigene Maskierungsschicht ist ausgefallen; "
            f"eigene Begriffe werden NICHT maskiert. Die Presidio-Erkennung "
            f"laeuft unveraendert weiter. Pruefen mit: datenschleuse-rules list"
        )

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
            "permission_warning": permission_warning(self.path),
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
                # Mount o.ae.). Steht ein guter Satz im Speicher, bleibt er
                # aktiv -- sonst ist die Schicht aus, und das wird gesagt.
                self._set_load_error(self._fehlermeldung("Datei verschwunden"))
            else:
                # Nie dagewesen: das Feature wird schlicht nicht genutzt.
                # Das ist kein Fehler und wird deshalb auch nicht gemeldet.
                self._active, self._quarantined = [], []
                self.load_error = None
            return
        except OSError as exc:
            self._set_load_error(self._fehlermeldung(
                f"nicht lesbar ({type(exc).__name__})"))
            return

        if key == self._stat_key:
            return
        self._seen_file = True
        self._load(key)
        # Security-Finding (Re-Audit, LOW): ERST nach erfolgreichem Laden
        # vorruecken. Stand die Zuweisung davor, blieb der Regelsatz nach
        # einer entkommenen Ausnahme in _load DAUERHAFT stehen -- der
        # naechste Aufruf sah key == _stat_key und lud nie wieder. Ein
        # stiller, permanenter Ausfall der Hot-Reload-Zusage, ausgeloest
        # schon von einem BrokenPipeError beim Loggen.
        self._stat_key = key

    def _load(self, key: Tuple[int, int]) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:
            # Kaputte Datei. Steht ein guter Satz im Speicher, bleibt er aktiv
            # (ein Tippfehler beim Handeditieren soll den laufenden Schutz
            # nicht abschalten). Beim KALTSTART gibt es keinen solchen Satz --
            # dann ist die Schicht aus, und genau das wird laut gemeldet.
            # Der Grund traegt nur den Ausnahme-TYP, nie Dateiinhalt (Gesetz 5):
            # die YAML-Fehlermeldung zitiert die fehlerhafte Zeile woertlich.
            self._set_load_error(self._fehlermeldung(
                f"kein gueltiges YAML ({type(exc).__name__})"))
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
            self._set_load_error(self._fehlermeldung(
                "erwartet wird eine Liste unter 'rules:'"))
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
        self._has_good_ruleset = True
        self._clear_load_error()

        # Quarantaene ist zur Laufzeit sonst unsichtbar (Finding F4): wer die
        # Datei von Hand editiert, sieht die rote Regel nur, wenn er zufaellig
        # die CLI aufruft. Deshalb einmal pro Ladevorgang ins Container-Log --
        # nur Regelnamen, nie Werte.
        if quarantaene:
            self._report(
                f"{len(quarantaene)} eigene Regel(n) sind NICHT aktiv "
                f"(Testfall rot oder ungueltig): "
                f"{', '.join(q.name for q in quarantaene)}. "
                f"Diese Muster schuetzen nicht. Details: datenschleuse-rules list",
                level="WARNUNG",
            )

    # -- Anwenden -----------------------------------------------------------
    def find(self, text: str) -> List[Dict[str, Any]]:
        """Sucht alle Treffer und liefert sie im Presidio-``/analyze``-Format.

        Schreibt NICHTS auf die Platte und merkt sich keinen Treffer (ISC-36).
        Jede Regel laeuft in ihrem eigenen ``try`` mit eigenem Zeitbudget:
        eine Regel, die scheitert oder in ein Timeout laeuft, kostet
        ausschliesslich ihre eigene Entitaet (ISC-26).

        ZUSAGE AN DEN AUFRUFER (Security-Finding S2): Sobald der Scan
        begonnen hat, verlaesst ein Fehler diese Methode ausschliesslich als
        ``RuleMatchingIncomplete``. Der Guardrail behandelt genau diesen Typ
        fail-closed; jede andere Ausnahme liefe dort in den fail-OPEN-Pfad
        und der Request ginge mit unbekannter Abdeckung hinaus.

        Der LADEvorgang steht bewusst VOR dieser Absicherung: scheitert er,
        greifen die eigenen Regeln eben nie -- die Abdeckung ist dann bekannt
        und die Presidio-Maskierung darf davon nicht mitgerissen werden
        (ISC-26). Das ist die einzige Ausnahme, und sie ist gewollt.
        """
        self._reload_if_changed()
        if not text or not self._active:
            return []
        try:
            return self._scan(text)
        except RuleMatchingIncomplete:
            raise
        except Exception as exc:
            # Security-Finding S2: F11 haengte die fail-closed-Behandlung an
            # den ``finditer``-Aufruf. Der Aufbau der Ergebnis-Dicts wurde
            # fuer F8 aber bewusst in den ``else:``-Block verschoben -- und
            # hatte dort keinen Handler. Reisst es dort (MemoryError bei sehr
            # vielen Treffern, OSError, RuntimeError), brechen die
            # Folgeregeln ab und die Abdeckung ist genauso unbekannt wie beim
            # Timeout. Dieselbe Frage, also dieselbe Konsequenz.
            self._report(
                f"Die eigenen Regeln sind mitten im Scan fehlgeschlagen "
                f"({type(exc).__name__}). Die Vollstaendigkeit der "
                f"Maskierung ist fuer diesen Text nicht gesichert -- der "
                f"Request wird blockiert (fail-closed).",
                level="FEHLER",
            )
            raise RuleMatchingIncomplete(
                f"Die eigenen Regeln konnten fuer diesen Text nicht "
                f"vollstaendig geprueft werden ({type(exc).__name__})."
            ) from exc

    def _scan(self, text: str) -> List[Dict[str, Any]]:
        """Der eigentliche Durchlauf. Getrennt von :meth:`find`, damit dort
        EIN Sicherheitsnetz ueber dem gesamten Scan liegt (Finding S2)."""
        # Security-Finding F2: das Zeitbudget gilt fuer den GESAMTEN Aufruf,
        # nicht pro Regel. Vorher summierte es sich -- 20 pathologische Muster
        # ergaben 20 x 0,25 s = 5 s fuer EINEN Text. Und weil das synchrone
        # CPU-Arbeit ist, blockierte sie so lange den asyncio-Event-Loop und
        # damit auch fremde, parallel laufende Requests.
        frist = time.monotonic() + self.match_timeout
        treffer: List[Dict[str, Any]] = []
        offen = len(self._active)
        for regel in self._active:
            rest = frist - time.monotonic()
            if rest <= 0:
                # Auch hier kein Teilergebnis: uebersprungene Regeln bedeuten
                # ungeprueften Text, und ungeprueft ist nicht dasselbe wie
                # sauber (Finding F8).
                self._report(
                    f"Zeitbudget fuer die eigenen Regeln erschoepft, "
                    f"{offen} Regel(n) ungeprueft (Textgroesse: {len(text)} "
                    f"Zeichen). Der Request wird blockiert (fail-closed) statt "
                    f"teilweise maskiert ausgeliefert. Ursache ist entweder "
                    f"ein sehr grosser Text oder ein zu teures Muster; bei "
                    f"normal grossen Texten pruefen mit: datenschleuse-rules list",
                    level="FEHLER",
                )
                raise RuleMatchingIncomplete(
                    f"{offen} eigene Regel(n) konnten fuer diesen Text nicht "
                    f"mehr geprueft werden (sehr grosser Text oder zu teures "
                    f"Muster; Textgroesse {len(text)} Zeichen)."
                )
            # FAIRER ANTEIL statt "wer zuerst kommt, frisst alles": jede Regel
            # bekoemmt den gleichen Bruchteil des VERBLEIBENDEN Budgets. Ein
            # pathologisches Muster verbrennt so nur seinen eigenen Anteil und
            # kann die gesunden Regeln dahinter nicht aushungern -- genau das
            # passierte mit einer simplen gemeinsamen Frist. Gesunde Regeln
            # brauchen Mikrosekunden und vererben ihren Rest an die naechsten.
            # Verteilung nach BEDARF, nicht nach Kopfzahl (Finding F8): der
            # Anteil ist mindestens MIN_RULE_BUDGET, gedeckelt auf den Rest.
            # Gesunde Regeln brauchen Mikrosekunden und vererben ihren Rest;
            # eine reine 1/N-Teilung verhungerte dagegen die vorderste Regel,
            # obwohl fast das gesamte Budget ungenutzt blieb.
            anteil = min(rest, max(rest / offen, MIN_RULE_BUDGET))
            offen -= 1
            try:
                # NUR die Spans innerhalb des Zeitbudgets einsammeln. Der
                # ``timeout`` von finditer laeuft ueber die GESAMTE Iteration,
                # also zaehlte frueher auch der Aufbau der Ergebnis-Dicts im
                # Schleifenkoerper gegen das Regex-Budget (Finding F8). Genau
                # deshalb war die TREFFERZAHL der Ausloeser und nicht die
                # Textgroesse. Die Dicts entstehen jetzt ausserhalb.
                spans = [m.span() for m
                         in regel.pattern.finditer(text, timeout=anteil)]
            except TimeoutError as exc:
                # Kein Teilergebnis ausliefern. Wir wissen an dieser Stelle
                # NICHT, wie viele Vorkommen noch gekommen waeren -- die
                # bereits gefundenen als vollstaendig zu behandeln hiesse,
                # den Rest im Klartext hinauszulassen (Finding F8, HIGH).
                # Finding F12: Die Meldung nannte frueher nur das
                # pathologische Muster als Ursache. Bei sehr grossen Texten
                # reisst aber schon eine voellig harmlose Regel das Budget --
                # dann schickt so eine Meldung den Betreiber auf die Suche
                # nach einem Problem, das es nicht gibt. Beide Ursachen
                # nennen, in der Reihenfolge ihrer Wahrscheinlichkeit.
                self._report(
                    f"Regel {regel.name!r} ueberschritt ihr Zeitbudget "
                    f"(Textgroesse: {len(text)} Zeichen). Die Vollstaendigkeit "
                    f"der Maskierung ist fuer diesen Text nicht gesichert -- "
                    f"der Request wird blockiert (fail-closed) statt halb "
                    f"maskiert ausgeliefert. Ursache ist entweder ein sehr "
                    f"grosser Text oder ein zu teures Muster; bei normal "
                    f"grossen Texten pruefen mit: datenschleuse-rules list",
                    level="FEHLER",
                )
                raise RuleMatchingIncomplete(
                    f"Regel {regel.name!r} konnte fuer diesen Text nicht "
                    f"vollstaendig geprueft werden (sehr grosser Text oder zu "
                    f"teures Muster; Textgroesse {len(text)} Zeichen)."
                ) from exc
            except Exception as exc:
                # Security-Finding F11: Hier stand die fail-OPEN-Behandlung
                # derselben Frage, die drei Zeilen darueber fail-closed
                # behandelt wird. Der Kommentar behauptete, solche Fehler
                # betraefen "nicht die Vollstaendigkeit des Ergebnisses" --
                # das ist falsch. Bricht der Scan mittendrin ab, wissen wir
                # genauso wenig wie beim Timeout, wie viele Vorkommen noch
                # gekommen waeren. Die Regel still zu ueberspringen liefert
                # ein Teilergebnis aus, das von einem vollstaendigen nicht zu
                # unterscheiden ist.
                #
                # Abgrenzung zu ISC-26: Ein fehlerhaftes MUSTER wird beim
                # LADEN erkannt und einzeln in Quarantaene gestellt -- dort
                # ist die Abdeckung bekannt (die Regel greift eben nie). Ein
                # Fehler mitten im SCAN ist etwas anderes.
                self._report(
                    f"Regel {regel.name!r} ist mitten im Scan fehlgeschlagen "
                    f"({type(exc).__name__}). Die Vollstaendigkeit der "
                    f"Maskierung ist damit fuer diesen Text nicht gesichert -- "
                    f"der Request wird blockiert (fail-closed).",
                    level="FEHLER",
                )
                raise RuleMatchingIncomplete(
                    f"Regel {regel.name!r} konnte fuer diesen Text nicht "
                    f"vollstaendig geprueft werden ({type(exc).__name__})."
                ) from exc
            else:
                # Ergebnis-Dicts BEWUSST hier, ausserhalb des Zeitbudgets.
                for start, end in spans:
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
