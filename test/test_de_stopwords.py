"""Tests fuer die deutsche Nicht-PII-Wortliste (presidio/de-stopwords.yml).

Die Liste unterdrueckt gemessene spaCy-NER-Fehlzuendungen (DATENSCHLE-71:
deutsche Schema-Schluessel) ueber Presidios `allow_list`-Mechanismus.

## Warum dieser Test so gebaut ist, wie er gebaut ist

Die erste Fassung dieses Tests hat zwei High-Findings NICHT gefunden, weil sie
eine andere Engine modelliert hat als die Produktion. Der Analyzer macht in
`AnalyzerEngine._remove_allow_list` Folgendes (aus dem laufenden Container
gelesen):

    pattern     = "|".join(allow_list)          # EIN gejointer Ausdruck
    re_compiled = re.compile(pattern, flags=regex_flags)   # re IST `regex`
    if not re_compiled.search(word, ...):       # search, NICHT fullmatch

Dazu kommt: `AnalyzerRequest` defaultet `regex_flags` auf
`re.DOTALL | re.MULTILINE | re.IGNORECASE`, wenn der Aufrufer sie nicht sendet.

Daraus folgen drei Eigenschaften, die ein naiver Test uebersieht:

1. **Gejoint statt einzeln.** Ein globales Inline-Flag `(?i)` in EINER
   Alternative wirkt nach dem Join auf den GESAMTEN Ausdruck. Case-Sensitivitaet
   pro Eintrag ist so nicht erreichbar -- nur gekapselt: `(?i:...)`.
2. **`search` statt `fullmatch`.** Ein Muster muss selbst verankern.
3. **`MULTILINE` per Default.** Damit matchen `^` und `$` an JEDEM
   Zeilenumbruch INNERHALB des Spans. `^wort$` ist dann kein Vollspan-Anker,
   sondern ein Zeilen-Anker -- und ein Span wie "Zahlungsart\\nLoewenstein"
   wird komplett unterdrueckt, inklusive des echten Nachnamens.

Deshalb prueft dieser Test gegen `regex.compile("|".join(patterns), flags=<die
Flags, die der Benchmark/Guardrail tatsaechlich sendet>).search(span)` -- also
gegen dieselbe Konstruktion wie der Analyzer, nicht gegen eine idealisierte.

Ausfuehren (aus dem Repo-Root -- "test.<modul>" kollidiert mit dem
Stdlib-Paket "test", siehe DATENSCHLE-62):
    python3 -m unittest discover -s ./test -p "test_de_stopwords.py" -v
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest

import regex
import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))

# litellm/ auf den Importpfad legen: die Laufzeit-Tests unten pruefen den
# Guardrail selbst, nicht nur die Datendatei.
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402

try:  # noqa: SIM105 -- solange DATENSCHLE-82 nicht umgesetzt ist, fehlt das Modul
    import de_stopwords as ds  # noqa: E402
except ImportError:  # pragma: no cover -- nur im roten Zustand
    ds = None

_STOPWORD_PATH = os.path.normpath(
    os.path.join(_HERE, "..", "presidio", "de-stopwords.yml")
)
_RECOGNIZER_PATH = os.path.normpath(
    os.path.join(_HERE, "..", "presidio", "recognizers-config.yml")
)
_ANALYZER_URL = os.environ.get("PRESIDIO_ANALYZER_URL", "http://localhost:5001")

# Erlaubte Kopf-Morpheme fuer Schema-Schluessel-Komposita (Aufnahmekriterium 2).
#
# ACHTUNG, das ist der Punkt, an dem die Regel schon einmal falsch war: Diese
# Koepfe sind NICHT namensfrei. 'Preis' und 'Grund' sind reale deutsche
# Familiennamen. Ein frueherer Kommentar behauptete hier das Gegenteil und
# wiederholte damit exakt den Fehlertyp, gegen den die Regel eingefuehrt wurde
# (eine plausible Behauptung statt einer Kontrolle -- so kamen 'menge' und
# 'fuege' auf die Liste, beides reale Nachnamen).
#
# Der Kopf-Filter leistet deshalb nur die VERENGUNG auf Komposita. Die
# Namensfreiheit belegen die Einzelkontrollen: Kollisionspruefung gegen die
# Kontrollnamen und Messbeleg am laufenden Analyzer. Weil der bare Kopf selbst
# ein Nachname sein kann, ist er als Eintrag gesperrt -- erzwungen von
# test_kein_eintrag_ist_ein_barer_kopf.
_ERLAUBTE_KOPF_MORPHEME = (
    "nummer", "datum", "art", "status", "betrag",
    "preis", "gebuehr", "grund", "fenster",
)

# Echte Namen, die von der Liste NIEMALS unterdrueckt werden duerfen.
# Enthaelt bewusst die Layouts, an denen die erste Fassung gescheitert ist:
# mehrzeilige Label-Wert-Paare und "Nachname, Vorname".
_RECALL_KONTROLLEN = [
    ("Herr Mueller hat den Vertrag unterschrieben.", "Mueller"),
    ("Frau Schroeder ruft morgen zurueck.", "Schroeder"),
    ("Der Antrag von Herrn Weiss liegt vor.", "Weiss"),
    ("Bitte kontaktieren Sie Frau Kraemer.", "Kraemer"),
    ("Sachbearbeiter ist Herr Baecker.", "Baecker"),
    ("Die Beschwerde von Frau Aenne Stoecker ist eingegangen.", "Stoecker"),
    ("Der Gutachter Herr Dr. Ruediger Loewenstein bestaetigt das.", "Loewenstein"),
    ("Spaeter hat Maria Meier den Vorgang uebernommen.", "Maria Meier"),
    ("Herr Müller hat den Vertrag unterschrieben.", "Müller"),
    ("Frau Schröder ruft morgen zurück.", "Schröder"),
    # --- Label-Wert-Layout ueber zwei Zeilen (Formular, Tabelle, CSV) ---
    ("Zahlungsart\nLoewenstein", "Loewenstein"),
    ("Bestellnummer\nKraemer", "Kraemer"),
    ("Rechnungsbetrag\nSchroeder", "Schroeder"),
    # --- "Nachname, Vorname" (Personenlisten, HR-Export) ---
    ("Menge, Andreas", "Menge"),
    ("Fuege, Anna", "Fuege"),
]

# Spans, die die gejointe Liste NICHT treffen darf. Direkt aus den
# Security-Findings F1 und F2 abgeleitet.
_VERBOTENE_SPANS = [
    "Zahlungsart\nLoewenstein",
    "Bestellnummer\nKraemer",
    "Rechnungsbetrag\nSchroeder",
    "Menge",
    "MENGE",
    "Fuege",
    "Mueller",
    "Herr Mueller",
]


def _load_stopwords():
    with open(_STOPWORD_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _entries(doc):
    return doc.get("entries", [])


def _patterns(doc):
    return [e["pattern"] for e in _entries(doc)]


def _joined_matcher(doc):
    """Baut den Matcher EXAKT so, wie der Analyzer es tut."""
    flags = doc.get("regex_flags", 0)
    return regex.compile("|".join(_patterns(doc)), flags=flags)


def _deny_list_terme():
    """Alle Terme aus den ``deny_list``-Recognizern des Betreibers.

    Liefert [(recognizer_name, term), ...] aus presidio/recognizers-config.yml
    (heute DE_GENDER und DE_BERUF).
    """
    with open(_RECOGNIZER_PATH, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    treffer = []
    for rec in doc.get("recognizers", []) or []:
        for term in rec.get("deny_list", []) or []:
            treffer.append((rec.get("name"), term))
    return treffer


class _FakeAnalyzerResponse:
    """Minimal-Antwort des Analyzers: leere Trefferliste, HTTP 200."""

    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return []


def analyze_payload(guard, text="bestellnummer"):
    """Gibt das Payload zurueck, das ``guard`` an POST /analyze schickt.

    DATENEBENE STATT QUELLTEXT-SUBSTRING. Hier stand vorher eine Pruefung
    ``"allow_list" in open(datenschleuse_guardrail.py).read()``, die als
    Schalter fuer den Laufzeit-Test unten diente. Die Konstruktion war in
    beide Richtungen falsch:

    * **Falsch-negativ.** Wird die Uebergabe ueber ein Hilfsmodul gebaut --
      genau das Muster von ``qi_generalization.py`` und
      ``sensitivity_classifier.py`` --, taucht das Wort im Guardrail nicht
      zwingend auf. Der Laufzeit-Test waere stillschweigend uebersprungen
      geblieben, obwohl die Anforderung faellig ist. Ein Test, der sich selbst
      abschaltet, ist schlimmer als keiner: er meldet Gruen.
    * **Falsch-positiv.** Umgekehrt haette schon ein Kommentar oder ein
      Variablenname mit dem Wort den Test scharf geschaltet, ohne dass ein
      einziges Byte auf der Leitung anders aussieht.

    Diese Funktion fragt stattdessen die einzige Instanz, die es wirklich
    weiss: das tatsaechlich gebaute Request-Payload. Der Analyzer wird dafuer
    nicht gebraucht -- ``httpx.AsyncClient`` wird ersetzt und das Payload
    abgegriffen.
    """
    gesehen = {}

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, **kwargs):  # noqa: A002
            gesehen["url"] = url
            gesehen["payload"] = json
            return _FakeAnalyzerResponse()

    orig = dg.httpx.AsyncClient
    dg.httpx.AsyncClient = _FakeClient  # type: ignore[assignment]
    try:
        asyncio.run(guard._analyze(text))
    finally:
        dg.httpx.AsyncClient = orig  # type: ignore[assignment]
    return gesehen.get("payload")


def _analyzer_erreichbar():
    try:
        import requests

        return requests.get(_ANALYZER_URL + "/health", timeout=3).status_code == 200
    except Exception:
        return False


_ANALYZER_DA = _analyzer_erreichbar()


class StopwordListeStruktur(unittest.TestCase):
    """Sicherheitseigenschaften -- gegen die ECHTE Engine-Semantik."""

    @classmethod
    def setUpClass(cls):
        cls.doc = _load_stopwords()
        cls.matcher = _joined_matcher(cls.doc)

    def test_liste_nutzt_regex_matching(self):
        self.assertEqual(self.doc.get("allow_list_match"), "regex")

    def test_regex_flags_werden_explizit_gesetzt(self):
        """Der Server-Default ist DOTALL|MULTILINE|IGNORECASE. Wer ihn erbt,
        schaltet die Zeilen-Anker-Luecke (F1) und die IGNORECASE-Luecke (F2)
        scharf. Die Liste MUSS die Flags also selbst mitbringen."""
        self.assertIn(
            "regex_flags",
            self.doc,
            "de-stopwords.yml muss regex_flags explizit setzen, sonst erbt "
            "der Aufrufer den Server-Default DOTALL|MULTILINE|IGNORECASE.",
        )
        self.assertEqual(
            self.doc["regex_flags"],
            0,
            "regex_flags muss 0 sein; Case-Sensitivitaet wird pro Eintrag "
            "gekapselt über (?i:...) gesteuert.",
        )

    def test_jeder_eintrag_nutzt_absolute_anker(self):
        r"""\A und \z statt ^ und $.

        ^ und $ sind unter MULTILINE Zeilen-Anker. \A und \z verankern immer
        am String-Anfang bzw. -Ende, unabhaengig von den Flags. Das ist die
        Eigenschaft, die verhindert, dass ein mehrzeiliger Span wie
        "Zahlungsart\nLoewenstein" komplett unterdrueckt wird.
        """
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                pat = e["pattern"]
                self.assertNotIn(
                    "^", pat,
                    "Eintrag %r nutzt ^ (Zeilen-Anker unter MULTILINE). "
                    "Erwartet: \\A" % e.get("term"),
                )
                self.assertNotIn(
                    "$", pat,
                    "Eintrag %r nutzt $ (Zeilen-Anker unter MULTILINE). "
                    "Erwartet: \\z" % e.get("term"),
                )
                self.assertIn("\\A", pat, "Eintrag %r ohne \\A" % e.get("term"))
                self.assertIn("\\z", pat, "Eintrag %r ohne \\z" % e.get("term"))

    def test_case_flags_sind_gekapselt(self):
        """Ein globales (?i) wirkt nach dem Join auf ALLE Alternativen.

        Belegt: regex.compile("(?i)\\Aa\\z|\\Ab\\z", flags=0) macht auch die
        zweite Alternative case-insensitiv. Pro-Eintrag-Steuerung geht nur
        gekapselt: (?i:...).
        """
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                pat = e["pattern"]
                self.assertFalse(
                    pat.startswith("(?i)") or pat.startswith("(?-i)"),
                    "Eintrag %r nutzt ein GLOBALES Inline-Flag. Nach dem Join "
                    "wirkt das auf alle Eintraege. Erwartet: (?i:...)"
                    % e.get("term"),
                )

    def test_globales_inline_flag_ist_tatsaechlich_global(self):
        """Beleg fuer die Regel oben -- damit sie nicht als Behauptung dasteht."""
        gejoint = regex.compile("(?i)\\Aaendere\\z|\\Amenge\\z", flags=0)
        self.assertTrue(
            gejoint.search("MENGE"),
            "Erwartet: ein globales (?i) faerbt auch die zweite Alternative "
            "case-insensitiv ab.",
        )

    def test_gejointes_muster_kompiliert(self):
        """Einzeln kompilierbar heisst nicht gejoint kompilierbar."""
        self.assertIsNotNone(self.matcher)

    def test_keine_doppelten_muster(self):
        pats = _patterns(self.doc)
        self.assertEqual(len(pats), len(set(pats)))

    def test_jeder_eintrag_hat_messbeleg(self):
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                self.assertTrue(e.get("probe"))
                self.assertTrue(e.get("measured_fp"))

    def test_aufnahmekriterium_kopfmorphem(self):
        """Aufnahmekriterium 2, Teil 1: Verengung auf Schema-Schluessel-Komposita.

        Vorher war das Kriterium "keine plausible Eigennamen-Lesart" -- eine
        Einschaetzung, die 'menge' und 'fuege' durchgelassen hat, beides reale
        deutsche Nachnamen. Jetzt muss der Term auf einem erlaubten Kopf enden.

        Diese Bedingung allein belegt KEINE Namensfreiheit (siehe Kommentar an
        _ERLAUBTE_KOPF_MORPHEME); sie wirkt nur zusammen mit der
        Kollisionspruefung, dem Messbeleg und test_kein_eintrag_ist_ein_barer_kopf.
        """
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                term = e["term"]
                self.assertTrue(
                    term.endswith(_ERLAUBTE_KOPF_MORPHEME),
                    "Term %r endet auf keinem erlaubten Kopf-Morphem %r. "
                    "Terme ohne maschinell pruefbare Namens-Ausschlussregel "
                    "gehoeren nicht auf die Liste." % (term, _ERLAUBTE_KOPF_MORPHEME),
                )

    def test_kein_eintrag_ist_ein_barer_kopf(self):
        """Aufnahmekriterium 2, Teil 2: der Kopf allein darf nicht auf die Liste.

        `term.endswith(kopf)` ist auch fuer den baren Kopf wahr -- 'preis'
        besteht den Kompositum-Test also formal, ist aber ein realer deutscher
        Familienname (ebenso 'grund'). Der Term muss deshalb ECHT laenger sein
        als sein Kopf.
        """
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                term = e["term"]
                self.assertNotIn(
                    term.lower(), _ERLAUBTE_KOPF_MORPHEME,
                    "Term %r IST ein bares Kopf-Morphem. Die Koepfe sind nicht "
                    "namensfrei (Preis, Grund sind deutsche Nachnamen) -- nur "
                    "das Kompositum ist geprueft." % term,
                )

    def test_barer_kopf_wuerde_auffallen(self):
        """Beleg, dass die Regel oben Zaehne hat -- konstruierter Gegenfall."""
        for kopf in ("preis", "grund"):
            self.assertIn(kopf, _ERLAUBTE_KOPF_MORPHEME)
            self.assertTrue(
                kopf.endswith(_ERLAUBTE_KOPF_MORPHEME),
                "Der bare Kopf %r besteht den Kompositum-Test -- genau deshalb "
                "braucht es die zusaetzliche Sperre." % kopf,
            )

    def test_gejointe_liste_trifft_keinen_verbotenen_span(self):
        """Der Kerntest gegen F1 und F2 -- gejoint, search, echte Flags."""
        for span in _VERBOTENE_SPANS:
            with self.subTest(span=span):
                self.assertIsNone(
                    self.matcher.search(span),
                    "Die gejointe Liste unterdrueckt den Span %r. Das entfernt "
                    "einen echten Treffer." % span,
                )

    def test_gejointe_liste_trifft_keinen_kontrollnamen(self):
        for _text, name in _RECALL_KONTROLLEN:
            with self.subTest(name=name):
                self.assertIsNone(
                    self.matcher.search(name),
                    "Die gejointe Liste unterdrueckt den Namen %r." % name,
                )

    def test_gejointe_liste_trifft_die_eigenen_proben(self):
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                span = e.get("measured_span", e["term"])
                self.assertIsNotNone(
                    self.matcher.search(span),
                    "Die gejointe Liste trifft den gemessenen Span %r nicht."
                    % span,
                )


class BetreiberVorrang(unittest.TestCase):
    """Die Stoppwortliste darf die deny_list des Betreibers nicht ueberstimmen.

    Presidios ``allow_list`` wirkt NACH der Erkennung: sie entfernt jeden
    Treffer, dessen Span sie matcht -- unabhaengig davon, welcher Recognizer
    ihn erzeugt hat. Sie trifft damit auch die ``deny_list``-Recognizer aus
    presidio/recognizers-config.yml (DE_GENDER, DE_BERUF).

    Live belegt:

        "Der Buergermeister kommt morgen vorbei."
          ohne allow_list                            -> DE_BERUF
          mit allow_list, die das Wort enthaelt      -> kein Treffer, keine Warnung

    Eine ``deny_list`` ist eine ausdrueckliche Schutzanweisung des Betreibers,
    die Stoppwortliste eine mitgelieferte Vorgabe. Eine Vorgabe darf eine
    ausdrueckliche Anweisung nicht still ueberstimmen -- sonst nimmt ein Update
    lautlos Schutz weg, den der Betreiber selbst konfiguriert hat.

    Heute gibt es keine Ueberschneidung. Das ist ein Zustand, kein Mechanismus.
    Dieser Test macht daraus einen Mechanismus -- ohne laufenden Container und
    ohne den Guardrail-Anschluss abzuwarten.

    Bindend festgehalten in ADR-0002 (Konsequenz 2) und
    docs/foundation/erkennungsziel.md §7 ("Vorrang der Betreiber-Konfiguration").
    """

    @classmethod
    def setUpClass(cls):
        cls.doc = _load_stopwords()
        cls.matcher = _joined_matcher(cls.doc)
        cls.deny = _deny_list_terme()

    def test_deny_list_terme_werden_ueberhaupt_gefunden(self):
        """Ohne diesen Test waere die Kollisionspruefung nach einer Umstellung
        von recognizers-config.yml still leer -- und damit immer gruen."""
        self.assertTrue(
            self.deny,
            "Keine deny_list-Terme in %s gefunden. Entweder wurde die Datei "
            "umstrukturiert oder die Recognizer sind weg -- in beiden Faellen "
            "prueft der Vorrangs-Test nichts mehr." % _RECOGNIZER_PATH,
        )
        namen = {n for n, _ in self.deny}
        self.assertIn("DE_BERUF", namen)
        self.assertIn("DE_GENDER", namen)

    def test_kein_muster_trifft_einen_deny_list_term(self):
        """Der eigentliche Vorrang: der Betreiber gewinnt."""
        for name, term in self.deny:
            with self.subTest(recognizer=name, term=term):
                self.assertIsNone(
                    self.matcher.search(term),
                    "Die Stoppwortliste unterdrueckt den deny_list-Term %r "
                    "(%s). Damit haette eine mitgelieferte Vorgabeliste eine "
                    "ausdrueckliche Anweisung des Betreibers still "
                    "ueberstimmt." % (term, name),
                )

    def test_die_kollisionspruefung_hat_zaehne(self):
        """Beleg, dass der Test oben nicht nur zufaellig gruen ist.

        Dieselbe Pruefung gegen eine konstruiert kollidierende Liste MUSS
        anschlagen -- sonst waere die Kontrolle wertlos.
        """
        kollidierend = _patterns(self.doc) + ["(?i:\\ABürgermeister\\z)"]
        matcher = regex.compile("|".join(kollidierend), flags=self.doc.get("regex_flags", 0))
        self.assertIsNotNone(
            matcher.search("Bürgermeister"),
            "Eine Liste, die einen deny_list-Term enthaelt, muss von der "
            "Kollisionspruefung erkannt werden.",
        )


class GuardrailSendetAllowList(unittest.TestCase):
    """Der ausgelieferte Zustand: schickt der Guardrail die Liste mit? (§7)

    Das war die eigentliche Luecke von DATENSCHLE-82: Die Liste war gemessen,
    auditiert und gemergt -- und wirkte ausschliesslich im Benchmark. Im
    laufenden Proxy stand sie nirgends. Gemessene Zahlen, die nur ein
    Werkzeug erreicht, beschreiben den erreichbaren, nicht den ausgelieferten
    Zustand.

    Geprueft wird deshalb das Payload auf der Leitung, nicht der Quelltext.
    """

    def setUp(self):
        self.doc = _load_stopwords()
        self.guard = dg.DatenschleuseGuardrail(
            presidio_analyzer_url="http://nicht-erreichbar:3000",
            image_policy="block",
        )

    def test_payload_enthaelt_die_allow_list(self):
        payload = analyze_payload(self.guard)
        self.assertIsNotNone(payload, "Es wurde gar kein /analyze-Payload gebaut.")
        self.assertIn(
            "allow_list",
            payload,
            "Der Guardrail sendet die Nicht-PII-Wortliste nicht mit. Damit "
            "wirkt presidio/de-stopwords.yml nur im Benchmark und nicht in "
            "Produktion (docs/foundation/erkennungsziel.md §7).",
        )
        self.assertEqual(sorted(payload["allow_list"]), sorted(_patterns(self.doc)))

    def test_payload_setzt_allow_list_match_auf_regex(self):
        payload = analyze_payload(self.guard) or {}
        self.assertEqual(
            payload.get("allow_list_match"),
            "regex",
            "Ohne allow_list_match='regex' vergleicht Presidio die Eintraege "
            "als Literale -- die verankerten Muster treffen dann nie.",
        )

    def test_payload_sendet_regex_flags_explizit(self):
        """Der Punkt, an dem die erste Fassung der Liste gescheitert ist (F1).

        Ohne explizite Flags defaultet ``AnalyzerRequest`` auf
        DOTALL|MULTILINE|IGNORECASE. Unter MULTILINE werden aus den
        Vollspan-Ankern ``\\A``/``\\z`` faktisch Zeilen-Anker-Verhaeltnisse:
        mehrzeilige Spans wie "Zahlungsart\\nLoewenstein" fielen komplett weg,
        inklusive des echten Nachnamens.
        """
        payload = analyze_payload(self.guard) or {}
        self.assertIn(
            "regex_flags",
            payload,
            "regex_flags fehlt im Payload -- der Analyzer defaultet dann auf "
            "DOTALL|MULTILINE|IGNORECASE (Security-Finding F1).",
        )
        self.assertEqual(payload["regex_flags"], self.doc["regex_flags"])

    def test_verifikationsdurchlauf_sieht_dieselbe_konfiguration(self):
        """Beide Durchlaeufe muessen dieselbe Erkennungskonfiguration sehen.

        ``_analyze`` bedient die Maskierung UND den Verifikationsdurchlauf,
        der das fertig maskierte Ergebnis erneut prueft und bei Restbefund
        fail-closed blockt. Wirkte die Liste nur im Maskierungspfad, waere der
        Selbstblock garantiert: Die Maskierung ueberspringt 'bestellnummer',
        die Verifikation findet es im Ergebnis weiterhin -- und blockt jeden
        Request, der einen Stoppwort-Term enthaelt. Aus einem Precision-Fix
        wuerde eine Verfuegbarkeitsstoerung.

        Der Test haelt fest, dass beide Pfade durch dieselbe Naht laufen und
        dort dasselbe Payload entsteht.
        """
        payload_maskierung = analyze_payload(self.guard, "bestellnummer")
        payload_verifikation = analyze_payload(self.guard, "bestellnummer   ")
        for name, payload in (
            ("Maskierung", payload_maskierung),
            ("Verifikation", payload_verifikation),
        ):
            with self.subTest(durchlauf=name):
                self.assertIn("allow_list", payload or {})
                self.assertEqual((payload or {}).get("allow_list_match"), "regex")

    def test_leere_liste_wird_nicht_gesendet(self):
        """Gegenprobe: der Test oben ist nicht durch ein Konstrukt gruen, das
        immer einen allow_list-Schluessel setzt."""
        payload = analyze_payload(self.guard, "   ")
        self.assertIsNone(
            payload,
            "Leerer Text darf gar keinen Analyzer-Call ausloesen -- sonst "
            "misst der Payload-Test etwas anderes als den echten Pfad.",
        )


class BetreiberVorrangZurLaufzeit(unittest.TestCase):
    """Der Betreiber gewinnt -- auch zur Laufzeit (§7, ADR-0002 Konsequenz 2).

    Die Datenebene (Klasse ``BetreiberVorrang`` oben) prueft die Liste, die in
    DIESEM Repo liegt. Das reicht nicht mehr, seit der Guardrail die Liste
    sendet: Betreiber pflegen ihre eigene recognizers-config.yml, und die kann
    mit der mitgelieferten Stoppwortliste kollidieren, ohne dass jemand hier
    es merkt.

    Verlangt ist FAIL-CLOSED beim Laden -- nicht "kollidierenden Eintrag still
    ueberspringen", nicht "wirken lassen". Wer beides konfiguriert hat, hat
    einen Konflikt, den nur er aufloesen kann; der Dienst darf ihn nicht fuer
    ihn entscheiden.

    KEIN ``skipUnless`` mehr. Vorher haing diese Klasse an einem Schalter, der
    den Quelltext des Guardrails nach dem Wort "allow_list" durchsuchte. Damit
    haette ein Rueckbau der Verdrahtung den Test nicht rot gemacht, sondern
    stillschweigend abgeschaltet -- die Anforderung waere lautlos verschwunden.
    Sie ist jetzt faellig, also laeuft sie.
    """

    @staticmethod
    def _schreibe_liste(verzeichnis, patterns, **overrides):
        doc = {
            "version": 2,
            "allow_list_match": "regex",
            "regex_flags": 0,
            "entries": [{"term": p, "pattern": p} for p in patterns],
        }
        doc.update(overrides)
        pfad = os.path.join(verzeichnis, "de-stopwords.yml")
        with open(pfad, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, allow_unicode=True)
        return pfad

    def _guardrail_mit(self, stopwords_path):
        return dg.DatenschleuseGuardrail(
            presidio_analyzer_url="http://nicht-erreichbar:3000",
            image_policy="block",
            stopwords_path=stopwords_path,
            recognizers_path=_RECOGNIZER_PATH,
        )

    def test_kollision_beim_laden_fuehrt_zu_startfehler(self):
        """Der Kern: ein Muster, das einen deny_list-Term trifft, verhindert
        den Start -- nicht "Eintrag ueberspringen", nicht "wirken lassen"."""
        deny_term = next(t for _, t in _deny_list_terme())
        with tempfile.TemporaryDirectory() as tmp:
            pfad = self._schreibe_liste(
                tmp, ["(?i:\\Abestellnummer\\z)", "(?i:\\A%s\\z)" % regex.escape(deny_term)]
            )
            with self.assertRaises(ds.StopwordConfigError) as ctx:
                self._guardrail_mit(pfad)
        self.assertIn(
            deny_term,
            str(ctx.exception),
            "Die Fehlermeldung muss den kollidierenden Term nennen -- sonst "
            "kann der Betreiber den Konflikt nicht aufloesen.",
        )

    def test_ohne_kollision_startet_der_guardrail(self):
        """Gegenprobe: die Pruefung blockt nicht einfach alles."""
        with tempfile.TemporaryDirectory() as tmp:
            pfad = self._schreibe_liste(tmp, ["(?i:\\Abestellnummer\\z)"])
            guard = self._guardrail_mit(pfad)
        payload = analyze_payload(guard)
        self.assertEqual(payload["allow_list"], ["(?i:\\Abestellnummer\\z)"])

    def test_die_ausgelieferte_kombination_startet(self):
        """Die Dateien, die dieses Repo mitliefert, muessen zusammenpassen.

        Ohne diesen Test koennte ein neuer Eintrag in de-stopwords.yml den
        Dienst beim naechsten Start unbrauchbar machen -- gemerkt haette es
        erst der Betreiber."""
        guard = dg.DatenschleuseGuardrail(
            presidio_analyzer_url="http://nicht-erreichbar:3000",
            image_policy="block",
            stopwords_path=_STOPWORD_PATH,
            recognizers_path=_RECOGNIZER_PATH,
        )
        self.assertIn("allow_list", analyze_payload(guard))

    def test_fehlende_liste_fuehrt_zu_startfehler(self):
        """Nicht lesbar heisst nicht "einfach ohne Liste weiterlaufen" -- das
        waere eine unbemerkte Verhaltensaenderung im Betrieb (§7)."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ds.StopwordConfigError):
                self._guardrail_mit(os.path.join(tmp, "gibt-es-nicht.yml"))

    def test_fehlende_regex_flags_fuehren_zu_startfehler(self):
        """Ohne explizite Flags waere F1 wieder scharf -- also gar nicht erst
        starten."""
        with tempfile.TemporaryDirectory() as tmp:
            pfad = self._schreibe_liste(tmp, ["(?i:\\Abestellnummer\\z)"])
            doc = yaml.safe_load(open(pfad, encoding="utf-8"))
            del doc["regex_flags"]
            with open(pfad, "w", encoding="utf-8") as fh:
                yaml.safe_dump(doc, fh)
            with self.assertRaises(ds.StopwordConfigError):
                self._guardrail_mit(pfad)

    def test_fehlende_recognizer_config_fuehrt_zu_startfehler(self):
        """Ohne die Betreiber-Config ist der Vorrang nicht pruefbar. Nicht
        pruefbar heisst nicht "dann eben nicht pruefen"."""
        with tempfile.TemporaryDirectory() as tmp:
            pfad = self._schreibe_liste(tmp, ["(?i:\\Abestellnummer\\z)"])
            with self.assertRaises(ds.StopwordConfigError):
                dg.DatenschleuseGuardrail(
                    presidio_analyzer_url="http://nicht-erreichbar:3000",
                    image_policy="block",
                    stopwords_path=pfad,
                    recognizers_path=os.path.join(tmp, "gibt-es-nicht.yml"),
                )

    def test_die_kollisionspruefung_hat_zur_laufzeit_zaehne(self):
        """Beleg, dass der Kern-Test nicht zufaellig gruen ist: dieselbe
        Pruefung gegen eine Betreiber-Config OHNE den Term muss durchlassen."""
        deny_term = next(t for _, t in _deny_list_terme())
        with tempfile.TemporaryDirectory() as tmp:
            leere_config = os.path.join(tmp, "recognizers-config.yml")
            with open(leere_config, "w", encoding="utf-8") as fh:
                yaml.safe_dump({"recognizers": [{"name": "X", "deny_list": ["zzz"]}]}, fh)
            pfad = self._schreibe_liste(tmp, ["(?i:\\A%s\\z)" % regex.escape(deny_term)])
            guard = dg.DatenschleuseGuardrail(
                presidio_analyzer_url="http://nicht-erreichbar:3000",
                image_policy="block",
                stopwords_path=pfad,
                recognizers_path=leere_config,
            )
        self.assertIn("allow_list", analyze_payload(guard))


@unittest.skipUnless(
    _ANALYZER_DA,
    "Presidio-Analyzer nicht erreichbar auf %s." % _ANALYZER_URL,
)
class StopwordListeGegenAnalyzer(unittest.TestCase):
    """Gegen den echten Analyzer: wirkt die Liste, und was kostet sie?"""

    @classmethod
    def setUpClass(cls):
        import requests

        cls.requests = requests
        cls.doc = _load_stopwords()
        cls.allow_list = _patterns(cls.doc)
        cls.flags = cls.doc.get("regex_flags", 0)

    def _analyze(self, text, mit_liste):
        payload = {"text": text, "language": "de"}
        if mit_liste:
            payload["allow_list"] = self.allow_list
            payload["allow_list_match"] = "regex"
            payload["regex_flags"] = self.flags
        r = self.requests.post(_ANALYZER_URL + "/analyze", json=payload, timeout=30)
        r.raise_for_status()
        return r.json()

    def test_probe_feuert_ohne_liste(self):
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                self.assertTrue(
                    self._analyze(e["probe"], mit_liste=False),
                    "Probe %r hat keinen gemessenen Anlass mehr." % e["probe"],
                )

    def test_probe_ist_mit_liste_sauber(self):
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                treffer = self._analyze(e["probe"], mit_liste=True)
                self.assertEqual(treffer, [], "Probe %r liefert noch %r." % (
                    e["probe"], treffer))

    def test_kein_recall_verlust_bei_echten_namen(self):
        """Anti-Kriterium gegen den echten Analyzer, inkl. der Layouts aus F1/F2."""
        for text, name in _RECALL_KONTROLLEN:
            with self.subTest(name=name, text=text):
                treffer = self._analyze(text, mit_liste=True)
                gefunden = any(name in text[t["start"]:t["end"]] for t in treffer)
                self.assertTrue(
                    gefunden,
                    "Name %r in %r wird mit aktiver Liste NICHT mehr erkannt. "
                    "Treffer: %r" % (name, text, treffer),
                )

    def test_liste_aendert_nichts_an_kontrollen_gegenprobe(self):
        """Staerkste Form: die Trefferliste MUSS mit und ohne Liste identisch
        sein, wenn der Text nur echte Namen enthaelt."""
        for text, name in _RECALL_KONTROLLEN:
            with self.subTest(name=name):
                ohne = self._analyze(text, mit_liste=False)
                mit = self._analyze(text, mit_liste=True)
                self.assertEqual(
                    [(t["entity_type"], t["start"], t["end"]) for t in ohne],
                    [(t["entity_type"], t["start"], t["end"]) for t in mit],
                    "Die Liste veraendert das Ergebnis fuer %r." % text,
                )


@unittest.skipUnless(
    _ANALYZER_DA,
    "Presidio-Analyzer nicht erreichbar auf %s." % _ANALYZER_URL,
)
class GuardrailAbnahmeGegenAnalyzer(unittest.IsolatedAsyncioTestCase):
    """Die Abnahmepunkte aus §7 -- durch den GUARDRAIL, nicht am Analyzer.

    Die Klasse darueber belegt, was der Analyzer mit der Liste tut. Das ist
    genau die Aussage, die DATENSCHLE-82 ausgeloest hat: der erreichbare
    Zustand. Hier laeuft derselbe Nachweis durch den ausgelieferten Pfad --
    ``async_pre_call_hook`` -> ``_analyze`` -> echter Analyzer.
    """

    def _guard(self):
        return dg.DatenschleuseGuardrail(
            presidio_analyzer_url=_ANALYZER_URL,
            image_policy="block",
        )

    async def _pre_call(self, messages):
        data = {"messages": messages}
        return await self._guard().async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )

    async def test_abnahme_1_tool_call_schluessel_bleibt_wert_wird_maskiert(self):
        """§7 Abnahme 1 -- die FP-Klasse, die still Funktionalitaet zerstoert."""
        msg = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "lookup",
                    "arguments": json.dumps(
                        {"bestellnummer": "Herr Mueller"}, ensure_ascii=False
                    ),
                },
            }],
        }
        out = await self._pre_call([msg])
        nachricht = next(m for m in out["messages"] if m.get("tool_calls"))
        args = json.loads(nachricht["tool_calls"][0]["function"]["arguments"])
        self.assertIn(
            "bestellnummer",
            args,
            "Der Parametername wurde maskiert -- der Tool-Call geht durch und "
            "ist beim Empfaenger unbrauchbar (DATENSCHLE-71).",
        )
        self.assertNotIn(
            "Mueller",
            args["bestellnummer"],
            "Der Wert muss weiterhin maskiert werden -- die Liste darf "
            "Precision kaufen, aber keinen Recall.",
        )

    async def test_abnahme_2_zweizeiliges_label_wert_paar(self):
        """§7 Abnahme 2 -- Regressionsnachweis fuer Security-Finding F1."""
        out = await self._pre_call(
            [{"role": "user", "content": "Zahlungsart\nLoewenstein"}]
        )
        inhalte = " ".join(
            m.get("content") or "" for m in out["messages"] if isinstance(m.get("content"), str)
        )
        self.assertNotIn("Loewenstein", inhalte)

    async def test_abnahme_3_nachname_vorname(self):
        """§7 Abnahme 3 -- Regressionsnachweis fuer Security-Finding F2."""
        out = await self._pre_call([{"role": "user", "content": "Menge, Andreas"}])
        inhalte = " ".join(
            m.get("content") or "" for m in out["messages"] if isinstance(m.get("content"), str)
        )
        for name in ("Menge", "Andreas"):
            with self.subTest(name=name):
                self.assertNotIn(name, inhalte)

    async def test_abnahme_4_deny_list_term_des_betreibers_bleibt_wirksam(self):
        """§7 Abnahme 4 -- die mitgelieferte Vorgabe entschaerft nichts."""
        out = await self._pre_call(
            [{"role": "user", "content": "Der Bürgermeister kommt morgen vorbei."}]
        )
        inhalte = " ".join(
            m.get("content") or "" for m in out["messages"] if isinstance(m.get("content"), str)
        )
        self.assertNotIn(
            "Bürgermeister",
            inhalte,
            "Der deny_list-Treffer des Betreibers wurde von der "
            "mitgelieferten Stoppwortliste still ueberstimmt.",
        )


if __name__ == "__main__":
    unittest.main()
