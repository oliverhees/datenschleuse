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

import os
import unittest

import regex
import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_STOPWORD_PATH = os.path.normpath(
    os.path.join(_HERE, "..", "presidio", "de-stopwords.yml")
)
_ANALYZER_URL = os.environ.get("PRESIDIO_ANALYZER_URL", "http://localhost:5001")

# Kopf-Morpheme, die als bare deutsche Familiennamen nicht vorkommen. Nur
# Komposita mit diesen Koepfen duerfen auf die Liste (Aufnahmekriterium 2).
# Die Regel ist maschinell prüfbar -- anders als "hat keine Namenslesart",
# das vorher eine Schaetzung war und genau deshalb 'menge' und 'fuege'
# durchgelassen hat (beides reale Nachnamen).
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
        """Aufnahmekriterium 2 maschinell statt geschaetzt.

        Vorher war das Kriterium "keine plausible Eigennamen-Lesart" -- eine
        Einschaetzung, die 'menge' und 'fuege' durchgelassen hat, beides reale
        deutsche Nachnamen. Jetzt: nur Komposita mit einem Kopf-Morphem, das
        als barer Familienname nicht vorkommt.
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


if __name__ == "__main__":
    unittest.main()
