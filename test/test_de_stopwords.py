"""Tests fuer die deutsche Nicht-PII-Wortliste (presidio/de-stopwords.yml).

Die Liste unterdrueckt gemessene spaCy-NER-Fehlzuendungen (DATENSCHLE-70:
ASCII-Umschrift, DATENSCHLE-71: deutsche Schema-Schluessel) ueber Presidios
eigenen `allow_list`-Mechanismus im /analyze-Request.

Zwei Test-Ebenen:

1. STRUKTUR (laeuft ohne Container). Prueft die Sicherheitseigenschaften der
   Liste selbst -- vor allem die Verankerung. Ein Eintrag MUSS `^...$`
   verankert sein, denn nur dann unterdrueckt er ausschliesslich Spans, die
   VOLLSTAENDIG aus dem Stoppwort bestehen. Erweitert der NER den Span auf
   einen Namenskontext ("Frau Menge"), greift die Unterdrueckung nicht mehr.
   Diese Eigenschaft ist der Grund, warum die Liste keinen Recall kostet --
   sie wird hier maschinell erzwungen, nicht nur dokumentiert.

2. INTEGRATION (braucht laufenden Analyzer auf PRESIDIO_ANALYZER_URL,
   Default http://localhost:5001). Prueft gegen den echten Analyzer, dass
   jeder Eintrag seinen gemessenen False Positive wirklich unterdrueckt --
   und dass die Positiv-Kontrollen (echte Nachnamen in ASCII-Umschrift)
   weiterhin erkannt werden.

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

# Echte Namen, die von der Liste NIEMALS unterdrueckt werden duerfen.
# Deckt beide Schreibweisen und den harten Fall "Stoppwort direkt neben
# echtem Namen im selben Satz" ab.
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
    # Kollisionsfall: 'menge' steht als Schema-Schluessel auf der Liste,
    # 'Menge' ist aber auch ein realer deutscher Nachname. Sobald ein
    # Namenskontext den Span verbreitert, muss die Erkennung greifen.
    ("Frau Menge und Herr Mueller melden sich.", "Menge"),
]


def _load_stopwords():
    with open(_STOPWORD_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _entries(doc):
    return doc.get("entries", [])


def _patterns(doc):
    return [e["pattern"] for e in _entries(doc)]


def _analyzer_erreichbar():
    try:
        import requests

        r = requests.get(_ANALYZER_URL + "/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


_ANALYZER_DA = _analyzer_erreichbar()


class StopwordListeStruktur(unittest.TestCase):
    """Sicherheitseigenschaften der Liste -- ohne Container pruefbar."""

    @classmethod
    def setUpClass(cls):
        cls.doc = _load_stopwords()

    def test_liste_nutzt_regex_matching(self):
        self.assertEqual(
            self.doc.get("allow_list_match"),
            "regex",
            "Die Liste muss regex-Matching deklarieren -- nur damit sind "
            "verankerte Muster und (?i) moeglich.",
        )

    def test_jeder_eintrag_ist_verankert(self):
        """^...$ ist die Eigenschaft, die den Recall schuetzt."""
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                pat = e["pattern"]
                kern = pat[4:] if pat.startswith("(?i)") else pat
                self.assertTrue(
                    kern.startswith("^") and kern.endswith("$"),
                    "Eintrag %r ist nicht verankert (%r). Unverankerte Muster "
                    "wuerden auch Spans wie 'Frau Menge' treffen und damit "
                    "echte Namen unterdruecken." % (e.get("term"), pat),
                )

    def test_jedes_muster_kompiliert(self):
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                regex.compile(e["pattern"])

    def test_keine_doppelten_muster(self):
        pats = _patterns(self.doc)
        self.assertEqual(
            len(pats), len(set(pats)), "Doppelte Muster in de-stopwords.yml."
        )

    def test_jeder_eintrag_hat_messbeleg(self):
        """Artefakt-Pflicht: kein Eintrag ohne gemessenen Anlass."""
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                self.assertTrue(
                    e.get("probe"), "Eintrag %r ohne probe-Text." % e.get("term")
                )
                self.assertTrue(
                    e.get("measured_fp"),
                    "Eintrag %r ohne gemessenen FP-Typ." % e.get("term"),
                )

    def test_muster_trifft_eigenen_probe_span(self):
        """Das Muster muss den gemessenen FP-Teilstring vollstaendig matchen."""
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                span = e.get("measured_span", e["term"])
                self.assertIsNotNone(
                    regex.fullmatch(e["pattern"], span),
                    "Muster %r matcht den gemessenen Span %r nicht."
                    % (e["pattern"], span),
                )

    def test_muster_trifft_keine_kontrollnamen(self):
        """Kein Eintrag darf einen Kontroll-Namensspan vollstaendig matchen."""
        namen = [wert for _, wert in _RECALL_KONTROLLEN]
        for e in _entries(self.doc):
            for name in namen:
                with self.subTest(term=e.get("term"), name=name):
                    self.assertIsNone(
                        regex.fullmatch(e["pattern"], name),
                        "Muster %r wuerde den echten Namen %r unterdruecken."
                        % (e["pattern"], name),
                    )


@unittest.skipUnless(
    _ANALYZER_DA,
    "Presidio-Analyzer nicht erreichbar auf %s -- Integrationsteil "
    "uebersprungen." % _ANALYZER_URL,
)
class StopwordListeGegenAnalyzer(unittest.TestCase):
    """Gegen den echten Analyzer: wirkt die Liste, und was kostet sie?"""

    @classmethod
    def setUpClass(cls):
        import requests

        cls.requests = requests
        cls.doc = _load_stopwords()
        cls.allow_list = _patterns(cls.doc)

    def _analyze(self, text, mit_liste):
        payload = {"text": text, "language": "de"}
        if mit_liste:
            payload["allow_list"] = self.allow_list
            payload["allow_list_match"] = "regex"
        r = self.requests.post(
            _ANALYZER_URL + "/analyze", json=payload, timeout=30
        )
        r.raise_for_status()
        return r.json()

    def test_probe_feuert_ohne_liste(self):
        """Gegenprobe: ohne Liste MUSS der FP auftreten (sonst ist der
        Eintrag veraltet und die Liste waechst ohne Anlass)."""
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                treffer = self._analyze(e["probe"], mit_liste=False)
                self.assertTrue(
                    treffer,
                    "Probe %r liefert ohne Liste keinen Treffer mehr -- "
                    "Eintrag %r hat keinen gemessenen Anlass mehr."
                    % (e["probe"], e.get("term")),
                )

    def test_probe_ist_mit_liste_sauber(self):
        for e in _entries(self.doc):
            with self.subTest(term=e.get("term")):
                treffer = self._analyze(e["probe"], mit_liste=True)
                self.assertEqual(
                    treffer,
                    [],
                    "Probe %r liefert trotz Liste noch %r."
                    % (e["probe"], treffer),
                )

    def test_kein_recall_verlust_bei_echten_namen(self):
        """Anti-Kriterium: echte Namen bleiben erkannt."""
        for text, name in _RECALL_KONTROLLEN:
            with self.subTest(name=name):
                treffer = self._analyze(text, mit_liste=True)
                gefunden = any(
                    t["entity_type"] == "PERSON"
                    and name in text[t["start"]:t["end"]]
                    for t in treffer
                )
                self.assertTrue(
                    gefunden,
                    "Name %r in %r wird mit aktiver Stoppwortliste NICHT "
                    "mehr als PERSON erkannt. Treffer: %r"
                    % (name, text, treffer),
                )


if __name__ == "__main__":
    unittest.main()
