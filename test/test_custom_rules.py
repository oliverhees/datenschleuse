"""Unit-Tests fuer die eigenen Deny-Listen und Regex-Muster (DATENSCHLE-7).

Fachlicher Hintergrund
----------------------
Die automatische Erkennung findet nie alles. Kundennamen, Projektnamen,
interne Kuerzel, Produktbezeichnungen und Mandantennamen kennt kein
Sprachmodell und kein generisches Regex. Der Anwender muss sie deshalb SELBST
hinterlegen koennen -- deterministisch, sofort wirksam, jede Regel testbar.
Das ist bewusst KEIN ML-Training (siehe ADR 0001).

Getestet wird die reine Regel-Logik (litellm/custom_rules.py) OHNE laufenden
Container: Laden, Selbstverifikation, Treffersuche, Fehler-Isolation,
Hot-Reload und die Persistenz-Operationen der CLI.

Ausfuehren (aus dem Repo-Root -- "test.test_custom_rules" kollidiert mit dem
Python-Stdlib-Paket "test" und schlaegt dort fehl, siehe DATENSCHLE-62):
    python3 -m unittest discover -s ./test -p "test_custom_rules.py" -v
    # oder aus dem test/-Ordner:
    python3 -m unittest test_custom_rules -v
"""

import contextlib
import io
import os
import re
import signal
import sys
import tempfile
import time
import unittest

import yaml

# litellm/-Ordner (mit custom_rules.py) auf den Importpfad legen.
_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import custom_rules as cr  # noqa: E402
import datenschleuse_guardrail as dg  # noqa: E402


# ---------------------------------------------------------------------------
# Test-Helfer
# ---------------------------------------------------------------------------
def rule(name, entity="KUNDENNAME", kind="term", value="Adlerflug",
         examples=None, **extra):
    """Baut ein gueltiges Regel-Dict; einzelne Felder per kwargs ueberschreibbar."""
    r = {
        "name": name,
        "entity": entity,
        "type": kind,
        "value": value,
        "examples": examples if examples is not None else [f"Text mit {value} drin."],
    }
    r.update(extra)
    return r


class _RuleFileTestCase(unittest.TestCase):
    """Basis: legt eine temporaere Regeldatei an und raeumt sie wieder ab."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "custom-rules.yml")

    def tearDown(self):
        self._dir.cleanup()

    def write_rules(self, rules):
        """Schreibt eine Regelliste als YAML. Gibt den Pfad zurueck."""
        with open(self.path, "w", encoding="utf-8") as fh:
            yaml.safe_dump({"rules": rules}, fh, allow_unicode=True)
        return self.path

    def write_raw(self, content):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return self.path

    def read_bytes(self):
        with open(self.path, "rb") as fh:
            return fh.read()

    def matched_values(self, ruleset, text):
        """Die tatsaechlich getroffenen Teilstrings -- so pruefen wir Spans."""
        return sorted(text[e["start"]:e["end"]] for e in ruleset.find(text))


# ===========================================================================
# 1. ISC-23 -- Begriffe und Muster persistent hinterlegen
# ===========================================================================
class TestLoadingAndPersistence(_RuleFileTestCase):
    def test_term_rule_from_file_matches(self):
        """Der Kern des Tickets: ein hinterlegter Begriff wird gefunden."""
        self.write_rules([rule("kunde-adlerflug", value="Projekt Adlerflug",
                               examples=["Wir liefern Projekt Adlerflug aus."])])
        rs = cr.RuleSet(self.path)
        self.assertEqual(
            self.matched_values(rs, "Der Status von Projekt Adlerflug ist gruen."),
            ["Projekt Adlerflug"],
        )

    def test_regex_rule_from_file_matches(self):
        """Interne Kuerzel als Muster, nicht als Einzelbegriff."""
        self.write_rules([rule(
            "interne-projektnummer", entity="PROJEKTNUMMER", kind="regex",
            value=r"\bPRJ-\d{4}\b",
            examples=["Ticket zu PRJ-1234 bitte pruefen."],
        )])
        rs = cr.RuleSet(self.path)
        self.assertEqual(
            self.matched_values(rs, "Siehe PRJ-0815 und PRJ-4711."),
            ["PRJ-0815", "PRJ-4711"],
        )

    def test_missing_file_is_no_error_just_no_rules(self):
        """Ohne Regeldatei laeuft die Datenschleuse unveraendert weiter."""
        rs = cr.RuleSet(os.path.join(self._dir.name, "gibt-es-nicht.yml"))
        self.assertEqual(rs.find("Projekt Adlerflug"), [])
        self.assertEqual(rs.active_rules, [])

    def test_disabled_rule_does_not_match(self):
        self.write_rules([rule("aus", value="Adlerflug", enabled=False)])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.find("Projekt Adlerflug"), [])

    def test_hot_reload_without_new_instance(self):
        """ISC-23/ISC-27: neues Muster wirkt SOFORT -- ohne Rebuild, ohne
        Neustart, ohne neues RuleSet-Objekt."""
        self.write_rules([rule("erste", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.find("Kunde Seeadler meldet sich"), [])

        time.sleep(0.01)  # mtime-Aufloesung
        self.write_rules([
            rule("erste", value="Adlerflug"),
            rule("zweite", value="Seeadler", examples=["Kunde Seeadler meldet sich"]),
        ])
        self.assertEqual(
            self.matched_values(rs, "Kunde Seeadler meldet sich"), ["Seeadler"]
        )

    def test_hot_reload_notices_removed_rule(self):
        self.write_rules([rule("weg", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        self.assertTrue(rs.find("Projekt Adlerflug"))
        time.sleep(0.01)
        self.write_rules([])
        self.assertEqual(rs.find("Projekt Adlerflug"), [])


# ===========================================================================
# 2. ISC-24 -- Kein ungetestetes Muster geht live
# ===========================================================================
class TestSelfVerificationGate(_RuleFileTestCase):
    def test_rule_without_examples_never_activates(self):
        self.write_rules([rule("ohne-test", examples=[])])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.active_rules, [])
        self.assertEqual([q.name for q in rs.quarantined], ["ohne-test"])

    def test_rule_whose_example_does_not_match_is_quarantined(self):
        """Der Anwender tippt sich im Beispiel oder im Muster -- die Regel
        darf dann NICHT stillschweigend nichts tun, sie muss rot sein."""
        self.write_rules([rule(
            "tippfehler", value="Adlerflug",
            examples=["Hier steht das Wort gar nicht."],
        )])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.active_rules, [])
        self.assertEqual([q.name for q in rs.quarantined], ["tippfehler"])
        self.assertEqual(rs.find("Projekt Adlerflug"), [])

    def test_counter_example_that_matches_quarantines_rule(self):
        """Gegenbeispiele halten zu gierige Muster auf."""
        self.write_rules([rule(
            "zu-gierig", entity="KUERZEL", kind="regex", value=r"\b[A-Z]{2}\b",
            examples=["Das Kuerzel AB steht fuer den Kunden."],
            counter_examples=["Die AG hat geantwortet."],
        )])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.active_rules, [])
        self.assertEqual([q.name for q in rs.quarantined], ["zu-gierig"])

    def test_passing_counter_example_keeps_rule_active(self):
        self.write_rules([rule(
            "praezise", entity="KUERZEL", kind="regex", value=r"\bKD-[A-Z]{3}\b",
            examples=["Mandant KD-ABC hat angerufen."],
            counter_examples=["Die AG hat geantwortet."],
        )])
        rs = cr.RuleSet(self.path)
        self.assertEqual([r.name for r in rs.active_rules], ["praezise"])

    def test_add_rule_refuses_untested_pattern_and_leaves_file_untouched(self):
        """Die CLI schreibt eine durchgefallene Regel gar nicht erst weg."""
        self.write_rules([rule("bestand", value="Adlerflug")])
        before = self.read_bytes()

        with self.assertRaises(cr.RuleError):
            cr.add_rule(self.path, rule("kaputt", value="Adlerflug",
                                        examples=["Wort kommt hier nicht vor"]))

        self.assertEqual(self.read_bytes(), before)

    def test_add_rule_writes_and_activates_valid_rule(self):
        self.write_rules([])
        cr.add_rule(self.path, rule("neu", value="Adlerflug"))
        rs = cr.RuleSet(self.path)
        self.assertEqual([r.name for r in rs.active_rules], ["neu"])

    def test_add_rule_rejects_duplicate_name(self):
        self.write_rules([rule("doppelt", value="Adlerflug")])
        with self.assertRaises(cr.RuleError):
            cr.add_rule(self.path, rule("doppelt", value="Seeadler",
                                        examples=["Kunde Seeadler"]))

    def test_remove_rule_persists(self):
        self.write_rules([rule("a", value="Adlerflug"),
                          rule("b", value="Seeadler",
                               examples=["Kunde Seeadler"])])
        cr.remove_rule(self.path, "a")
        rs = cr.RuleSet(self.path)
        self.assertEqual([r.name for r in rs.active_rules], ["b"])


# ===========================================================================
# 3. ISC-26 (Anti-Kriterium) -- ein kaputtes Muster blockiert nur sich selbst
# ===========================================================================
class TestFaultIsolation(_RuleFileTestCase):
    def test_broken_regex_only_disables_itself(self):
        """DAS Anti-Kriterium: unbalancierte Klammer killt eine Regel, nicht
        die Pipeline."""
        self.write_rules([
            rule("kaputt", entity="MUELL", kind="regex", value=r"([A-Z",
                 examples=["irgendwas"]),
            rule("heil", value="Adlerflug"),
        ])
        rs = cr.RuleSet(self.path)
        self.assertEqual([r.name for r in rs.active_rules], ["heil"])
        self.assertEqual([q.name for q in rs.quarantined], ["kaputt"])
        # Die gesunde Regel arbeitet unbeeindruckt weiter:
        self.assertEqual(
            self.matched_values(rs, "Projekt Adlerflug laeuft"), ["Adlerflug"]
        )

    def test_catastrophic_regex_does_not_hang_the_pipeline(self):
        """Ein Muster mit exponentiellem Backtracking (ReDoS) darf den Request
        nicht ANHALTEN.

        Praezisiert nach Security-Finding F8: Der betroffene Request wird
        sichtbar geblockt statt still halb maskiert ausgeliefert -- ein
        Teilergebnis ist von einem vollstaendigen nicht zu unterscheiden.
        "Nicht lahmlegen" heisst: begrenzte Zeit und kein Dauerschaden, NICHT
        "liefere aus, was zufaellig fertig wurde".
        """
        self.write_rules([
            rule("redos", entity="MUELL", kind="regex", value=r"(a|a)*$",
                 examples=["aaaaaaaaaa"]),
            rule("heil", value="Adlerflug"),
        ])
        rs = cr.RuleSet(self.path)
        boese = "a" * 44 + "b Projekt Adlerflug"

        start = time.monotonic()
        with self.assertRaises(cr.RuleMatchingIncomplete):
            rs.find(boese)
        dauer = time.monotonic() - start

        self.assertLess(dauer, 5.0, "ReDoS-Regel hat die Pipeline angehalten")
        # Kein Dauerschaden: der naechste, harmlose Text laeuft normal durch.
        self.assertEqual(self.matched_values(rs, "Projekt Adlerflug laeuft"),
                         ["Adlerflug"])

    def test_unknown_rule_type_is_quarantined_not_fatal(self):
        self.write_rules([
            rule("exotisch", kind="neuronal", value="Adlerflug"),
            rule("heil", value="Adlerflug"),
        ])
        rs = cr.RuleSet(self.path)
        self.assertEqual([r.name for r in rs.active_rules], ["heil"])
        self.assertIn("exotisch", [q.name for q in rs.quarantined])

    def test_broken_yaml_keeps_last_good_ruleset(self):
        """Ein manueller Editier-Fehler an der Datei darf den laufenden Schutz
        nicht abschalten."""
        self.write_rules([rule("heil", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        self.assertTrue(rs.find("Projekt Adlerflug"))

        time.sleep(0.01)
        self.write_raw("rules: [ das ist: kein: gueltiges yaml")

        self.assertTrue(rs.find("Projekt Adlerflug"),
                        "letzter guter Stand wurde verworfen")
        self.assertTrue(rs.load_error)

    def test_rule_list_of_wrong_shape_is_quarantined(self):
        self.write_rules(["nur ein String statt eines Regel-Dicts"])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.active_rules, [])
        self.assertTrue(rs.quarantined)


# ===========================================================================
# 4. ISC-25 -- Welche Muster sind aktiv?
# ===========================================================================
class TestVisibility(_RuleFileTestCase):
    def test_describe_lists_active_and_quarantined_with_reason(self):
        self.write_rules([
            rule("gut", value="Adlerflug"),
            rule("schlecht", value="Adlerflug", examples=["kommt nicht vor"]),
        ])
        rs = cr.RuleSet(self.path)
        info = rs.describe()

        self.assertEqual([r["name"] for r in info["active"]], ["gut"])
        self.assertEqual([r["name"] for r in info["quarantined"]], ["schlecht"])
        # Der Anwender muss den GRUND sehen, sonst haelt er sich faelschlich
        # fuer geschuetzt (Auflage des Leads).
        self.assertTrue(info["quarantined"][0]["reason"])

    def test_describe_reports_entity_type_used_in_placeholders(self):
        self.write_rules([rule("gut", entity="Kundenname", value="Adlerflug")])
        info = cr.RuleSet(self.path).describe()
        self.assertEqual(info["active"][0]["entity_type"], "CUSTOM_KUNDENNAME")


# ===========================================================================
# 5. ISC-36 -- keine Trefferdaten, kein Roh-PII gespeichert
# ===========================================================================
class TestNoPiiPersistence(_RuleFileTestCase):
    def test_find_never_writes_to_disk(self):
        """Muster sind Konfiguration. Treffer sind fluechtig und werden
        NIRGENDWO persistiert -- das ist eine Kernzusage des Produkts."""
        self.write_rules([rule("kunde", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        vorher = self.read_bytes()
        dateien_vorher = sorted(os.listdir(self._dir.name))

        for i in range(50):
            rs.find(f"Projekt Adlerflug Vorgang {i} von Frau Mueller")

        self.assertEqual(self.read_bytes(), vorher)
        self.assertEqual(sorted(os.listdir(self._dir.name)), dateien_vorher)

    def test_quarantine_reason_does_not_echo_rule_value_or_examples(self):
        """Fehlermeldungen laufen in Logs (Gesetz 5). Der Regelwert kann ein
        echter Kundenname sein -- er darf dort nie auftauchen."""
        geheim = "Nordwind Sonderprojekt"
        self.write_rules([rule(
            "leck", entity="KUNDE", kind="regex", value=r"([A-Z" + geheim,
            examples=[f"Vertrag mit {geheim} unterschrieben"],
        )])
        rs = cr.RuleSet(self.path)
        reason = rs.quarantined[0].reason
        self.assertNotIn(geheim, reason)
        self.assertNotIn("Nordwind", reason)
        self.assertIn("leck", reason + rs.quarantined[0].name)


# ===========================================================================
# 6. Treffer-Semantik: Begriffe sind Literale, keine Regexe
# ===========================================================================
class TestMatchSemantics(_RuleFileTestCase):
    def test_term_is_literal_not_regex(self):
        """Ein Punkt im Begriff ist ein Punkt, kein 'beliebiges Zeichen'."""
        self.write_rules([rule("literal", value="a.b",
                               examples=["Kennung a.b hier"])])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.find("Kennung axb hier"), [])
        self.assertTrue(rs.find("Kennung a.b hier"))

    def test_term_is_case_insensitive_by_default(self):
        self.write_rules([rule("gross-klein", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        self.assertTrue(rs.find("projekt adlerflug"))

    def test_term_case_sensitive_when_requested(self):
        self.write_rules([rule("exakt", value="ADL", case_sensitive=True,
                               examples=["Kuerzel ADL hier"])])
        rs = cr.RuleSet(self.path)
        self.assertTrue(rs.find("Kuerzel ADL hier"))
        self.assertEqual(rs.find("Kuerzel adl hier"), [])

    def test_term_respects_word_boundaries(self):
        """'Adler' maskiert nicht die halbe 'Adlerflug' -- sonst entstehen
        Text-Truemmer, die das Modell verwirren."""
        self.write_rules([rule("wort", value="Adler",
                               examples=["Der Adler ist gelandet"])])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.find("Projekt Adlerflug"), [])
        self.assertTrue(rs.find("Der Adler ist gelandet"))

    def test_entity_type_is_prefixed_to_avoid_collisions(self):
        """Eigene Entitaeten duerfen nie mit Presidio-Typen kollidieren."""
        self.write_rules([rule("k", entity="person", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.find("Projekt Adlerflug")[0]["entity_type"],
                         "CUSTOM_PERSON")

    def test_result_shape_is_presidio_compatible(self):
        """Die Treffer muessen ohne Umbau durch den bestehenden Masker laufen."""
        self.write_rules([rule("k", value="Adlerflug")])
        treffer = cr.RuleSet(self.path).find("Projekt Adlerflug")[0]
        for key in ("entity_type", "start", "end", "score"):
            self.assertIn(key, treffer)
        self.assertIsInstance(treffer["start"], int)
        self.assertIsInstance(treffer["score"], float)

    def test_overlapping_matches_of_one_rule_are_not_duplicated(self):
        self.write_rules([rule("k", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        self.assertEqual(len(rs.find("Adlerflug und Adlerflug")), 2)


# ===========================================================================
# 7. Round-Trip: eigene Begriffe laufen durch DASSELBE Mapping wie alles andere
# ===========================================================================
class TestRoundTripThroughMasker(_RuleFileTestCase):
    def test_custom_match_gets_placeholder_and_reid_map_entry(self):
        self.write_rules([rule("kunde", entity="KUNDENNAME",
                               value="Projekt Adlerflug",
                               examples=["Projekt Adlerflug laeuft"])])
        rs = cr.RuleSet(self.path)
        text = "Der Status von Projekt Adlerflug ist gruen."

        masker = dg.Masker()
        maskiert = masker.mask(text, rs.find(text))

        self.assertNotIn("Projekt Adlerflug", maskiert)
        self.assertIn("<CUSTOM_KUNDENNAME_0>", maskiert)
        # ... und zurueck, ueber den bestehenden Weg:
        self.assertEqual(dg.reidentify_full(maskiert, masker.reid_map), text)

    def test_custom_match_survives_streaming_reidentification(self):
        """Der Platzhalter muss auch ueber Chunk-Grenzen hinweg zurueckkommen."""
        self.write_rules([rule("kunde", entity="KUNDENNAME", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        masker = dg.Masker()
        masker.mask("Projekt Adlerflug", rs.find("Projekt Adlerflug"))

        proc = dg.ReidStreamProcessor(masker.reid_map)
        out = proc.feed("Status von <CUSTOM_KUND") + proc.feed("ENNAME_0> ok")
        out += proc.flush()
        self.assertEqual(out, "Status von Adlerflug ok")


# ===========================================================================
# 8. Integration in die Guardrail (Presidio gemockt)
# ===========================================================================
class TestGuardrailIntegration(_RuleFileTestCase, unittest.IsolatedAsyncioTestCase):
    async def test_analyze_merges_custom_rules_with_presidio(self):
        self.write_rules([rule("kunde", entity="KUNDENNAME", value="Adlerflug")])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def fake_presidio(text, payload=None):
            return [{"entity_type": "PERSON", "start": 0, "end": 4, "score": 0.99}]

        guard._presidio_analyze = fake_presidio  # nur den externen Call ersetzen
        treffer = await guard._analyze("Anna leitet Projekt Adlerflug")
        typen = sorted(e["entity_type"] for e in treffer)
        self.assertEqual(typen, ["CUSTOM_KUNDENNAME", "PERSON"])

    async def test_custom_rule_masked_in_pre_call_hook(self):
        """End-to-end durch den echten Hook: der eigene Begriff verlaesst das
        System nicht im Klartext."""
        self.write_rules([rule("kunde", entity="KUNDENNAME", value="Adlerflug")])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def keine_presidio_treffer(text, payload=None):
            return []

        guard._presidio_analyze = keine_presidio_treffer

        data = {"messages": [{"role": "user", "content": "Wie laeuft Adlerflug?"}]}
        out = await guard.async_pre_call_hook(None, None, data, "completion")

        self.assertNotIn("Adlerflug", out["messages"][0]["content"])
        self.assertIn("Adlerflug", out["metadata"][dg.REID_MAP_KEY].values())

    async def test_guardrail_survives_completely_broken_rule_file(self):
        """ISC-26 auf Guardrail-Ebene: kaputte Regeln duerfen die
        Presidio-Maskierung nicht mitreissen."""
        self.write_raw("{{{ kein yaml")
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def fake_presidio(text, payload=None):
            return [{"entity_type": "PERSON", "start": 0, "end": 4, "score": 0.99}]

        guard._presidio_analyze = fake_presidio
        treffer = await guard._analyze("Anna leitet das Projekt")
        self.assertEqual([e["entity_type"] for e in treffer], ["PERSON"])

    async def test_guardrail_without_rules_file_behaves_as_before(self):
        guard = dg.DatenschleuseGuardrail(
            custom_rules_path=os.path.join(self._dir.name, "nicht-da.yml")
        )

        async def fake_presidio(text, payload=None):
            return []

        guard._presidio_analyze = fake_presidio
        self.assertEqual(await guard._analyze("harmloser Text"), [])


if __name__ == "__main__":
    unittest.main()


# ===========================================================================
# 9. F1 (Security-Audit) — eine eigene Regel darf NIE Schutz WEGNEHMEN
#
# Der gefaehrlichste denkbare Defekt fuer dieses Feature: Ein Anwender legt
# eine Regel an, um sich ZUSAETZLICH zu schuetzen, und verliert dadurch
# Schutz, den er vorher hatte -- ohne es zu merken. Ursache war, dass
# _resolve_overlaps den ueberlappenden schwaecheren Treffer KOMPLETT verwarf,
# auch wenn dieser den Gewinner echt enthielt.
# ===========================================================================
class TestCustomRuleNeverReducesMasking(_RuleFileTestCase):
    def _presidio(self, text, wert, typ, score):
        i = text.index(wert)
        return {"entity_type": typ, "start": i, "end": i + len(wert), "score": score}

    def test_custom_rule_does_not_unmask_rest_of_presidio_span(self):
        """Regel auf 'Max' darf 'Mustermann' nicht im Klartext rauslassen."""
        text = "Bitte melde dich bei Max Mustermann von Nordwind Logistik GmbH."
        self.write_rules([
            rule("kunde-max", entity="Kundenname", value="Max",
                 examples=["Kunde Max meldet sich"]),
            rule("kunde-nordwind", entity="Kundenname", value="Nordwind",
                 examples=["Firma Nordwind meldet sich"]),
        ])
        rs = cr.RuleSet(self.path)

        presidio = [
            self._presidio(text, "Max Mustermann", "PERSON", 0.85),
            self._presidio(text, "Nordwind Logistik GmbH", "DE_FIRMA", 0.6),
        ]
        maskiert = dg.Masker().mask(text, presidio + rs.find(text))

        self.assertNotIn("Mustermann", maskiert)
        self.assertNotIn("Logistik", maskiert)
        self.assertNotIn("GmbH", maskiert)

    def test_masking_with_custom_rules_covers_at_least_presidio_alone(self):
        """Formal: die maskierte Zeichenmenge darf durch eigene Regeln nur
        wachsen, nie schrumpfen."""
        text = "Bitte melde dich bei Max Mustermann von Nordwind Logistik GmbH."
        self.write_rules([rule("kunde-max", entity="Kundenname", value="Max",
                               examples=["Kunde Max meldet sich"])])
        rs = cr.RuleSet(self.path)
        presidio = [self._presidio(text, "Max Mustermann", "PERSON", 0.85)]

        def abgedeckt(entities):
            positionen = set()
            for e in dg.Masker._resolve_overlaps(entities, len(text)):
                positionen.update(range(e["start"], e["end"]))
            return positionen

        nur_presidio = abgedeckt(presidio)
        mit_eigenen = abgedeckt(presidio + rs.find(text))
        self.assertTrue(nur_presidio.issubset(mit_eigenen),
                        "eigene Regeln haben Abdeckung WEGGENOMMEN")


class TestResolveOverlapsCoverage(unittest.TestCase):
    """Direkt auf _resolve_overlaps -- die Stelle, an der F1 entstand."""

    def test_stronger_short_span_inside_weaker_long_span_keeps_full_span(self):
        text = "Max Mustermann"
        entities = [
            {"entity_type": "PERSON", "start": 0, "end": 14, "score": 0.85},
            {"entity_type": "CUSTOM_KUNDENNAME", "start": 0, "end": 3, "score": 0.9},
        ]
        kept = dg.Masker._resolve_overlaps(entities, len(text))
        self.assertEqual(len(kept), 1)
        self.assertEqual((kept[0]["start"], kept[0]["end"]), (0, 14))
        self.assertEqual(kept[0]["entity_type"], "CUSTOM_KUNDENNAME")

    def test_partial_overlap_masks_the_union(self):
        entities = [
            {"entity_type": "A", "start": 0, "end": 10, "score": 0.9},
            {"entity_type": "B", "start": 5, "end": 20, "score": 0.4},
        ]
        kept = dg.Masker._resolve_overlaps(entities, 30)
        self.assertEqual(len(kept), 1)
        self.assertEqual((kept[0]["start"], kept[0]["end"]), (0, 20))

    def test_chained_overlaps_merge_transitively(self):
        entities = [
            {"entity_type": "A", "start": 0, "end": 6, "score": 0.9},
            {"entity_type": "B", "start": 4, "end": 12, "score": 0.5},
            {"entity_type": "C", "start": 10, "end": 18, "score": 0.6},
        ]
        kept = dg.Masker._resolve_overlaps(entities, 30)
        self.assertEqual(len(kept), 1)
        self.assertEqual((kept[0]["start"], kept[0]["end"]), (0, 18))

    def test_disjoint_spans_stay_separate(self):
        entities = [
            {"entity_type": "A", "start": 0, "end": 5, "score": 0.9},
            {"entity_type": "B", "start": 10, "end": 15, "score": 0.5},
        ]
        kept = dg.Masker._resolve_overlaps(entities, 30)
        self.assertEqual(len(kept), 2)

    def test_adjacent_spans_are_not_merged(self):
        """Direkt aneinandergrenzend ist KEINE Ueberlappung."""
        entities = [
            {"entity_type": "A", "start": 0, "end": 5, "score": 0.9},
            {"entity_type": "B", "start": 5, "end": 10, "score": 0.5},
        ]
        kept = dg.Masker._resolve_overlaps(entities, 30)
        self.assertEqual(len(kept), 2)


# ===========================================================================
# 10. F3 (Security-Audit) — Kaltstart mit kaputter Regeldatei
#
# Bei JEDEM Container-Neustart wird ein frisches RuleSet gebaut. Ist die
# Regeldatei dann beschaedigt, gibt es keinen "letzten guten Regelsatz" --
# es ist schlicht NICHTS aktiv. Frueher war dieser Pfad komplett lautlos und
# die Meldung behauptete das Gegenteil. Ein beschaedigtes Byte haette die
# komplette eigene Maskierungsschicht still abgeschaltet.
# ===========================================================================
class TestColdStartWithBrokenFile(_RuleFileTestCase):
    def _laden_mit_stderr(self):
        fehler = io.StringIO()
        with contextlib.redirect_stderr(fehler):
            rs = cr.RuleSet(self.path)
        return rs, fehler.getvalue()

    def test_cold_start_broken_yaml_says_nothing_is_active(self):
        """Die Meldung muss die WAHRHEIT sagen: es ist nichts aktiv."""
        self.write_raw("rules: [ das ist: kein: gueltiges yaml")
        rs, _ = self._laden_mit_stderr()

        self.assertEqual(rs.active_rules, [])
        self.assertTrue(rs.load_error)
        # Darf NICHT behaupten, ein alter Regelsatz sei noch aktiv.
        self.assertNotIn("zuletzt gueltige", rs.load_error)
        self.assertIn("KEINE", rs.load_error)

    def test_cold_start_broken_yaml_is_loud_on_stderr(self):
        """Lautlos war der eigentliche Defekt -- der Betreiber muss es sehen."""
        self.write_raw("rules: [ kaputt")
        _, stderr = self._laden_mit_stderr()
        self.assertTrue(stderr.strip(), "Kaltstart-Fehler wurde nicht gemeldet")
        self.assertIn("datenschleuse", stderr.lower())

    def test_cold_start_error_names_no_file_content(self):
        """Auch die laute Meldung darf keinen Regelwert leaken (Gesetz 5)."""
        self.write_raw('rules: [ {name: x, value: "Nordwind Sonderprojekt"')
        rs, stderr = self._laden_mit_stderr()
        self.assertNotIn("Nordwind", stderr)
        self.assertNotIn("Nordwind", rs.load_error or "")

    def test_warm_reload_keeps_last_good_and_says_so_truthfully(self):
        """Der von Oliver freigegebene Pfad: hier gibt es einen letzten guten
        Stand, und nur hier darf die Meldung das auch behaupten."""
        self.write_rules([rule("heil", value="Adlerflug")])
        rs, _ = self._laden_mit_stderr()
        self.assertTrue(rs.find("Projekt Adlerflug"))

        time.sleep(0.01)
        self.write_raw("rules: [ jetzt kaputt")
        fehler = io.StringIO()
        with contextlib.redirect_stderr(fehler):
            treffer = rs.find("Projekt Adlerflug")

        self.assertTrue(treffer, "letzter guter Stand wurde verworfen")
        self.assertIn("zuletzt gueltige", rs.load_error)
        self.assertTrue(fehler.getvalue().strip(), "Reload-Fehler war lautlos")

    def test_error_is_not_repeated_on_every_single_request(self):
        """Laut ja -- aber kein Log-Spam bei jedem Request."""
        self.write_raw("rules: [ kaputt")
        rs, _ = self._laden_mit_stderr()
        fehler = io.StringIO()
        with contextlib.redirect_stderr(fehler):
            for _ in range(20):
                rs.find("irgendein Text")
        self.assertEqual(fehler.getvalue(), "")

    def test_recovery_after_fixing_the_file_is_reported(self):
        """Wenn es wieder geht, soll man das auch sehen."""
        self.write_raw("rules: [ kaputt")
        rs, _ = self._laden_mit_stderr()
        self.assertEqual(rs.active_rules, [])

        time.sleep(0.01)
        self.write_rules([rule("heil", value="Adlerflug")])
        fehler = io.StringIO()
        with contextlib.redirect_stderr(fehler):
            treffer = rs.find("Projekt Adlerflug")

        self.assertTrue(treffer)
        self.assertIsNone(rs.load_error)
        self.assertIn("wieder", fehler.getvalue().lower())


class TestGuardrailSurfacesRuleFileError(_RuleFileTestCase,
                                         unittest.IsolatedAsyncioTestCase):
    async def test_guardrail_logs_broken_rule_file_at_startup(self):
        """Der Guardrail wertete load_error frueher NIE aus -- nur die CLI auf
        dem Host tat das. Im Container blieb der Fehler unsichtbar."""
        self.write_raw("{{{ kein yaml")
        fehler = io.StringIO()
        with contextlib.redirect_stderr(fehler):
            guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        self.assertTrue(fehler.getvalue().strip(),
                        "Guardrail meldet die kaputte Regeldatei nicht")
        self.assertIsNotNone(guard.custom_rules)

    async def test_guardrail_startup_quiet_when_file_is_fine(self):
        self.write_rules([rule("heil", value="Adlerflug")])
        fehler = io.StringIO()
        with contextlib.redirect_stderr(fehler):
            dg.DatenschleuseGuardrail(custom_rules_path=self.path)
        self.assertEqual(fehler.getvalue(), "")


# ===========================================================================
# 11. F5 (Security-Audit) — die Temp-Datei des atomaren Schreibens
#
# save_document schreibt ueber eine Temp-Datei und os.replace. Wird der Prozess
# dazwischen hart beendet (SIGKILL, Container-Stop), bleibt sie liegen -- mit
# dem VOLLEN Regelsatz inklusive echter Kundennamen. Das Repo ist oeffentlich.
# ===========================================================================
class TestTempFileIsNotLeaked(unittest.TestCase):
    _REPO = os.path.normpath(os.path.join(_HERE, ".."))

    def test_gitignore_covers_the_temp_file_pattern(self):
        pfad = os.path.join(self._REPO, ".gitignore")
        with open(pfad, encoding="utf-8") as fh:
            inhalt = fh.read()
        self.assertIn("rules/.custom-rules-*.tmp", inhalt)
        self.assertIn("rules/custom-rules.yml", inhalt)

    def test_temp_file_prefix_matches_the_ignored_pattern(self):
        """Der Praefix im Code und das Muster in .gitignore muessen
        zusammenpassen -- sonst schuetzt die Zeile nichts."""
        with open(os.path.join(self._REPO, "litellm", "custom_rules.py"),
                  encoding="utf-8") as fh:
            quelle = fh.read()
        self.assertIn('prefix=".custom-rules-"', quelle)
        self.assertIn('suffix=".tmp"', quelle)

    def test_written_rules_file_is_owner_only(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        pfad = os.path.join(d.name, "custom-rules.yml")
        cr.add_rule(pfad, rule("k", value="Adlerflug"))
        self.assertEqual(os.stat(pfad).st_mode & 0o777, 0o600)


# ===========================================================================
# 12. F7 (Security-Audit) — der Kategoriename reist zum Anbieter mit
#
# Der Entitaetsname landet WOERTLICH im Platzhalter (<CUSTOM_<ENTITY>_0>) und
# geht damit an den LLM-Anbieter. Wer seine Kategorie nach dem Kunden benennt
# -- die naheliegendste Sache der Welt -- maskiert den Wert und verschickt den
# Namen trotzdem. Der eigene Schutz ist damit aufgehoben.
# ===========================================================================
class TestEntityNameDoesNotLeakTheSecret(_RuleFileTestCase):
    def test_entity_named_after_the_customer_is_rejected(self):
        with self.assertRaises(cr.RuleError):
            cr.build_rule(rule("kunde", entity="Nordwind Logistik GmbH",
                               value="Nordwind Logistik GmbH",
                               examples=["Vertrag mit Nordwind Logistik GmbH"]))

    def test_entity_sharing_any_token_with_the_value_is_rejected(self):
        with self.assertRaises(cr.RuleError):
            cr.build_rule(rule("kunde", entity="Projekt Adlerflug",
                               value="Adlerflug",
                               examples=["Projekt Adlerflug laeuft"]))

    def test_rejection_message_names_the_risk_without_echoing_the_value(self):
        try:
            cr.build_rule(rule("kunde", entity="Nordwind",
                               value="Nordwind Logistik",
                               examples=["Kunde Nordwind Logistik"]))
        except cr.RuleError as exc:
            self.assertNotIn("Nordwind Logistik", str(exc))
        else:
            self.fail("Regel haette abgelehnt werden muessen")

    def test_generic_category_names_still_work(self):
        """Die Validierung darf die normale Benutzung nicht behindern."""
        for entity, value in [
            ("Kundenname", "Nordwind Logistik"),
            ("Projektname", "Adlerflug"),
            ("Projektnummer", "PRJ-1234"),
            ("Mandant", "KD-ABC"),
            ("Produktname", "Windrose Classic"),
        ]:
            regel = cr.build_rule(rule("r", entity=entity, value=value,
                                       examples=[f"Text mit {value} drin"]))
            self.assertEqual(regel.entity, entity)

    def test_overly_long_entity_name_is_rejected(self):
        """Ein Kategoriename ist ein Wort, kein Satz -- alles andere ist ein
        Hinweis darauf, dass hier Inhalt statt Kategorie steht."""
        with self.assertRaises(cr.RuleError):
            cr.build_rule(rule("r", entity="Der grosse Kunde aus dem Norden mit "
                                           "dem langen Namen", value="Adlerflug"))

    def test_rule_with_leaking_entity_is_quarantined_not_active(self):
        """Auch von Hand eingetragen darf so eine Regel nicht live gehen."""
        self.write_rules([rule("leaky", entity="Adlerflug", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        self.assertEqual(rs.active_rules, [])
        self.assertEqual([q.name for q in rs.quarantined], ["leaky"])

    def test_placeholder_of_a_valid_rule_carries_no_secret(self):
        self.write_rules([rule("kunde", entity="Kundenname",
                               value="Nordwind Logistik",
                               examples=["Kunde Nordwind Logistik meldet sich"])])
        rs = cr.RuleSet(self.path)
        text = "Vertrag mit Nordwind Logistik unterschrieben"
        maskiert = dg.Masker().mask(text, rs.find(text))
        self.assertNotIn("Nordwind", maskiert)
        self.assertNotIn("Logistik", maskiert)
        self.assertIn("<CUSTOM_KUNDENNAME_0>", maskiert)


# ===========================================================================
# 13. F2 (Security-Audit) — das Zeitbudget gilt pro REQUEST, nicht pro Regel
#
# Mit einem Budget pro Regel summierte sich die Wartezeit: 20 pathologische
# Muster = 20 x 0,25 s = 5 s pro Text. Und weil find() synchrone CPU-Arbeit
# ist, blockiert sie waehrenddessen den asyncio-Event-Loop -- also auch
# fremde, parallel laufende Requests.
# ===========================================================================
class TestMatchBudgetIsPerCall(_RuleFileTestCase):
    def test_many_pathological_rules_stay_within_one_budget(self):
        regeln = [
            rule(f"redos-{i}", entity="MUELL", kind="regex", value=r"(a|a)*$",
                 examples=["aaaaaaaaaa"])
            for i in range(10)
        ]
        regeln.append(rule("heil", value="Adlerflug"))
        self.write_rules(regeln)
        rs = cr.RuleSet(self.path, match_timeout=0.2)

        boese = "a" * 44 + "b Projekt Adlerflug"
        start = time.monotonic()
        with self.assertRaises(cr.RuleMatchingIncomplete):
            rs.find(boese)
        dauer = time.monotonic() - start

        self.assertLess(dauer, 1.0,
                        f"Budget summierte sich auf {dauer:.2f}s statt gedeckelt zu sein")

    def test_pathological_rule_only_affects_texts_that_trigger_it(self):
        """Eine pathologische Regel kostet nur die Texte, die sie ausloesen --
        nicht den Betrieb. Texte ohne das Ausloesemuster laufen normal."""
        self.write_rules([
            rule("heil", value="Adlerflug"),
            rule("redos", entity="MUELL", kind="regex", value=r"(a|a)*$",
                 examples=["aaaaaaaaaa"]),
        ])
        rs = cr.RuleSet(self.path, match_timeout=0.2)
        # Harmloser Text: laeuft durch, obwohl die ReDoS-Regel geladen ist.
        self.assertEqual(self.matched_values(rs, "Projekt Adlerflug laeuft"),
                         ["Adlerflug"])
        # Ausloesender Text: sichtbarer Block statt stiller Teil-Maskierung.
        with self.assertRaises(cr.RuleMatchingIncomplete):
            rs.find("a" * 44 + "b Projekt Adlerflug")

    def test_normal_ruleset_is_not_slowed_down(self):
        self.write_rules([rule(f"r{i}", value=f"Begriff{i}",
                               examples=[f"Text Begriff{i} hier"])
                          for i in range(30)])
        rs = cr.RuleSet(self.path)
        start = time.monotonic()
        rs.find("Ein ganz normaler Satz mit Begriff7 darin.")
        self.assertLess(time.monotonic() - start, 0.5)


# ===========================================================================
# 14. F6 (Security-Audit) — der Setup-Weg per `cp` erzeugt 0664
#
# save_document schreibt 0600. Wer die Beispieldatei aber per `cp` kopiert,
# bekommt die Rechte der Umask (typisch 0664) -- die Regeldatei mit echten
# Kundennamen ist dann fuer jeden Benutzer der Maschine lesbar, ohne Warnung.
# ===========================================================================
class TestFilePermissionWarning(_RuleFileTestCase):
    def test_group_readable_file_is_flagged(self):
        self.write_rules([rule("k", value="Adlerflug")])
        os.chmod(self.path, 0o664)
        self.assertTrue(cr.permission_warning(self.path))

    def test_owner_only_file_is_not_flagged(self):
        self.write_rules([rule("k", value="Adlerflug")])
        os.chmod(self.path, 0o600)
        self.assertIsNone(cr.permission_warning(self.path))

    def test_missing_file_is_not_flagged(self):
        self.assertIsNone(cr.permission_warning(
            os.path.join(self._dir.name, "gibt-es-nicht.yml")))

    def test_warning_names_the_fix_command(self):
        self.write_rules([rule("k", value="Adlerflug")])
        os.chmod(self.path, 0o644)
        self.assertIn("chmod 600", cr.permission_warning(self.path))

    def test_describe_carries_the_warning(self):
        self.write_rules([rule("k", value="Adlerflug")])
        os.chmod(self.path, 0o664)
        self.assertTrue(cr.RuleSet(self.path).describe()["permission_warning"])


# ===========================================================================
# 15. F8 (Security-Audit) — Teil-Maskierung darf es nicht geben
#
# Der F2-Fix teilte das Budget nach ANZAHL statt nach BEDARF (rest/offen).
# Eine harmlose term-Regel an Position 1 von 30 bekam 1/31 des Budgets,
# obwohl die uebrigen 30 fast nichts brauchten -- bei vielen Treffern lief
# sie ins Timeout. Und ``except TimeoutError`` behielt die bereits
# gesammelten Treffer: ein TEILERGEBNIS wurde als vollstaendig behandelt.
# Der Text sah korrekt maskiert aus, waehrend die Haelfte im Klartext ging.
# ===========================================================================
class TestPartialMatchingNeverLeaks(_RuleFileTestCase):
    KUNDE = "Nordwind Logistik"

    def _regelsatz(self, kunde_zuerst, n=30):
        kunde = rule("kunde", entity="Kundenname", value=self.KUNDE,
                     examples=[f"Kunde {self.KUNDE} meldet sich"])
        fueller = [rule(f"fuell{i}", entity="Sonstiges", value=f"Begriff{i}",
                        examples=[f"Text Begriff{i} hier"]) for i in range(n)]
        return [kunde] + fueller if kunde_zuerst else fueller + [kunde]

    def _kunden_treffer(self, rs, text):
        return [t for t in rs.find(text)
                if t["entity_type"] == "CUSTOM_KUNDENNAME"]

    def test_all_occurrences_masked_with_rule_in_first_position(self):
        """Das Leck: Regel an Position 1 von 30, 2000 Vorkommen."""
        text = (self.KUNDE + " ") * 2000
        self.write_rules(self._regelsatz(kunde_zuerst=True))
        rs = cr.RuleSet(self.path)
        self.assertEqual(len(self._kunden_treffer(rs, text)), 2000)

    def test_rule_position_does_not_change_the_result(self):
        """Die Position einer Regel in der Datei darf den Schutz nicht
        beeinflussen -- das war der einzige Unterschied im Auditor-Befund."""
        text = (self.KUNDE + " ") * 2000

        self.write_rules(self._regelsatz(kunde_zuerst=True))
        zuerst = len(self._kunden_treffer(cr.RuleSet(self.path), text))

        time.sleep(0.01)
        self.write_rules(self._regelsatz(kunde_zuerst=False))
        zuletzt = len(self._kunden_treffer(cr.RuleSet(self.path), text))

        self.assertEqual(zuerst, zuletzt)
        self.assertEqual(zuerst, 2000)

    def test_budget_is_not_wasted_on_healthy_rules(self):
        """96 % des Budgets lagen ungenutzt, waehrend abgeschnitten wurde."""
        text = (self.KUNDE + " ") * 2000
        self.write_rules(self._regelsatz(kunde_zuerst=True, n=100))
        rs = cr.RuleSet(self.path)
        start = time.monotonic()
        treffer = self._kunden_treffer(rs, text)
        dauer = time.monotonic() - start
        self.assertEqual(len(treffer), 2000)
        self.assertLess(dauer, 1.0)

    def test_timeout_never_returns_a_partial_result(self):
        """Wenn die Zeit doch nicht reicht: lieber sichtbar blocken als still
        halb maskieren. Ein Teilergebnis sieht korrekt aus und ist es nicht."""
        self.write_rules([rule("kunde", entity="Kundenname", value=self.KUNDE,
                               examples=[f"Kunde {self.KUNDE} meldet sich"])])
        rs = cr.RuleSet(self.path)
        rs.match_timeout = 0.0000001  # erst NACH dem Laden, sonst Quarantaene
        with self.assertRaises(cr.RuleMatchingIncomplete):
            rs.find((self.KUNDE + " ") * 5000)

    def test_attack_scenario_many_occurrences_never_leaks(self):
        """Angriff: Client kennt eine Regel und flutet den Text mit dem Wert."""
        text = (self.KUNDE + " ") * 4000
        self.write_rules(self._regelsatz(kunde_zuerst=True, n=20))
        rs = cr.RuleSet(self.path)
        try:
            treffer = self._kunden_treffer(rs, text)
        except cr.RuleMatchingIncomplete:
            return  # sichtbarer Block ist ein zulaessiger Ausgang
        maskiert = dg.Masker().mask(text, treffer)
        self.assertNotIn(self.KUNDE, maskiert,
                         "Werte sind im Klartext hinausgegangen")


# ===========================================================================
# 16. Integration mit dem Verifikationsdurchlauf aus DATENSCHLE-66
#
# _verify_no_pii_left schickt den FERTIG maskierten String noch einmal durch
# _analyze -- also durch den Pfad, in dem auch die eigenen Regeln haengen.
# Ein Rest-Treffer dort blockt den Request. Die Sorge war: eigene Regeln
# koennten auf den Platzhaltern selbst anschlagen und damit korrekt maskierte
# Anfragen grundlos lahmlegen.
#
# DATENSCHLE-66 neutralisiert die bekannten Platzhalter vorher mit einem
# Leerzeichen (_PLACEHOLDER_PROBE_FILLER). Diese Tests MESSEN, ob das
# ausreicht -- hergeleitet war es, belegt bisher nicht.
# ===========================================================================
class TestVerificationPassInteraction(_RuleFileTestCase,
                                      unittest.IsolatedAsyncioTestCase):
    async def _guard_ohne_presidio(self):
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def keine_treffer(text, payload=None):
            return []

        guard._presidio_analyze = keine_treffer
        return guard

    async def test_fall1_breites_grossbuchstaben_muster_blockt_nicht(self):
        """Fall 1: '[A-Z]{5,}' wuerde CUSTOM und KUNDENNAME im Platzhalter
        treffen, wenn nicht neutralisiert wuerde."""
        self.write_rules([rule(
            "breit", entity="Kuerzel", kind="regex", value=r"[A-Z]{5,}",
            examples=["Das Kuerzel ABCDEF steht hier"],
        )])
        guard = await self._guard_ohne_presidio()

        # WICHTIG: echt maskieren lassen statt den maskierten Text zu
        # erfinden. Was die Regel im ersten Durchlauf trifft, ist danach
        # ersetzt -- ein handgebauter String wuerde einen Defekt vortaeuschen,
        # den die Pipeline gar nicht erzeugen kann.
        text = "Vertrag mit Nordwind Logistik geschlossen."
        masker = dg.Masker()
        maskiert = masker.mask(text, await guard._analyze(text))

        await guard._verify_no_pii_left(maskiert, masker)  # darf NICHT werfen

    async def test_fall2_regel_die_ueber_den_filler_hinweg_greift(self):
        r"""Fall 2: Verkleben. Das Leerzeichen trennt zwar, aber ein Muster
        mit \s* ueberspannt es trotzdem.

        NEUBEWERTET IM RE-AUDIT (S1-R), Entscheidung des Leads: Dieser Fall
        blockt jetzt -- und das ist gewollt. Ein Muster, das ueber einen
        Platzhalter hinweggreift, ist nicht von der Konstruktion zu
        unterscheiden, mit der man die Maskierung umgeht (Telefonnummer mit
        eingeklebtem Platzhalter). Ein SICHTBARER Fehlalarm ist billiger als
        ein stilles Leck.

        Betroffen ist nur ein enger Fall: eine eigene REGEX-Regel, deren
        Muster sowohl MIT als auch OHNE den Trenner passt. Deny-Listen (der
        Standardtyp) koennen das prinzipiell nicht. Gemessen am
        Presidio-Testkorpus: 0 von 45 Faellen betroffen.
        """
        self.write_rules([rule(
            "verklebt", entity="Firmenname", kind="regex", value=r"Nord\s*wind",
            examples=["Die Nord wind Gruppe"],
        )])
        guard = await self._guard_ohne_presidio()

        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"
        maskiert = "Nord<PERSON_0>wind"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(maskiert, masker)

    async def test_fall3_regel_die_den_filler_selbst_erfasst(self):
        """Fall 3: aneinandergrenzende Platzhalter werden zu einer
        Leerzeichenkette, die ein Whitespace-Muster erfasst."""
        self.write_rules([rule(
            "whitespace", entity="Formatierung", kind="regex", value=r"\s{3,}",
            examples=["a   b"],
        )])
        guard = await self._guard_ohne_presidio()

        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"
        masker.reid_map["<PERSON_1>"] = "Erika"
        masker.reid_map["<PERSON_2>"] = "Anna"
        # DREI angrenzende Platzhalter -> drei Leerzeichen -> \s{3,} greift.
        maskiert = "<PERSON_0><PERSON_1><PERSON_2>"

        try:
            await guard._verify_no_pii_left(maskiert, masker)
        except dg.DatenschleuseBlocked as exc:
            self.fail(f"grundloser Block durch Filler-Kette: {exc}")

    async def test_echter_rest_wird_weiterhin_geblockt(self):
        """Gegenprobe: die Nachpruefung darf durch den Filter nicht stumpf
        geworden sein. Ein PRESIDIO-Rest muss weiterhin blocken -- nur die
        eigenen Regeln sind ausgenommen, nicht die Erkennung als solche."""
        self.write_rules([rule("kunde", entity="Kundenname",
                               value="Nordwind Logistik",
                               examples=["Kunde Nordwind Logistik meldet sich"])])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def presidio_findet_rest(text, payload=None):
            i = text.find("Max Mustermann")
            if i < 0:
                return []
            return [{"entity_type": "PERSON", "start": i,
                     "end": i + len("Max Mustermann"), "score": 0.9}]

        guard._presidio_analyze = presidio_findet_rest

        masker = dg.Masker()
        masker.reid_map["<CUSTOM_KUNDENNAME_0>"] = "Nordwind Logistik"
        # Der Name ist NICHT maskiert -> muss auffallen.
        maskiert = "<CUSTOM_KUNDENNAME_0> und Max Mustermann"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(maskiert, masker)

    async def test_filter_haengt_an_der_herkunft_nicht_am_typ(self):
        """Regressionsschutz fuer Finding F10.

        Der Filter MUSS an der Fueller-Herkunft haengen, nicht am
        entity_type. Ein Praefix-Filter sieht einfacher aus, nimmt aber auch
        ECHTE Funde aus der Pruefung -- und zwar ausgerechnet die eigenen,
        fuer die dieses Netz allein zustaendig ist. Wer hier zurueckbaut,
        soll an diesem Test scheitern und nicht erst am naechsten Audit.
        """
        with open(os.path.join(_HERE, "..", "litellm",
                               "datenschleuse_guardrail.py"),
                  encoding="utf-8") as fh:
            quelle = fh.read()
        start = quelle.index("async def _verify_no_pii_left")
        koerper = quelle[start:start + 6000]
        self.assertIn("_is_filler_artifact", koerper)
        self.assertNotIn("startswith(cur.ENTITY_PREFIX)", koerper)

    async def test_verifikation_wertet_typen_aus_nicht_zaehlungen(self):
        """Punkt 3 des Leads: meine F1-Union verschmilzt zwei Entitaeten zu
        EINEM Platzhalter. Wertet die Nachpruefung Zaehlungen aus, saehe das
        wie eine Diskrepanz aus. Am Code belegt: sie bildet eine Menge der
        entity_type-Werte, zaehlt also nicht."""
        with open(os.path.join(_HERE, "..", "litellm",
                               "datenschleuse_guardrail.py"),
                  encoding="utf-8") as fh:
            quelle = fh.read()
        start = quelle.index("async def _verify_no_pii_left")
        koerper = quelle[start:start + 6000]
        self.assertIn("{str(e.get(\"entity_type\")) for e in leftovers}", koerper)
        self.assertNotIn("len(leftovers)", koerper)


# ===========================================================================
# 17. F10/F13 (Security-Audit) — das Sicherheitsnetz darf nicht durchloechert
#     werden
#
# Der erste F9-Fix filterte nach entity_type-Praefix CUSTOM_. Das schloss den
# Fehlalarm-Raum, blendete den Verifikationsdurchlauf aber VOLLSTAENDIG fuer
# eigene Entitaeten aus -- ausgerechnet fuer die Werte, die sonst gar nichts
# erkennt. Der Docstring nennt die Pruefung "die einzige, die unabhaengig vom
# Pfad greift"; fuer Custom-Entitaeten war sie das nicht mehr.
#
# Richtig ist, nach der HERKUNFT zu filtern statt nach dem Typ: Treffer, deren
# Span einen Fuellerbereich schneidet, sind Artefakte der Neutralisierung.
# Die Fuellerpositionen kennen wir -- wir setzen sie selbst.
# ===========================================================================
class TestVerificationNetStaysSharpForCustom(_RuleFileTestCase,
                                             unittest.IsolatedAsyncioTestCase):
    async def _guard(self, presidio=None):
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def keine(text, payload=None):
            return []

        guard._presidio_analyze = presidio or keine
        return guard

    async def test_unmasked_custom_value_still_blocks(self):
        """Der Kern von F10: ein NICHT maskierter eigener Wert im Ergebnis
        muss auffallen -- sonst schuetzt das Netz genau dort nicht, wo es
        allein zustaendig ist."""
        self.write_rules([rule("kunde", entity="Kundenname",
                               value="Nordwind Logistik",
                               examples=["Kunde Nordwind Logistik meldet sich"])])
        guard = await self._guard()

        masker = dg.Masker()
        masker.reid_map["<CUSTOM_KUNDENNAME_0>"] = "Nordwind Logistik"
        maskiert = "<CUSTOM_KUNDENNAME_0> und Nordwind Logistik"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(maskiert, masker)

    async def test_verklebtes_muster_blockt_nach_s1r(self):
        r"""Frueher Gegenprobe 1 ("der Fehlalarm bleibt weg"), im Re-Audit
        umgedreht: ein Muster, das MIT und OHNE Trenner passt, blockt jetzt.
        Siehe die ausfuehrliche Begruendung an
        test_fall2_regel_die_ueber_den_filler_hinweg_greift.

        Der Fehlalarm-Raum, den F9 urspruenglich schliessen sollte, bleibt
        fuer den haeufigen Fall geschlossen -- siehe die naechste
        Gegenprobe (Fuellerkette)."""
        self.write_rules([rule("verklebt", entity="Firmenname", kind="regex",
                               value=r"Nord\s*wind",
                               examples=["Die Nord wind Gruppe"])])
        guard = await self._guard()
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("Nord<PERSON_0>wind", masker)

    async def test_filler_chain_artifact_still_does_not_block(self):
        """Gegenprobe 2: Leerzeichenkette aus angrenzenden Platzhaltern."""
        self.write_rules([rule("ws", entity="Formatierung", kind="regex",
                               value=r"\s{3,}", examples=["a   b"])])
        guard = await self._guard()
        masker = dg.Masker()
        for i, name in enumerate(("Max", "Erika", "Anna")):
            masker.reid_map[f"<PERSON_{i}>"] = name
        await guard._verify_no_pii_left("<PERSON_0><PERSON_1><PERSON_2>", masker)

    async def test_presidio_leftover_still_blocks(self):
        """Gegenprobe 3: die Presidio-Seite bleibt unveraendert scharf."""
        async def presidio(text, payload=None):
            i = text.find("Max Mustermann")
            return ([] if i < 0 else
                    [{"entity_type": "PERSON", "start": i,
                      "end": i + 14, "score": 0.9}])

        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard(presidio)
        masker = dg.Masker()
        masker.reid_map["<CUSTOM_KUNDENNAME_0>"] = "Adlerflug"
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(
                "<CUSTOM_KUNDENNAME_0> und Max Mustermann", masker)

    async def test_f13_presidio_recognizer_named_custom_is_not_skipped(self):
        """F13: Ein Presidio-Recognizer mit dem Namen CUSTOM_* fiel beim
        Praefix-Filter still aus der Pruefung. Der Namensraum ist geteilt --
        die Herkunft darf nicht am Namen haengen."""
        async def presidio(text, payload=None):
            i = text.find("GEHEIM")
            return ([] if i < 0 else
                    [{"entity_type": "CUSTOM_LEGACY_ID", "start": i,
                      "end": i + 6, "score": 0.9}])

        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard(presidio)
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("<PERSON_0> hat GEHEIM genannt",
                                            masker)

    async def test_leftover_adjacent_to_filler_still_blocks(self):
        """Grenzfall: ein echter Fund direkt NEBEN einem Fueller ueberlappt
        ihn nicht und muss erhalten bleiben."""
        self.write_rules([rule("kunde", entity="Kundenname", value="Adlerflug",
                               examples=["Projekt Adlerflug laeuft"])])
        guard = await self._guard()
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("<PERSON_0>Adlerflug", masker)


# ===========================================================================
# 18. F11 (Security-Audit) — dieselbe Klasse wie F8
#
# Wirft finditer mitten im Scan einen NICHT-Timeout-Fehler, wurde die Regel
# still uebersprungen und der Request ging raus. Die Abdeckung ist dabei
# genauso unbekannt wie beim Timeout -- drei Zeilen ueber der fail-closed-
# Behandlung stand die fail-open-Behandlung derselben Frage.
# ===========================================================================
class TestScanErrorIsFailClosed(_RuleFileTestCase):
    class _Boom:
        def finditer(self, text, timeout=None):
            raise ValueError("Scan mittendrin abgebrochen")

    def test_non_timeout_scan_error_blocks(self):
        self.write_rules([rule("kunde", entity="Kundenname", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        rs.active_rules  # Laden erzwingen
        rs._active[0].pattern = self._Boom()
        with self.assertRaises(cr.RuleMatchingIncomplete):
            rs.find("Projekt Adlerflug laeuft")

    def test_scan_error_does_not_silently_drop_the_rule(self):
        """Auch mit einer gesunden Regel daneben: kein Teilergebnis."""
        self.write_rules([
            rule("kaputt", entity="Kundenname", value="Adlerflug"),
            rule("heil", entity="Sonstiges", value="Seewind",
                 examples=["Kunde Seewind meldet sich"]),
        ])
        rs = cr.RuleSet(self.path)
        rs.active_rules
        rs._active[0].pattern = self._Boom()
        with self.assertRaises(cr.RuleMatchingIncomplete):
            rs.find("Projekt Adlerflug mit Seewind")


# ===========================================================================
# 19. F12 — ehrliche Meldung bei sehr grossen Texten
# ===========================================================================
class TestBudgetMessageIsHonest(_RuleFileTestCase):
    def test_message_does_not_only_blame_a_pathological_pattern(self):
        """Ab einigen MB Text reisst schon die erste harmlose Regel das
        Budget. Die Meldung darf den Betreiber dann nicht auf die Suche nach
        einem Muster schicken, das es nicht gibt."""
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        rs.match_timeout = 0.0000001
        try:
            rs.find("Projekt Adlerflug " * 200)
        except cr.RuleMatchingIncomplete as exc:
            meldung = str(exc).lower()
            self.assertIn("grosser text", meldung,
                          f"Meldung nennt die Textgroesse nicht als moegliche "
                          f"Ursache: {exc}")
            self.assertIn("zeichen", meldung,
                          f"Meldung nennt die konkrete Textgroesse nicht: {exc}")
        else:
            self.fail("kein fail-closed ausgeloest")


# ===========================================================================
# 20. S1 (Security-Audit, HIGH) — der Fueller-Filter darf keine ECHTEN Funde
#     fressen
#
# Der F10-Fix verwirft einen Treffer, sobald IRGENDEIN Fueller in seinem
# getrimmten Kern liegt -- ohne je zu pruefen, ob die Nicht-Fueller-Anteile
# fuer sich genommen PII sind. Das ist eine REGRESSION gegenueber dem
# Praefix-Filter: der behielt PERSON und blockte. Der blinde Fleck war
# vorher auf CUSTOM_* begrenzt, mit dem Span-Filter gilt er fuer JEDEN Typ.
#
#   "Anna <PERSON_0> Mueller"  ->  Probe "Anna   Mueller"  ->  KEIN BLOCK
#   "Anna<PERSON_0>Mueller"    ->  Probe "Anna Mueller"    ->  KEIN BLOCK
#
# Der bestehende Gegenprobe-Test trifft den Fall NICHT: dort steht " und "
# zwischen Platzhalter und Restnamen, der Span schneidet den Fueller also
# gerade nicht. Hier ueberspannt er ihn wirklich.
#
# Richtig ist: den Treffer an den Fuellergrenzen aufteilen und die Segmente
# erneut durch _analyze schicken. Bleibt ein Segment fuer sich ein Fund, ist
# es kein Artefakt. "Nord" und "wind" einzeln sind kein Fund -> verwerfen.
# "Anna" und "Mueller" einzeln sind PERSON -> blocken.
# ===========================================================================
# Mini-Analyzer, der sich wie Presidio verhaelt: er findet den Namen auch
# ueber mehrere Leerzeichen hinweg, weil die Tokenisierung Whitespace
# zusammenfasst. Genau daraus entsteht der ueberspannende Treffer.
_NAME_RE = re.compile(r"\bAnna(?:\s+Mueller)?\b|\bMueller\b|\bLisa\s+Weber\b")


class TestFillerFilterKeepsRealFindings(_RuleFileTestCase,
                                        unittest.IsolatedAsyncioTestCase):
    async def _guard(self):
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def presidio(text, payload=None):
            return [{"entity_type": "PERSON", "start": m.start(),
                     "end": m.end(), "score": 0.9}
                    for m in _NAME_RE.finditer(text)]

        guard._presidio_analyze = presidio
        return guard

    async def test_fund_der_einen_fueller_ueberspannt_blockt(self):
        """Der Kern von S1: der Treffer UEBERSPANNT den Fueller. Links und
        rechts davon steht echter Klartext -- der Fund ist real."""
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard()
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("Anna <PERSON_0> Mueller", masker)

    async def test_eingeklebter_platzhalter_blockt(self):
        """Ohne trennende Leerzeichen: der Platzhalter macht den Namen im
        ROHTEXT fuer die Tokenisierung unlesbar (erster Durchlauf greift
        nicht), im Probe-String wird er zum Leerzeichen und der Name wird
        sichtbar. Genau dieser Fund darf nicht als Artefakt gelten."""
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard()
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("Anna<PERSON_0>Mueller", masker)

    async def test_decoy_erzwungener_platzhalter_blockt(self):
        """Das Angriffsszenario des Auditors: ein Decoy erzwingt die Erzeugung
        von <PERSON_0> (Nummerierung ab 0, deterministisch vorhersagbar), der
        eingeklebte Platzhalter schmuggelt den echten Namen vorbei."""
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard()
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Lisa Weber"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(
                "Kontakt <PERSON_0>. Anna<PERSON_0>Mueller", masker)

    async def test_artefakt_ohne_klartext_im_kern_bleibt_artefakt(self):
        """Gegenprobe zur Aufteilung, im Re-Audit praezisiert.

        Verworfen wird ein Treffer nur noch, wenn sein Kern KEINEN Klartext
        traegt -- dann gibt es weder Segmente noch einen verklebten Kern, den
        man pruefen koennte. Das ist der haeufige Artefaktfall: benachbarte
        Platzhalter werden zu einer Leerzeichenkette, ein Whitespace-Muster
        greift darauf. Er kostet keinen einzigen Analyzer-Aufruf.

        Der frueher hier gepruefte Fall (Nord\\s*wind ueber einem Fueller)
        blockt nach S1-R bewusst -- siehe
        test_fall2_regel_die_ueber_den_filler_hinweg_greift."""
        self.write_rules([rule("ws", entity="Formatierung", kind="regex",
                               value=r"\s{3,}", examples=["a   b"])])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        aufrufe = []

        async def keine(text, payload=None):
            aufrufe.append(text)
            return []

        guard._presidio_analyze = keine
        masker = dg.Masker()
        for i, name in enumerate(("Max", "Erika", "Anna")):
            masker.reid_map[f"<PERSON_{i}>"] = name
        await guard._verify_no_pii_left("<PERSON_0><PERSON_1><PERSON_2>",
                                        masker)
        self.assertEqual(len(aufrufe), 1,
                         "reiner Fuellertreffer darf keine Nachpruefung "
                         "kosten")


# ===========================================================================
# 21. S3 (Security-Audit, LOW) — degenerierte Spans sind kein Artefakt
#
# Nach dem Clamping fielen verdrehte (start > end) und ausserhalb des Textes
# liegende Spans in denselben Zweig wie ein reiner Whitespace-Treffer und
# galten damit als Artefakt. Das widerspricht dem Kommentar acht Zeilen
# darueber ("im Zweifel blocken"): ein unlesbarer Treffer wird still
# geschluckt, statt fail-closed zu wirken.
# ===========================================================================
class TestDegenerateSpanIsNotAnArtifact(_RuleFileTestCase,
                                        unittest.IsolatedAsyncioTestCase):
    async def _guard(self, span):
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def presidio(text, payload=None):
            return [{"entity_type": "PERSON", "start": span[0],
                     "end": span[1], "score": 0.9}]

        guard._presidio_analyze = presidio
        return guard

    def _masker(self):
        masker = dg.Masker()
        # WICHTIG: ein Platzhalter MUSS drin sein, sonst ist filler_spans leer
        # und der Klassifizierer wird gar nicht erst befragt.
        masker.reid_map["<PERSON_0>"] = "Max"
        return masker

    async def test_verdrehter_span_blockt(self):
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard((9, 3))
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("<PERSON_0> Text", self._masker())

    async def test_span_ausserhalb_des_textes_blockt(self):
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard((500, 600))
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("<PERSON_0> Text", self._masker())


# ===========================================================================
# 22. S4 (Security-Audit, LOW) — _build_probe darf nicht endlos laufen
#
# Ein leerer Schluessel im reid_map macht ``text.startswith("", i)`` immer
# wahr; der Index rueckt nie vor und die Schleife laeuft ewig weiter (und
# frisst dabei Speicher). Ein leerer Platzhalter ist kein Platzhalter.
# ===========================================================================
class TestProbeBuilderTerminates(unittest.TestCase):
    def test_leerer_schluessel_haengt_nicht(self):
        reid_map = {"": "irgendwas", "<PERSON_0>": "Max"}
        # Das "<" ohne folgenden Platzhalter ist der Ausloeser: die Vorpruefung
        # auf das Anfangszeichen greift, kein echter Schluessel passt -- und
        # der leere Schluessel passt immer.
        text = "a < b <PERSON_0> c"

        def wecker(signum, frame):
            raise TimeoutError("_build_probe terminiert nicht")

        alt = signal.signal(signal.SIGALRM, wecker)
        signal.setitimer(signal.ITIMER_REAL, 0.25)
        try:
            probe, fueller = dg._build_probe(text, reid_map)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, alt)

        self.assertEqual(probe, "a < b   c")
        self.assertEqual(fueller, [(6, 7)])


# ===========================================================================
# 23. S2 (Security-Audit, MEDIUM) — F11 greift nicht auf allen Abbruchpfaden
#
# Der Aufbau der Ergebnis-Dicts wurde fuer F8 bewusst aus dem ``try`` in den
# ``else:``-Block verschoben -- und hat dort KEINEN Handler. Reisst es dort
# (MemoryError, OSError, RuntimeError), verlaesst die Ausnahme find() als
# etwas anderes als RuleMatchingIncomplete und laeuft im Guardrail weiter in
# den fail-OPEN-Handler: Folgeregeln abgebrochen, Abdeckung unbekannt,
# Request geht raus. Exakt die Klasse, die F11 gerade verworfen hat.
# ===========================================================================
class _KaputterSpan:
    """Ein Span, der beim Entpacken im Ergebnisaufbau reisst -- also NACH dem
    Scan, ausserhalb des bisherigen try."""

    def __iter__(self):
        raise MemoryError("kein Speicher fuer die Ergebnisliste")


class _MatchMitKaputtemSpan:
    def span(self):
        return _KaputterSpan()


class _PatternDasNachDemScanReisst:
    def finditer(self, text, timeout=None):
        return [_MatchMitKaputtemSpan()]


class TestPostScanErrorIsFailClosed(_RuleFileTestCase):
    def test_fehler_beim_ergebnisaufbau_wird_zu_incomplete(self):
        """find() darf diese Klasse nur als RuleMatchingIncomplete verlassen --
        alles andere landet im fail-open-Handler."""
        self.write_rules([rule("kunde", entity="Kundenname", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        rs.active_rules  # Laden erzwingen
        rs._active[0].pattern = _PatternDasNachDemScanReisst()
        with self.assertRaises(cr.RuleMatchingIncomplete):
            rs.find("Projekt Adlerflug laeuft")


class TestPostScanErrorBlocksRequest(_RuleFileTestCase,
                                     unittest.IsolatedAsyncioTestCase):
    async def test_analyze_blockt_statt_still_zu_ueberspringen(self):
        """Ende zu Ende: derselbe Fehler muss den Request blocken."""
        self.write_rules([rule("kunde", entity="Kundenname", value="Adlerflug")])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def keine(text, payload=None):
            return []

        guard._presidio_analyze = keine
        guard.custom_rules.active_rules  # Laden erzwingen
        guard.custom_rules._active[0].pattern = _PatternDasNachDemScanReisst()

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._analyze("Projekt Adlerflug laeuft")

    async def test_ladefehler_bleibt_fail_open(self):
        """Die Gegengrenze (ISC-26): ein Fehler beim LADEN der Regeldatei ist
        etwas anderes -- dort ist die Abdeckung bekannt (die Regeln greifen
        eben nie), und die Presidio-Maskierung darf davon nicht mitgerissen
        werden. Wer S2 zu weit fixt, scheitert an diesem Test."""
        self.write_rules([rule("kunde", entity="Kundenname", value="Adlerflug")])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def presidio(text, payload=None):
            return [{"entity_type": "PERSON", "start": 0, "end": 3,
                     "score": 0.9}]

        guard._presidio_analyze = presidio

        def kaputtes_laden():
            raise OSError("Regeldatei unlesbar")

        guard.custom_rules._reload_if_changed = kaputtes_laden

        with contextlib.redirect_stderr(io.StringIO()):
            treffer = await guard._analyze("Projekt Adlerflug laeuft")
        self.assertEqual(len(treffer), 1,
                         "Presidio-Maskierung wurde mitgerissen (ISC-26)")


# ===========================================================================
# 24. S1-R (Security-Audit, HIGH) — die Segmentpruefung allein traegt nur
#     fuer KONTEXTFREIE Erkennung
#
# Die Zerlegung an den Fuellergrenzen rettet Namen, weil Presidio Namens-
# Tokens EINZELN erkennt ("Anna" ist fuer sich PERSON). MUSTERBASIERTE
# Recognizer koennen ihre Bruchstuecke prinzipbedingt nicht erkennen: eine
# halbe Telefonnummer ist keine Telefonnummer.
#
#   "Nummer: +49 30<PERSON_0>901820"  ->  Probe "Nummer: +49 30 901820"
#     _analyze(probe)      -> PHONE_NUMBER
#     _analyze("+49 30")   -> []          <- Bruchstueck
#     _analyze("901820")   -> []          <- Bruchstueck
#   => alle Segmente leer -> als Artefakt verworfen -> 11 Ziffern im Klartext
#
# Der Absender tippt den Platzhalter SELBST in den Prompt; die Nummerierung
# startet deterministisch bei 0. Durchlauf 1 findet die Nummer nicht, weil
# der eingeklebte Platzhalter das Muster zerreisst. Das Netz findet sie im
# Probe-String -- und verwirft genau diesen Fund.
#
# Zusaetzliches Kriterium: der VERKLEBTE KERN (Segmente ohne den
# eingefuegten Whitespace aneinandergehaengt). Artefakt nur, wenn BEIDE
# Pruefungen leer bleiben.
# ===========================================================================
# Musterbasierte Erkennung: matcht ueber den Trenner hinweg UND ohne ihn,
# aber nie ein Bruchstueck. Genau das Verhalten echter Recognizer fuer
# Telefonnummern, IBANs, IPs und Ticket-IDs.
_PHONE_RE = re.compile(r"\+49[\s./-]?\d{2,5}[\s./-]?\d{5,9}")


class TestPatternEntitiesSurviveSegmentation(_RuleFileTestCase,
                                             unittest.IsolatedAsyncioTestCase):
    async def _guard_mit_telefon(self):
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def presidio(text, payload=None):
            return [{"entity_type": "PHONE_NUMBER", "start": m.start(),
                     "end": m.end(), "score": 0.9}
                    for m in _PHONE_RE.finditer(text)]

        guard._presidio_analyze = presidio
        return guard

    async def test_telefonnummer_ueber_platzhalter_blockt(self):
        """Der Live-Fall des Auditors. Bruchstuecke sind kein Fund, der
        verklebte Kern ist einer."""
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard_mit_telefon()
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max Mustermann"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(
                "Kontakt <PERSON_0>. Nummer: +49 30<PERSON_0>901820", masker)

    async def test_bruchstuecke_sind_wirklich_kein_fund(self):
        """Belegt die Praemisse des Findings: ohne den verklebten Kern haette
        die Segmentpruefung hier nichts zu greifen."""
        guard = await self._guard_mit_telefon()
        self.assertEqual(await guard._presidio_analyze("+49 30"), [])
        self.assertEqual(await guard._presidio_analyze("901820"), [])
        self.assertTrue(await guard._presidio_analyze("+49 30 901820"))
        self.assertTrue(await guard._presidio_analyze("+49 30901820"))

    async def test_musterbasierte_eigene_regel_blockt_ebenso(self):
        """Dieselbe Klasse auf der Regel-Seite: eine Server-/Ticket-ID mit
        optionalem Trenner. Segmente leer, verklebter Kern ist ein Fund."""
        self.write_rules([rule("srv", entity="Serverkennung", kind="regex",
                               value=r"SRV-\d{3}\s*-\d{4}",
                               examples=["Host SRV-123-4567 meldet sich"])])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def keine(text, payload=None):
            return []

        guard._presidio_analyze = keine
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("SRV-123<PERSON_0>-4567", masker)

    async def test_reine_fuellerkette_bleibt_artefakt(self):
        """Die Gegenprobe, die das Kombi-Kriterium NICHT aufweicht: ein Kern
        aus lauter Fuellern hat keinen verklebten Rest. Er wird weiterhin
        vor jeder Analyse verworfen."""
        self.write_rules([rule("ws", entity="Formatierung", kind="regex",
                               value=r"\s{3,}", examples=["a   b"])])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def keine(text, payload=None):
            return []

        guard._presidio_analyze = keine
        masker = dg.Masker()
        for i, name in enumerate(("Max", "Erika", "Anna")):
            masker.reid_map[f"<PERSON_{i}>"] = name
        await guard._verify_no_pii_left("<PERSON_0><PERSON_1><PERSON_2>",
                                        masker)


# ===========================================================================
# 25. DoS-1 (Security-Audit, MEDIUM) — _build_probe ist quadratisch
#
# Die Vorpruefung "if text[i] in starts" haelt den Durchlauf nur linear,
# solange das Anfangszeichen selten ist. Der Absender kontrolliert beides:
# Textform und reid_map-Groesse. Gemessen: 200 KB "<x" mal 100000 mit 1000
# Schluesseln -> 6,54 s (main: 0,072 s). Synchrone CPU-Arbeit im Event-Loop,
# also fuer ALLE Nutzer -- exakt die Defektklasse, die dieser Branch als F2
# selbst behoben hat.
# ===========================================================================
class TestProbeBuilderIsLinear(unittest.TestCase):
    # Grosszuegig: die Regex-Variante liegt deutlich darunter, die
    # quadratische Variante um ein Vielfaches darueber. Kein Mikro-Benchmark,
    # sondern ein Riss-Detektor.
    OBERGRENZE_SEKUNDEN = 1.0

    def test_pathologischer_text_bleibt_schnell(self):
        reid_map = {f"<PERSON_{i}>": f"Name{i}" for i in range(1000)}
        text = "<x" * 100000  # 200 KB, jedes zweite Zeichen ist ein "<"

        beginn = time.monotonic()
        probe, fueller = dg._build_probe(text, reid_map)
        dauer = time.monotonic() - beginn

        # Kein Platzhalter passt wirklich -> Text bleibt unveraendert.
        self.assertEqual(probe, text)
        self.assertEqual(fueller, [])
        self.assertLess(
            dauer, self.OBERGRENZE_SEKUNDEN,
            f"_build_probe braucht {dauer:.2f}s fuer 200 KB -- quadratisches "
            f"Verhalten blockiert den Event-Loop fuer alle Nutzer (DoS-1)")

    def test_positionen_bleiben_korrekt(self):
        """Die Beschleunigung darf die Fuellerpositionen nicht verschieben --
        auf ihnen beruht die gesamte Artefakt-Erkennung."""
        reid_map = {"<PERSON_0>": "Max", "<PERSON_1>": "Erika",
                    "<PERSON_10>": "Anna"}
        text = "A<PERSON_0>B<PERSON_10>C<PERSON_1>"
        probe, fueller = dg._build_probe(text, reid_map)

        # Laengster Platzhalter zuerst: <PERSON_10> darf nicht als
        # <PERSON_1> + "0" gelesen werden.
        self.assertEqual(probe, "A B C ")
        self.assertEqual(fueller, [(1, 2), (3, 4), (5, 6)])
        for fs, fe in fueller:
            self.assertEqual(probe[fs:fe], dg._PLACEHOLDER_PROBE_FILLER)


# ===========================================================================
# 26. DoS-2 (Security-Audit, MEDIUM) — das F2-Budget multipliziert sich
#
# _verify_no_pii_left machte EINEN _analyze-Aufruf, jetzt sind es
# 1 + Summe(Segmente). Jeder setzt in _scan eine FRISCHE Frist. Das Budget,
# dessen Sinn laut F2 ausdruecklich ist, "fuer den GESAMTEN Aufruf" zu
# gelten, vervielfacht sich damit still. Der 16er-Deckel begrenzt pro
# Treffer, nicht ueber alle Treffer eines Textes.
# ===========================================================================
class TestVerificationHasGlobalAnalyzeBudget(_RuleFileTestCase,
                                             unittest.IsolatedAsyncioTestCase):
    async def test_ein_aufruf_auch_bei_sechzig_treffern(self):
        """DoS-2 ist mit dem Rueckbau der Heuristik gegenstandslos: der
        Artefaktfilter entscheidet ohne Nachpruefung. Sechzig Treffer ueber
        Fuellern kosten deshalb genau EINEN Analyzer-Aufruf -- und sie
        blocken, weil ihr Kern Klartext enthaelt.

        Der Test bleibt als Deckel-Ersatz stehen: er faellt, sobald jemand
        wieder Nachpruef-Aufrufe einbaut."""
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        aufrufe = []

        async def presidio(text, payload=None):
            aufrufe.append(text)
            if "|" not in text:
                return []
            return [{"entity_type": "PERSON", "start": m.start(),
                     "end": m.end(), "score": 0.9}
                    for m in re.finditer(r"a b", text)]

        guard._presidio_analyze = presidio

        masker = dg.Masker()
        for i in range(60):
            masker.reid_map[f"<PERSON_{i}>"] = f"Name{i}"
        # 60 Treffer der Form "a b", jeder ueberspannt genau einen Fueller.
        maskiert = "|" + "".join(f"a<PERSON_{i}>b " for i in range(60))

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(maskiert, masker)

        self.assertEqual(
            len(aufrufe), 1,
            f"{len(aufrufe)} Analyzer-Aufrufe fuer EINEN Verifikations"
            f"durchlauf -- das F2-Zeitbudget der Regel-Schicht gilt damit "
            f"nicht mehr fuer den gesamten Aufruf (DoS-2)")

    async def test_normalfall_bleibt_bei_einem_aufruf(self):
        """Auch ohne Treffer ueber einem Fueller: genau ein Aufruf."""
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        aufrufe = []

        async def presidio(text, payload=None):
            aufrufe.append(text)
            return []

        guard._presidio_analyze = presidio
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"
        await guard._verify_no_pii_left("Hallo <PERSON_0>, alles gut?", masker)
        self.assertEqual(len(aufrufe), 1)


# ===========================================================================
# 27. Zwei Low aus dem Re-Audit
# ===========================================================================
class TestWhitespaceRuleIsExplicit(_RuleFileTestCase,
                                   unittest.IsolatedAsyncioTestCase):
    """Low: _is_filler_artifact gibt bei leerem filler_spans sofort False. Damit
    blockt derselbe reine Whitespace-Treffer OHNE Platzhalter im Text und
    wird verworfen, sobald irgendwo einer steht. Das ist fail-closed und
    gewollt -- aber es muss die Regel sein, die auch dasteht: ohne Fueller
    haben WIR nichts eingefuegt, also ist jeder Fund der des Analyzers."""

    async def _guard(self):
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def presidio(text, payload=None):
            i = text.find("   ")
            return ([] if i < 0 else
                    [{"entity_type": "PERSON", "start": i, "end": i + 3,
                      "score": 0.9}])

        guard._presidio_analyze = presidio
        return guard

    async def test_ohne_platzhalter_blockt_der_whitespace_treffer(self):
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard()
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left("a   b", dg.Masker())

    async def test_mit_platzhaltern_ist_er_ein_artefakt(self):
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = await self._guard()
        masker = dg.Masker()
        for i, name in enumerate(("Max", "Erika", "Anna")):
            masker.reid_map[f"<PERSON_{i}>"] = name
        await guard._verify_no_pii_left("<PERSON_0><PERSON_1><PERSON_2>",
                                        masker)


class TestStatKeyOnlyAdvancesAfterSuccess(_RuleFileTestCase):
    """Low: _stat_key wurde VOR _load gesetzt. Entkommt _load eine Ausnahme
    (realistisch: BrokenPipeError beim Loggen, wenn der Collector weg ist),
    bleibt der Regelsatz dauerhaft stehen -- der naechste Aufruf sieht
    key == _stat_key und laedt nie wieder. Stiller, permanenter Ausfall der
    Hot-Reload-Zusage."""

    def test_nach_ausnahme_wird_erneut_geladen(self):
        self.write_rules([rule("kunde", entity="Kundenname", value="Adlerflug")])
        rs = cr.RuleSet(self.path)
        rs.active_rules  # Erstladung abschliessen

        # Datei aendern, damit ueberhaupt ein Reload ansteht.
        self.write_rules([rule("kunde", entity="Kundenname", value="Adlerflug"),
                          rule("zweiter", entity="Projektname",
                               value="Seewind")])

        versuche = []
        echtes_load = rs._load

        def load_das_beim_ersten_mal_reisst(key):
            versuche.append(key)
            if len(versuche) == 1:
                raise BrokenPipeError("Log-Collector weg")
            return echtes_load(key)

        rs._load = load_das_beim_ersten_mal_reisst

        with self.assertRaises(BrokenPipeError):
            rs._reload_if_changed()
        # Zweiter Anlauf MUSS erneut laden, sonst ist der Hot-Reload tot.
        rs._reload_if_changed()
        self.assertEqual(len(versuche), 2,
                         "nach der Ausnahme wurde nie wieder geladen")
        self.assertTrue(rs.active_rules, "Regelsatz blieb dauerhaft leer")


# ===========================================================================
# 28. HIGH-1 / HIGH-2 (Re-Audit 2) — die Segment- und Verkleb-Heuristik
#     erzeugt selbst Lecks
#
# Dritter Anlauf, den Fehlalarmraum feiner zuzuschneiden, drittes Leck:
#
#   HIGH-2  Die Duplikat-Entfernung (dict.fromkeys) macht aus vier
#           Zifferngruppen zwei. "4111 1111 1111 1111" wird zu "41111111" --
#           acht Ziffern statt sechzehn, kein Fund, kein Block. Wiederholte
#           Zifferngruppen sind bei Karten, IBANs und Telefonnummern der
#           NORMALFALL, nicht der Sonderfall.
#
#   HIGH-1  Der verklebte Kern LOESCHT den Trenner. Ein Deny-Listen-Begriff,
#           der selbst ein Leerzeichen enthaelt, kann darin per Konstruktion
#           nicht vorkommen: "Zephyr Kontor" findet sich weder in "Zephyr"
#           noch in "Kontor" noch in "ZephyrKontor". Und genau fuer generisch
#           unbekannte Namen gibt es die Deny-Liste ueberhaupt -- Presidio
#           schweigt dort. Die Beispieldatei des Repos und die CLI-Hilfe
#           fuehren beide mit "Nordwind Logistik". Mehrwortig.
#
# Konsequenz (Entscheidung des Leads): Die Heuristik fliegt raus. Verworfen
# wird nur noch, was BEWEISBAR unsere eigene Einfuegung ist -- ein Kern ohne
# jeden Klartext. Alles darueber hinaus war Optimierung auf Verdacht und hat
# drei Lecks gekostet, jedes davon gefunden erst von einem Auditor.
# ===========================================================================
class TestNoPlaintextEscapesThroughArtifactFilter(
        _RuleFileTestCase, unittest.IsolatedAsyncioTestCase):

    async def test_kreditkarte_mit_platzhaltern_blockt(self):
        """HIGH-2: vier Zifferngruppen, drei davon identisch. Die
        Duplikat-Entfernung halbierte die Nummer."""
        self.write_rules([rule("k", entity="Kundenname", value="Adlerflug")])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        # Recognizer, der NUR die volle 16-stellige Form kennt -- so wie ein
        # echter Kreditkarten-Recognizer (Luhn braucht alle Ziffern).
        voll = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")

        async def presidio(text, payload=None):
            return [{"entity_type": "CREDIT_CARD", "start": m.start(),
                     "end": m.end(), "score": 0.9}
                    for m in voll.finditer(text)]

        guard._presidio_analyze = presidio
        masker = dg.Masker()
        for i, name in enumerate(("Max", "Erika", "Anna")):
            masker.reid_map[f"<PERSON_{i}>"] = name

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(
                "Karte 4111<PERSON_0>1111<PERSON_1>1111<PERSON_2>1111",
                masker)

    async def test_mehrwortiger_deny_begriff_blockt(self):
        """HIGH-1: der verklebte Kern loescht den Trenner. Ein Begriff mit
        Leerzeichen kann darin nicht vorkommen -- und Presidio schweigt hier,
        weil der Name generisch unbekannt ist."""
        self.write_rules([rule("kunde", entity="Kundenname",
                               value="Zephyr Kontor",
                               examples=["Angebot fuer Zephyr Kontor"])])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def stumm(text, payload=None):
            return []

        guard._presidio_analyze = stumm
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(
                "Angebot fuer Zephyr<PERSON_0>Kontor", masker)

    async def test_repo_beispiel_nordwind_logistik_blockt(self):
        """Dieselbe Klasse mit dem Begriff, mit dem die Beispieldatei und die
        CLI-Hilfe des Repos werben. Wer die Doku nachbaut, ist betroffen."""
        self.write_rules([rule("kunde", entity="Kundenname",
                               value="Nordwind Logistik",
                               examples=["Kunde Nordwind Logistik meldet"])])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        async def stumm(text, payload=None):
            return []

        guard._presidio_analyze = stumm
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(
                "Kunde Nordwind<PERSON_0>Logistik meldet sich", masker)

    async def test_artefaktfilter_kostet_keinen_analyzer_aufruf(self):
        """Gegenprobe zur Vereinfachung: der verbliebene Artefaktfall wird
        OHNE jede Nachpruefung entschieden. Genau ein Analyzer-Aufruf pro
        Verifikationsdurchlauf -- damit ist auch DoS-2 gegenstandslos."""
        self.write_rules([rule("ws", entity="Formatierung", kind="regex",
                               value=r"\s{3,}", examples=["a   b"])])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        aufrufe = []

        async def stumm(text, payload=None):
            aufrufe.append(text)
            return []

        guard._presidio_analyze = stumm
        masker = dg.Masker()
        for i, name in enumerate(("Max", "Erika", "Anna")):
            masker.reid_map[f"<PERSON_{i}>"] = name

        await guard._verify_no_pii_left("<PERSON_0><PERSON_1><PERSON_2>",
                                        masker)
        self.assertEqual(len(aufrufe), 1,
                         "der Artefaktfilter darf keine Nachpruefung kosten")

    async def test_auch_der_blockpfad_kostet_nur_einen_aufruf(self):
        self.write_rules([rule("kunde", entity="Kundenname",
                               value="Zephyr Kontor",
                               examples=["Angebot fuer Zephyr Kontor"])])
        guard = dg.DatenschleuseGuardrail(custom_rules_path=self.path)

        aufrufe = []

        async def stumm(text, payload=None):
            aufrufe.append(text)
            return []

        guard._presidio_analyze = stumm
        masker = dg.Masker()
        masker.reid_map["<PERSON_0>"] = "Max"

        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard._verify_no_pii_left(
                "Angebot fuer Zephyr<PERSON_0>Kontor", masker)
        self.assertEqual(len(aufrufe), 1)
