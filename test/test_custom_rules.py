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
        nicht anhalten. Die Regel laeuft in ein Timeout, alle anderen liefern."""
        self.write_rules([
            rule("redos", entity="MUELL", kind="regex", value=r"(a|a)*$",
                 examples=["aaaaaaaaaa"]),
            rule("heil", value="Adlerflug"),
        ])
        rs = cr.RuleSet(self.path)
        boese = "a" * 44 + "b Projekt Adlerflug"

        start = time.monotonic()
        treffer = self.matched_values(rs, boese)
        dauer = time.monotonic() - start

        self.assertIn("Adlerflug", treffer)
        self.assertLess(dauer, 5.0, "ReDoS-Regel hat die Pipeline blockiert")

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
        treffer = self.matched_values(rs, boese)
        dauer = time.monotonic() - start

        self.assertIn("Adlerflug", treffer)
        self.assertLess(dauer, 1.0,
                        f"Budget summierte sich auf {dauer:.2f}s statt gedeckelt zu sein")

    def test_healthy_rules_before_the_slow_one_still_match(self):
        """Wer zuerst drankommt, liefert -- das Budget frisst nicht alles."""
        self.write_rules([
            rule("heil", value="Adlerflug"),
            rule("redos", entity="MUELL", kind="regex", value=r"(a|a)*$",
                 examples=["aaaaaaaaaa"]),
        ])
        rs = cr.RuleSet(self.path, match_timeout=0.2)
        treffer = self.matched_values(rs, "a" * 44 + "b Projekt Adlerflug")
        self.assertIn("Adlerflug", treffer)

    def test_normal_ruleset_is_not_slowed_down(self):
        self.write_rules([rule(f"r{i}", value=f"Begriff{i}",
                               examples=[f"Text Begriff{i} hier"])
                          for i in range(30)])
        rs = cr.RuleSet(self.path)
        start = time.monotonic()
        rs.find("Ein ganz normaler Satz mit Begriff7 darin.")
        self.assertLess(time.monotonic() - start, 0.5)
