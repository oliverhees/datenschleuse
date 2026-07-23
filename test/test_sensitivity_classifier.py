"""Unit-Tests fuer den Datenschleuse Sensitivitaets-Klassifizierer
(Schutzklassen-Modell, litellm/sensitivity_classifier.py).

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.
Die Klassifizierungslogik ist reine Python-Logik; Presidio-Entities werden
als Dicts direkt injiziert, die Config als dict uebergeben (kein PyYAML noetig).
Ein separater Test laedt zusaetzlich die echte YAML-Config (uebersprungen,
falls PyYAML fehlt).

Ausfuehren:
    python3 -m unittest test.test_sensitivity_classifier -v
    # oder aus dem test/-Ordner:
    python3 -m unittest test_sensitivity_classifier -v
"""

import inspect
import os
import sys
import unittest

# litellm/-Ordner (mit sensitivity_classifier.py) auf den Importpfad legen.
_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import sensitivity_classifier as sc  # noqa: E402


# ---------------------------------------------------------------------------
# Test-Config (spiegelt presidio/sensitivity-keywords.yml, aber schlank).
# Direkt als dict injiziert -> Tests brauchen weder PyYAML noch die Datei.
# ---------------------------------------------------------------------------
TEST_CONFIG = {
    "tier3_special_categories": {
        "gesundheit": ["Diagnose", "HIV", "Schwangerschaft", "psychische Erkrankung", "Behinderung"],
        "gewerkschaft": ["Gewerkschaft"],
        "religion_weltanschauung": ["Glaubensrichtung", "Konfession"],
        "strafrechtlich": ["Vorstrafe", "verurteilt"],
        "biometrisch_genetisch": ["Gentest", "DNA"],
        "sexualleben": ["sexuelle Orientierung"],
    },
    "tier2_context_words": ["vertraulich", "intern", "NDA"],
    "tier2_patterns": {
        "vertragsnummer": r"vertrags?(?:nummer|nr\.?)\s*:?\s*[A-Za-z0-9][A-Za-z0-9\-/]{2,}",
        "gehalt": r"(?:gehalt|jahresgehalt|verdient)\D{0,20}\d{1,3}(?:[.\s]?\d{3})*(?:\s?(?:eur|euro|€))?",
    },
    "person_linking_entities": ["PERSON", "EMAIL_ADDRESS", "DE_STEUER_ID"],
    "person_indicators": ["Patient", "Mitarbeiter", "mein Bruder", "Herr", "Frau"],
}


def make_clf(**kwargs):
    return sc.SensitivityClassifier(config=TEST_CONFIG, **kwargs)


def person_entity(etype="PERSON", start=0, end=5):
    return [{"entity_type": etype, "start": start, "end": end, "score": 0.99}]


# ===========================================================================
# 1. Stufe 1 — niedrig sensibel
# ===========================================================================
class TestTier1(unittest.TestCase):
    def test_plain_text_is_tier_1(self):
        clf = make_clf()
        res = clf.classify("Wie wird das Wetter morgen in Berlin?")
        self.assertEqual(res.tier, sc.Tier.TIER_1)
        self.assertFalse(res.is_tier_3)

    def test_person_without_sensitive_context_is_tier_1(self):
        """Reiner Personenname ohne Art.-9-/Vertraulichkeitskontext -> Stufe 1
        (normale PII-Maskierung reicht)."""
        clf = make_clf()
        res = clf.classify("Max Mustermann braucht Hilfe.", entities=person_entity(end=14))
        self.assertEqual(res.tier, sc.Tier.TIER_1)

    def test_art9_keyword_without_person_is_tier_1(self):
        """Allgemeine Wissensfrage mit Art.-9-Begriff, aber ohne Personenbezug
        -> kein Personendatum -> Stufe 1."""
        clf = make_clf()
        res = clf.classify("Was ist eigentlich HIV und wie wird es uebertragen?")
        self.assertEqual(res.tier, sc.Tier.TIER_1)


# ===========================================================================
# 2. Stufe 2 — vertraulich
# ===========================================================================
class TestTier2(unittest.TestCase):
    def test_confidentiality_word_plus_person(self):
        clf = make_clf()
        res = clf.classify(
            "Streng vertraulich: Max Mustermann verhandelt gerade.",
            entities=[{"entity_type": "PERSON", "start": 20, "end": 34, "score": 0.9}],
        )
        self.assertEqual(res.tier, sc.Tier.TIER_2)

    def test_contract_number_plus_person_indicator(self):
        clf = make_clf()
        res = clf.classify("Der Mitarbeiter hat Vertragsnummer AB-2024-01 unterschrieben.")
        self.assertEqual(res.tier, sc.Tier.TIER_2)

    def test_salary_plus_person(self):
        clf = make_clf()
        res = clf.classify(
            "Herr Schmidt verdient 72.000 EUR im Jahr.",
        )
        self.assertEqual(res.tier, sc.Tier.TIER_2)

    def test_confidentiality_without_person_is_tier_1(self):
        clf = make_clf()
        res = clf.classify("Dieses Dokument ist intern.")
        self.assertEqual(res.tier, sc.Tier.TIER_1)


# ===========================================================================
# 3. Stufe 3 — hoechst sensibel (Art. 9 / Art. 10)
# ===========================================================================
class TestTier3(unittest.TestCase):
    def test_health_plus_person_entity(self):
        clf = make_clf()
        # Art.-9-Gesundheitsbegriff ('Diagnose') + PERSON-Entity -> Stufe 3.
        res = clf.classify(
            "Die Diagnose von Max Mustermann lautet Depression.",
            entities=[{"entity_type": "PERSON", "start": 17, "end": 31, "score": 0.99}],
        )
        self.assertEqual(res.tier, sc.Tier.TIER_3)
        self.assertTrue(res.is_tier_3)

    def test_health_plus_person_indicator_fallback(self):
        """Auch ohne Presidio-Entity greift der Text-Fallback (Patient)."""
        clf = make_clf()
        res = clf.classify("Der Patient hat eine psychische Erkrankung.")
        self.assertEqual(res.tier, sc.Tier.TIER_3)

    def test_criminal_record_plus_person(self):
        clf = make_clf()
        res = clf.classify("Herr Meier wurde verurteilt und hat eine Vorstrafe.")
        self.assertEqual(res.tier, sc.Tier.TIER_3)

    def test_union_membership_plus_person(self):
        clf = make_clf()
        res = clf.classify(
            "Mitarbeiter ist in der Gewerkschaft organisiert.",
        )
        self.assertEqual(res.tier, sc.Tier.TIER_3)

    def test_email_counts_as_person_reference(self):
        clf = make_clf()
        res = clf.classify(
            "Kontakt max@example.de, Schwangerschaft bestaetigt.",
            entities=[{"entity_type": "EMAIL_ADDRESS", "start": 8, "end": 22, "score": 1.0}],
        )
        self.assertEqual(res.tier, sc.Tier.TIER_3)

    def test_reasons_are_populated(self):
        """Nachvollziehbarkeit: die Einstufung liefert eine Begruendung."""
        clf = make_clf()
        res = clf.classify("Der Patient hat HIV.")
        self.assertEqual(res.tier, sc.Tier.TIER_3)
        self.assertTrue(res.reasons)
        self.assertIn("art9", " ".join(res.reasons))
        # Begruendung nennt die Kategorie, nicht nackt eine Zahl:
        self.assertIn("gesundheit", " ".join(res.reasons))


# ===========================================================================
# 4. Explizite Nutzer-Markierung — monoton (nur erhoehen)
# ===========================================================================
class TestUserLevelMonotonic(unittest.TestCase):
    def test_user_can_raise_tier(self):
        clf = make_clf()
        res = clf.classify("Ein harmloser Satz.", requested_level=2)
        self.assertEqual(res.tier, sc.Tier.TIER_2)

    def test_user_can_raise_to_tier_3(self):
        clf = make_clf()
        res = clf.classify("Ein harmloser Satz.", requested_level=3)
        self.assertEqual(res.tier, sc.Tier.TIER_3)

    def test_user_cannot_lower_below_heuristic(self):
        """KERN-INVARIANTE: Nutzer-Stufe 1 darf eine als Stufe 3 erkannte
        Anfrage NICHT herunterstufen."""
        clf = make_clf()
        res = clf.classify(
            "Der Patient hat eine psychische Erkrankung.",
            requested_level=1,  # Versuch, herunterzustufen
        )
        self.assertEqual(res.tier, sc.Tier.TIER_3)

    def test_invalid_user_level_fails_closed_to_tier_3(self):
        """Ungueltige, aber gesetzte Stufe (z.B. 0/4/'hoch') -> strengste Stufe,
        nicht ignorieren (fail-closed)."""
        clf = make_clf()
        for bad in (0, 4, 99, "hoch", "drei"):
            res = clf.classify("Harmlos.", requested_level=bad)
            self.assertEqual(res.tier, sc.Tier.TIER_3, f"level={bad!r}")

    def test_no_user_level_is_none(self):
        clf = make_clf()
        res = clf.classify("Harmlos.", requested_level=None)
        self.assertIsNone(res.requested_level)


# ===========================================================================
# 5. HARD-BLOCK-GARANTIE Stufe 3 + Bypass-Versuche (das Kernversprechen)
# ===========================================================================
class TestTier3HardBlock(unittest.TestCase):
    def _tier3_classification(self):
        clf = make_clf()
        res = clf.classify("Der Patient hat HIV.")
        self.assertEqual(res.tier, sc.Tier.TIER_3)
        return res

    def test_enforce_raises_on_tier_3(self):
        res = self._tier3_classification()
        with self.assertRaises(sc.Tier3Blocked):
            sc.enforce_tier_3_block(res)

    def test_enforce_noop_on_tier_1_and_2(self):
        clf = make_clf()
        t1 = clf.classify("Harmlos.")
        t2 = clf.classify("Der Mitarbeiter hat Vertragsnummer AB-2024-01.")
        self.assertEqual(t1.tier, sc.Tier.TIER_1)
        self.assertEqual(t2.tier, sc.Tier.TIER_2)
        # Duerfen NICHT werfen:
        sc.enforce_tier_3_block(t1)
        sc.enforce_tier_3_block(t2)

    def test_enforce_signature_has_no_bypass_parameter(self):
        """Struktureller Schutz: enforce_tier_3_block darf KEINEN Parameter
        akzeptieren, der den Block umgehen koennte. Nur 'classification'."""
        params = list(inspect.signature(sc.enforce_tier_3_block).parameters)
        self.assertEqual(params, ["classification"])
        # Kein force/override/allow/bypass im Namen irgendeines Parameters:
        forbidden = ("force", "override", "bypass", "allow", "skip", "approval")
        for p in params:
            for bad in forbidden:
                self.assertNotIn(bad, p.lower())

    def test_bypass_attempts_all_fail(self):
        """EXPLIZITER BYPASS-TEST: verschiedene Umgehungswege, alle muessen
        greifen (Tier3Blocked). Der Block darf sich durch NICHTS entschaerfen
        lassen."""
        clf = make_clf()

        # Vektor A: Freigabe-Flag gesetzt (soll Stufe 3 NICHT durchlassen).
        res_a = clf.classify("Der Patient hat HIV.")
        approved = sc.is_release_approved({sc.SENSITIVITY_APPROVAL_KEY: True})
        self.assertTrue(approved)  # Flag ist gesetzt ...
        with self.assertRaises(sc.Tier3Blocked):  # ... aendert aber nichts:
            sc.enforce_tier_3_block(res_a)
        # Und das Stufe-2-Gate darf Stufe 3 nicht "freigeben":
        sc.enforce_tier_2_gate(res_a, approved=True)  # no-op fuer Stufe 3
        with self.assertRaises(sc.Tier3Blocked):
            sc.enforce_tier_3_block(res_a)

        # Vektor B: Nutzer versucht herunterzustufen (requested_level=1).
        res_b = clf.classify("Der Patient hat HIV.", requested_level=1)
        self.assertEqual(res_b.tier, sc.Tier.TIER_3)
        with self.assertRaises(sc.Tier3Blocked):
            sc.enforce_tier_3_block(res_b)

        # Vektor C: manipulierte Metadaten mit erfundenen Bypass-Keys.
        for meta in (
            {"force": True},
            {"override_tier3": True},
            {"sensitivity_approval": "true", "bypass": 1},
            {sc.SENSITIVITY_LEVEL_KEY: 1, sc.SENSITIVITY_APPROVAL_KEY: True},
        ):
            res_c = clf.classify(
                "Der Patient hat HIV.",
                requested_level=meta.get(sc.SENSITIVITY_LEVEL_KEY),
            )
            self.assertEqual(res_c.tier, sc.Tier.TIER_3)
            with self.assertRaises(sc.Tier3Blocked):
                sc.enforce_tier_3_block(res_c)

        # Vektor D: leeres/falsches Freigabe-Flag.
        for approval_val in ("", None, False, "false", "0", "nope"):
            self.assertFalse(sc.is_release_approved({sc.SENSITIVITY_APPROVAL_KEY: approval_val}))

        # Vektor E: Heuristik + Nutzerstufe 3 kombiniert bleibt Stufe 3.
        res_e = clf.classify("Der Patient hat HIV.", requested_level=3)
        with self.assertRaises(sc.Tier3Blocked):
            sc.enforce_tier_3_block(res_e)


# ===========================================================================
# 6. Stufe-2-Freigabe-Gate
# ===========================================================================
class TestTier2Gate(unittest.TestCase):
    def _tier2(self):
        clf = make_clf()
        res = clf.classify("Der Mitarbeiter hat Vertragsnummer AB-2024-01.")
        self.assertEqual(res.tier, sc.Tier.TIER_2)
        return res

    def test_tier2_without_approval_blocks(self):
        res = self._tier2()
        with self.assertRaises(sc.Tier2ApprovalRequired):
            sc.enforce_tier_2_gate(res, approved=False)

    def test_tier2_with_approval_passes(self):
        res = self._tier2()
        sc.enforce_tier_2_gate(res, approved=True)  # darf NICHT werfen

    def test_tier2_gate_noop_on_tier1(self):
        clf = make_clf()
        res = clf.classify("Harmlos.")
        sc.enforce_tier_2_gate(res, approved=False)  # kein Block fuer Stufe 1

    def test_is_release_approved_variants(self):
        self.assertTrue(sc.is_release_approved({sc.SENSITIVITY_APPROVAL_KEY: True}))
        self.assertTrue(sc.is_release_approved({sc.SENSITIVITY_APPROVAL_KEY: "true"}))
        self.assertTrue(sc.is_release_approved({sc.SENSITIVITY_APPROVAL_KEY: "JA"}))
        self.assertFalse(sc.is_release_approved({sc.SENSITIVITY_APPROVAL_KEY: False}))
        self.assertFalse(sc.is_release_approved({}))
        self.assertFalse(sc.is_release_approved(None))
        self.assertFalse(sc.is_release_approved("nicht-dict"))

    def test_missing_approval_is_safe_default(self):
        """'Freigabe fehlt' == blockiert (nicht automatisch annehmen)."""
        res = self._tier2()
        approved = sc.is_release_approved({})  # nichts gesetzt
        self.assertFalse(approved)
        with self.assertRaises(sc.Tier2ApprovalRequired):
            sc.enforce_tier_2_gate(res, approved=approved)


# ===========================================================================
# 7. Fail-closed-Verhalten
# ===========================================================================
class TestFailClosed(unittest.TestCase):
    def test_classification_error_falls_to_fail_closed_tier(self):
        """Wirft die interne Klassifizierung einen Fehler, faellt das Ergebnis
        auf die (strengere) fail_closed_tier, nicht auf Stufe 1."""
        clf = make_clf()

        def boom(*a, **k):
            raise RuntimeError("simulierter Analysefehler")

        clf._classify_impl = boom  # type: ignore[assignment]
        res = clf.classify("egal")
        self.assertEqual(res.tier, sc.Tier.TIER_2)  # Default fail_closed_tier
        self.assertIn("fail_closed", " ".join(res.reasons))

    def test_fail_closed_tier_can_be_tier_3(self):
        clf = make_clf(fail_closed_tier=sc.Tier.TIER_3)

        def boom(*a, **k):
            raise RuntimeError("x")

        clf._classify_impl = boom  # type: ignore[assignment]
        res = clf.classify("egal")
        self.assertEqual(res.tier, sc.Tier.TIER_3)

    def test_fail_closed_tier_cannot_be_lax(self):
        with self.assertRaises(ValueError):
            make_clf(fail_closed_tier=sc.Tier.TIER_1)

    def test_empty_config_raises(self):
        with self.assertRaises(sc.SensitivityConfigError):
            sc.SensitivityClassifier(config={"tier3_special_categories": {}})


# ===========================================================================
# 8. Wortgrenzen / False-Positive-Schutz
# ===========================================================================
class TestWordBoundaries(unittest.TestCase):
    def test_no_substring_false_positive(self):
        """'Religion' darf nicht in 'Religionsunterricht' matchen (Wortgrenze).
        Wir nehmen 'Konfession' analog: 'Konfessionslosigkeit' matcht nicht."""
        clf = sc.SensitivityClassifier(
            config={
                "tier3_special_categories": {"religion_weltanschauung": ["Konfession"]},
                "person_indicators": ["Patient"],
            }
        )
        res = clf.classify("Der Patient diskutiert Konfessionslosigkeit theoretisch.")
        # 'Konfession' als Teil von 'Konfessionslosigkeit' -> KEIN Treffer:
        self.assertEqual(res.tier, sc.Tier.TIER_1)

    def test_punctuation_boundary_matches(self):
        clf = sc.SensitivityClassifier(
            config={
                "tier3_special_categories": {"gesundheit": ["Diagnose"]},
                "person_indicators": ["Patient"],
            }
        )
        res = clf.classify("Patient, Diagnose: unklar.")
        self.assertEqual(res.tier, sc.Tier.TIER_3)


# ===========================================================================
# 9. Echte YAML-Config laden (uebersprungen, falls PyYAML fehlt)
# ===========================================================================
class TestRealConfig(unittest.TestCase):
    def test_real_yaml_loads_and_classifies(self):
        try:
            import yaml  # noqa: F401
        except Exception:
            self.skipTest("PyYAML nicht installiert")
        path = os.path.normpath(
            os.path.join(_HERE, "..", "presidio", "sensitivity-keywords.yml")
        )
        if not os.path.exists(path):
            self.skipTest("sensitivity-keywords.yml nicht gefunden")
        clf = sc.SensitivityClassifier(config_path=path)
        # Stufe 3 aus der echten Liste:
        res3 = clf.classify("Der Patient hat eine Schwerbehinderung.")
        self.assertEqual(res3.tier, sc.Tier.TIER_3)
        # Stufe 1:
        res1 = clf.classify("Wie spaet ist es in Tokio?")
        self.assertEqual(res1.tier, sc.Tier.TIER_1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
