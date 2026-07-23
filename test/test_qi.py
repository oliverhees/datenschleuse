"""Unit-Tests fuer den Quasi-Identifier-Layer der Datenschleuse.

Deckt ab:
  * Generalisierungs-Funktionen pro QI-Typ (mehrere Beispielwerte),
  * Schwellwert-Logik (2 Typen -> keine Generalisierung, 3. Typ -> ab jetzt),
  * TTL-Ablauf des verschluesselten State-Stores,
  * Preset-Verhalten (paranoid vs. balanced vs. utility),
  * Session-Key-Aufloesung (echte Session-ID vs. API-Key-Hash-Fallback),
  * Guardrail-Integration (Generalisierung nur ab Schwellwert; direkte
    Maskierung bleibt unangetastet; QI-Fehler blocken den Request nicht).

Laeuft mit stdlib unittest. Der State-Store braucht `cryptography` (Fernet);
das ist die einzige zusaetzliche Abhaengigkeit dieser Test-Suite. Presidio/
LiteLLM werden NICHT benoetigt (Analyzer wird gemockt).

Ausfuehren (aus test/):
    python3 -m unittest test_qi -v
"""

import os
import sys
import types
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import qi_generalization as qig  # noqa: E402
import qi_state as qs  # noqa: E402
import datenschleuse_guardrail as dg  # noqa: E402

from cryptography.fernet import Fernet  # noqa: E402


def _key() -> bytes:
    return Fernet.generate_key()


# ===========================================================================
# 1. Generalisierungs-Funktionen
# ===========================================================================
class TestGeneralization(unittest.TestCase):
    def test_plz_regions(self):
        cases = {
            "01067": "Region Sachsen/Thüringen",
            "10115": "Region Berlin/Brandenburg/Mecklenburg-Vorpommern",
            "50667": "Region Nordrhein-Westfalen (Süd)/Rheinland-Pfalz (Nord)",
            "84028": "Region Bayern (Süd)/Baden-Württemberg (Süd)",
            "99084": "Region Bayern (Nord/Ost)",
        }
        for plz, region in cases.items():
            self.assertEqual(qig.generalize_plz(plz), region)

    def test_plz_fallback_no_digit(self):
        self.assertEqual(qig.generalize_plz("keine"), "Region in Deutschland")

    def test_geburtsjahr_decade_and_phase(self):
        self.assertEqual(qig.generalize_geburtsjahr("1970"), "Anfang der 1970er")
        self.assertEqual(qig.generalize_geburtsjahr("1975"), "Mitte der 1970er")
        self.assertEqual(qig.generalize_geburtsjahr("1979"), "Ende der 1970er")
        self.assertEqual(qig.generalize_geburtsjahr("2001"), "Anfang der 2000er")
        self.assertEqual(qig.generalize_geburtsjahr("1988"), "Ende der 1980er")

    def test_tvoed_bands(self):
        self.assertEqual(
            qig.generalize_tvoed_stufe("TVöD E5"),
            "unteres Einkommensband (öffentlicher Dienst)",
        )
        self.assertEqual(
            qig.generalize_tvoed_stufe("EG 9"),
            "mittleres Einkommensband (öffentlicher Dienst)",
        )
        self.assertEqual(
            qig.generalize_tvoed_stufe("TVöD E13"),
            "gehobenes Einkommensband (öffentlicher Dienst)",
        )
        self.assertEqual(
            qig.generalize_tvoed_stufe("Besoldungsgruppe A13"),
            "gehobenes Einkommensband (öffentlicher Dienst)",
        )

    def test_gender_suppressed(self):
        self.assertEqual(qig.generalize_gender("männlich"), "[Geschlecht anonymisiert]")
        self.assertEqual(qig.generalize_gender("weiblich"), "[Geschlecht anonymisiert]")

    def test_dispatcher_and_beruf_stays(self):
        self.assertEqual(qig.generalize("DE_PLZ", "84028"), qig.generalize_plz("84028"))
        # DE_BERUF bleibt im Text stehen -> None
        self.assertIsNone(qig.generalize("DE_BERUF", "Bürgermeister"))

    def test_state_category_never_raw(self):
        # Fuer transformierbare Typen: generalisierte Form.
        self.assertEqual(qig.state_category("DE_PLZ", "84028"), qig.generalize_plz("84028"))
        # Fuer DE_BERUF: generischer Marker, NIE der Rohwert.
        cat = qig.state_category("DE_BERUF", "Bürgermeister")
        self.assertNotIn("Bürgermeister", cat)

    def test_apply_generalizations_value_based(self):
        text = "PLZ 84028, geboren 1979, Geschlecht männlich, Beruf Bürgermeister."
        turn_qi = [
            ("DE_PLZ", "84028"),
            ("DE_GEBURTSJAHR", "1979"),
            ("DE_GENDER", "männlich"),
            ("DE_BERUF", "Bürgermeister"),
        ]
        out = qig.apply_generalizations(text, turn_qi)
        self.assertNotIn("84028", out)
        self.assertNotIn("1979", out)
        self.assertNotIn("männlich", out)
        self.assertIn("Region Bayern", out)
        self.assertIn("Ende der 1970er", out)
        self.assertIn("[Geschlecht anonymisiert]", out)
        # Beruf bleibt stehen
        self.assertIn("Bürgermeister", out)


# ===========================================================================
# 2. Schwellwert-Entscheidung (rein)
# ===========================================================================
class TestThresholdDecision(unittest.TestCase):
    def test_two_types_below_three_no_generalize(self):
        gen, after = qig.decide_generalization(
            {"DE_PLZ"}, [("DE_GENDER", "männlich")], threshold=3
        )
        self.assertFalse(gen)
        self.assertEqual(after, {"DE_PLZ", "DE_GENDER"})

    def test_third_type_triggers(self):
        gen, after = qig.decide_generalization(
            {"DE_PLZ", "DE_GENDER"}, [("DE_GEBURTSJAHR", "1979")], threshold=3
        )
        self.assertTrue(gen)
        self.assertEqual(len(after), 3)

    def test_same_type_repeats_does_not_count(self):
        # Bereits gesehener Typ erneut -> keine neue Distinktheit.
        gen, after = qig.decide_generalization(
            {"DE_PLZ", "DE_GENDER"}, [("DE_PLZ", "12345")], threshold=3
        )
        self.assertFalse(gen)
        self.assertEqual(after, {"DE_PLZ", "DE_GENDER"})

    def test_preset_thresholds(self):
        self.assertEqual(qig.threshold_for_preset("utility"), 5)
        self.assertEqual(qig.threshold_for_preset("balanced"), 3)
        self.assertEqual(qig.threshold_for_preset("paranoid"), 1)
        self.assertEqual(qig.threshold_for_preset(None), 3)  # Default
        self.assertEqual(qig.threshold_for_preset("quatsch"), 3)  # Fallback

    def test_paranoid_single_qi_triggers(self):
        gen, _ = qig.decide_generalization(set(), [("DE_PLZ", "84028")], threshold=1)
        self.assertTrue(gen)

    def test_utility_needs_five(self):
        gen, _ = qig.decide_generalization(
            {"DE_PLZ", "DE_GENDER", "DE_BERUF"},
            [("DE_GEBURTSJAHR", "1979")],
            threshold=5,
        )
        self.assertFalse(gen)  # erst 4 Typen, Schwelle 5


# ===========================================================================
# 3. State-Store: Verschluesselung, fail-closed, TTL, Akkumulation
# ===========================================================================
class TestStateStore(unittest.TestCase):
    def test_missing_key_fails_closed(self):
        with self.assertRaises(qs.QiStateError):
            qs.QiStateStore(db_path=":memory:", fernet_key=None)

    def test_invalid_key_fails_closed(self):
        with self.assertRaises(qs.QiStateError):
            qs.QiStateStore(db_path=":memory:", fernet_key=b"nicht-fernet")

    def test_accumulates_distinct_types(self):
        store = qs.QiStateStore(db_path=":memory:", fernet_key=_key())
        store.record("sess-1", "DE_PLZ", "Region X")
        store.record("sess-1", "DE_GENDER", "[Geschlecht anonymisiert]")
        store.record("sess-1", "DE_PLZ", "Region Y")  # Wiederholung
        self.assertEqual(store.get_seen_types("sess-1"), {"DE_PLZ", "DE_GENDER"})

    def test_sessions_isolated(self):
        store = qs.QiStateStore(db_path=":memory:", fernet_key=_key())
        store.record("a", "DE_PLZ", "Region X")
        store.record("b", "DE_GENDER", "[x]")
        self.assertEqual(store.get_seen_types("a"), {"DE_PLZ"})
        self.assertEqual(store.get_seen_types("b"), {"DE_GENDER"})

    def test_never_persists_raw_value(self):
        # Rohwert darf NICHT im Klartext in der DB stehen (nur verschluesselt).
        store = qs.QiStateStore(db_path=":memory:", fernet_key=_key())
        store.record("s", "DE_PLZ", "Region Bayern (Süd)")
        rows = store._conn.execute(
            "SELECT session_hash, qi_type, category_enc FROM qi_session_state"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        session_hash, qi_type, blob = rows[0]
        self.assertNotIn("Region Bayern", session_hash)
        # category ist verschluesselt (Fernet-Token beginnt mit "gAAAAA")
        self.assertNotIn(b"Region Bayern", bytes(blob))
        # aber entschluesselbar
        self.assertEqual(store.get_categories("s"), [("DE_PLZ", "Region Bayern (Süd)")])

    def test_ttl_expiry(self):
        clock = {"t": 1000.0}
        store = qs.QiStateStore(
            db_path=":memory:", fernet_key=_key(), ttl_seconds=100, clock=lambda: clock["t"]
        )
        store.record("s", "DE_PLZ", "Region X")
        self.assertEqual(store.get_seen_types("s"), {"DE_PLZ"})
        # innerhalb TTL
        clock["t"] = 1099.0
        self.assertEqual(store.get_seen_types("s"), {"DE_PLZ"})
        # ueber TTL -> weg
        clock["t"] = 1201.0
        self.assertEqual(store.get_seen_types("s"), set())


# ===========================================================================
# 4. Session-Key-Aufloesung
# ===========================================================================
class TestSessionKeyResolution(unittest.TestCase):
    def test_prefers_litellm_session_id(self):
        key, coarse = qs.resolve_session_key({"litellm_session_id": "abc"}, None)
        self.assertEqual(key, "sid:abc")
        self.assertFalse(coarse)

    def test_metadata_session_id(self):
        key, coarse = qs.resolve_session_key({"metadata": {"session_id": "xy"}}, None)
        self.assertEqual(key, "sid:xy")
        self.assertFalse(coarse)

    def test_header_fallback(self):
        data = {"metadata": {"headers": {"x-litellm-session-id": "hdr"}}}
        key, coarse = qs.resolve_session_key(data, None)
        self.assertEqual(key, "sid:hdr")
        self.assertFalse(coarse)

    def test_api_key_hash_fallback_is_coarse(self):
        uak = types.SimpleNamespace(api_key="hashed-token-123")
        key, coarse = qs.resolve_session_key({}, uak)
        self.assertEqual(key, "apikey:hashed-token-123")
        self.assertTrue(coarse)

    def test_metadata_user_api_key_hash_fallback(self):
        data = {"metadata": {"user_api_key_hash": "h9"}}
        key, coarse = qs.resolve_session_key(data, None)
        self.assertEqual(key, "apikey:h9")
        self.assertTrue(coarse)

    def test_nothing_resolvable(self):
        key, coarse = qs.resolve_session_key({}, None)
        self.assertIsNone(key)


# ===========================================================================
# 5. Guardrail-Integration (Presidio gemockt, injizierter Store)
# ===========================================================================
def _guard_with_store(preset="balanced"):
    store = qs.QiStateStore(db_path=":memory:", fernet_key=_key())
    guard = dg.DatenschleuseGuardrail(qi_risk_preset=preset, qi_store=store)
    return guard, store


def _fake_analyze_factory(entity_map):
    """entity_map: dict value-substring -> entity_type. Baut ein _analyze,
    das fuer jede vorkommende Value die passende Entity zurueckliefert."""

    async def fake_analyze(text):
        out = []
        for value, etype in entity_map.items():
            idx = text.find(value)
            if idx >= 0:
                out.append(
                    {"entity_type": etype, "start": idx, "end": idx + len(value), "score": 0.9}
                )
        return out

    return fake_analyze


class TestGuardrailQiIntegration(unittest.IsolatedAsyncioTestCase):
    async def _run(self, guard, content, session_id="s1"):
        data = {
            "messages": [{"role": "user", "content": content}],
            "metadata": {"session_id": session_id},
        }
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        return out["messages"][0]["content"]

    async def test_below_threshold_keeps_qi_values(self):
        guard, _ = _guard_with_store("balanced")
        # 2 unterschiedliche QI-Typen ueber 2 Turns -> noch KEINE Generalisierung.
        guard._analyze = _fake_analyze_factory({"84028": "DE_PLZ"})
        c1 = await self._run(guard, "Meine PLZ ist 84028.")
        self.assertIn("84028", c1)  # unveraendert

        guard._analyze = _fake_analyze_factory({"männlich": "DE_GENDER"})
        c2 = await self._run(guard, "Ich bin männlich.")
        self.assertIn("männlich", c2)  # unveraendert (erst 2 Typen)

    async def test_third_type_triggers_generalization(self):
        guard, _ = _guard_with_store("balanced")
        guard._analyze = _fake_analyze_factory({"84028": "DE_PLZ"})
        await self._run(guard, "PLZ 84028.")
        guard._analyze = _fake_analyze_factory({"männlich": "DE_GENDER"})
        await self._run(guard, "Bin männlich.")
        # 3. Typ -> ab jetzt generalisieren
        guard._analyze = _fake_analyze_factory({"1979": "DE_GEBURTSJAHR"})
        c3 = await self._run(guard, "Jahrgang 1979.")
        self.assertNotIn("1979", c3)
        self.assertIn("Ende der 1970er", c3)

    async def test_paranoid_generalizes_first_qi(self):
        guard, _ = _guard_with_store("paranoid")
        guard._analyze = _fake_analyze_factory({"84028": "DE_PLZ"})
        c = await self._run(guard, "PLZ 84028.")
        self.assertNotIn("84028", c)
        self.assertIn("Region Bayern", c)

    async def test_utility_does_not_generalize_at_three(self):
        guard, _ = _guard_with_store("utility")  # Schwelle 5
        guard._analyze = _fake_analyze_factory({"84028": "DE_PLZ"})
        await self._run(guard, "PLZ 84028.")
        guard._analyze = _fake_analyze_factory({"männlich": "DE_GENDER"})
        await self._run(guard, "Bin männlich.")
        guard._analyze = _fake_analyze_factory({"1979": "DE_GEBURTSJAHR"})
        c3 = await self._run(guard, "Jahrgang 1979.")
        self.assertIn("1979", c3)  # unter utility (5) noch nicht generalisiert

    async def test_direct_masking_still_works_alongside_qi(self):
        guard, _ = _guard_with_store("paranoid")
        # PERSON (direkter Identifier) + DE_PLZ (QI) im selben Text.
        guard._analyze = _fake_analyze_factory(
            {"Max Mustermann": "PERSON", "84028": "DE_PLZ"}
        )
        data = {
            "messages": [{"role": "user", "content": "Max Mustermann, PLZ 84028."}],
            "metadata": {"session_id": "sx"},
        }
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        content = out["messages"][0]["content"]
        # direkter Identifier maskiert:
        self.assertIn("<PERSON_0>", content)
        self.assertNotIn("Max Mustermann", content)
        # QI generalisiert (paranoid):
        self.assertNotIn("84028", content)
        self.assertIn("Region Bayern", content)
        # Re-Id-Map enthaelt NUR den direkten Identifier, nicht die QI:
        reid = out["metadata"][dg.REID_MAP_KEY]
        self.assertEqual(reid, {"<PERSON_0>": "Max Mustermann"})

    async def test_qi_error_does_not_block_direct_masking(self):
        # QI-Store wirft -> Request darf NICHT geblockt werden, direkte
        # Maskierung muss trotzdem greifen.
        guard, store = _guard_with_store("balanced")

        def boom(*a, **k):
            raise RuntimeError("QI kaputt (simuliert)")

        store.get_seen_types = boom  # type: ignore[method-assign]
        guard._analyze = _fake_analyze_factory(
            {"Max Mustermann": "PERSON", "84028": "DE_PLZ"}
        )
        data = {
            "messages": [{"role": "user", "content": "Max Mustermann, PLZ 84028."}],
            "metadata": {"session_id": "sy"},
        }
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        content = out["messages"][0]["content"]
        # direkte Maskierung greift trotz QI-Fehler:
        self.assertIn("<PERSON_0>", content)
        self.assertNotIn("Max Mustermann", content)

    async def test_qi_disabled_by_default_no_key_needed(self):
        # Ohne Preset ist der QI-Layer aus -> Konstruktion OHNE State-Key ok,
        # QI-Werte laufen unveraendert durch (bzw. wie bisher).
        guard = dg.DatenschleuseGuardrail()
        self.assertFalse(guard.qi_enabled)
        guard._analyze = _fake_analyze_factory({"Max Mustermann": "PERSON"})
        data = {"messages": [{"role": "user", "content": "Max Mustermann hier."}]}
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        self.assertIn("<PERSON_0>", out["messages"][0]["content"])


class TestGuardrailFailClosedOnStateKey(unittest.TestCase):
    def test_enabled_without_key_raises(self):
        # QI aktiv, aber kein State-Key und kein injizierter Store -> harter
        # Abbruch beim Konstruieren (fail-closed beim Start).
        old = os.environ.pop("DATENSCHLEUSE_STATE_KEY", None)
        try:
            with self.assertRaises(qs.QiStateError):
                dg.DatenschleuseGuardrail(qi_risk_preset="balanced")
        finally:
            if old is not None:
                os.environ["DATENSCHLEUSE_STATE_KEY"] = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
