"""Unit-Tests fuer die Datenschleuse Custom-Guardrail.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm:
- Presidio-Calls werden gemockt / das Mapping wird direkt injiziert.
- Die reine Sliding-Window-Logik wird framework-frei getestet.

Ausfuehren (aus dem Repo-Root -- "test.test_datenschleuse_guardrail" kollidiert
mit dem Python-Stdlib-Paket "test" und schlaegt dort fehl, siehe DATENSCHLE-62):
    python3 -m unittest discover -s ./test -p "test_datenschleuse_guardrail.py" -v
    # oder aus dem test/-Ordner:
    python3 -m unittest test_datenschleuse_guardrail -v

Nutzt stdlib unittest.IsolatedAsyncioTestCase (kein pytest/pytest-asyncio noetig).
Fuer CI kann aequivalent mit pytest + pytest-asyncio gelaufen werden.
"""

import os
import re
import sys
import types
import unittest

# litellm/-Ordner (mit datenschleuse_guardrail.py) auf den Importpfad legen.
_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


# ---------------------------------------------------------------------------
# Test-Helfer: leichte Fake-Chunks, die wie ModelResponseStream aussehen
# (choices[0].delta.content). SimpleNamespace reicht — die Guardrail nutzt
# Attribut-Zugriff und copy.deepcopy, beides funktioniert damit.
# ---------------------------------------------------------------------------
def make_chunk(content, finish_reason=None):
    delta = types.SimpleNamespace(content=content)
    choice = types.SimpleNamespace(delta=delta, finish_reason=finish_reason, index=0)
    return types.SimpleNamespace(choices=[choice])


async def async_gen(chunks):
    for c in chunks:
        yield c


def collect_text_from_hook_output(chunks):
    """Sammelt den re-identifizierten Volltext aus den vom Streaming-Hook
    ausgegebenen Chunks."""
    out = []
    for c in chunks:
        content = c.choices[0].delta.content
        if isinstance(content, str):
            out.append(content)
    return "".join(out)


# ===========================================================================
# 1. Reine Sliding-Window-Logik
# ===========================================================================
class TestReidStreamProcessor(unittest.TestCase):
    def test_split_placeholder_over_two_chunks(self):
        """KERN-TEST: Platzhalter kommt ueber zwei Chunk-Grenzen gesplittet an.
        Chunk 1 endet mit '<PERS', Chunk 2 startet mit 'ON_1> hat angerufen'."""
        mapping = {"<PERSON_1>": "Max Mustermann"}
        proc = dg.ReidStreamProcessor(mapping)

        out = []
        out.append(proc.feed("Guten Tag, <PERS"))
        out.append(proc.feed("ON_1> hat angerufen"))
        out.append(proc.flush())
        result = "".join(out)

        self.assertEqual(result, "Guten Tag, Max Mustermann hat angerufen")
        self.assertNotIn("<PERSON_1>", result)
        self.assertNotIn("<PERS", result)

    def test_split_placeholder_char_by_char(self):
        """Extremfall: der Platzhalter kommt Zeichen fuer Zeichen an."""
        mapping = {"<EMAIL_ADDRESS_0>": "max@example.de"}
        proc = dg.ReidStreamProcessor(mapping)
        full = "Mail an <EMAIL_ADDRESS_0> bitte."
        out = [proc.feed(ch) for ch in full]
        out.append(proc.flush())
        result = "".join(out)
        self.assertEqual(result, "Mail an max@example.de bitte.")

    def test_multiple_placeholders_and_partial_at_end(self):
        """Mehrere Platzhalter, letzter Platzhalter endet exakt am Stream-Ende
        (Rest-Puffer muss via flush() emittiert werden)."""
        mapping = {"<PERSON_0>": "Anna", "<LOCATION_0>": "Weimar"}
        proc = dg.ReidStreamProcessor(mapping)
        out = []
        out.append(proc.feed("<PERSON_0> wohnt in <LOCA"))
        out.append(proc.feed("TION_0>"))
        out.append(proc.flush())
        self.assertEqual("".join(out), "Anna wohnt in Weimar")

    def test_superstring_placeholder_not_corrupted(self):
        """<PERSON_1> darf nicht INNERHALB von <PERSON_10> matchen."""
        mapping = {"<PERSON_1>": "Bob", "<PERSON_10>": "Alice"}
        proc = dg.ReidStreamProcessor(mapping)
        out = [proc.feed("A: <PERSON_10>, B: <PERSON_1>."), proc.flush()]
        self.assertEqual("".join(out), "A: Alice, B: Bob.")

    def test_no_mapping_passes_through_unbuffered(self):
        """Ohne Platzhalter wird jedes Delta sofort und unveraendert
        durchgereicht (kein Latenz-Verlust)."""
        proc = dg.ReidStreamProcessor({})
        self.assertEqual(proc.feed("hallo "), "hallo ")
        self.assertEqual(proc.feed("welt"), "welt")
        self.assertEqual(proc.flush(), "")

    def test_window_size_relates_to_longest_placeholder(self):
        """Fenstergroesse = laengster Platzhalter + Marge."""
        mapping = {"<PERSON_0>": "X", "<DE_SOZIALVERSICHERUNG_0>": "Y"}
        proc = dg.ReidStreamProcessor(mapping, margin=10)
        longest = max(len(k) for k in mapping)
        self.assertEqual(proc.window, longest + 10)

    def test_no_partial_placeholder_ever_emitted(self):
        """Invariante: solange ein Platzhalter unvollstaendig ist, darf sein
        Anfang NIE emittiert werden."""
        mapping = {"<PHONE_NUMBER_0>": "030 1234567"}
        proc = dg.ReidStreamProcessor(mapping)
        emitted = proc.feed("Ruf an: <PHONE_NUMBER")  # unvollstaendig
        self.assertNotIn("<PHONE", emitted)  # Anfang zurueckgehalten
        rest = proc.feed("_0> danke") + proc.flush()
        self.assertEqual(emitted + rest, "Ruf an: 030 1234567 danke")


# ===========================================================================
# 2. Non-Streaming Voll-Ersatz
# ===========================================================================
class TestReidentifyFull(unittest.TestCase):
    def test_full_replace(self):
        mapping = {"<PERSON_0>": "Max Mustermann", "<IBAN_CODE_0>": "DE89370400440532013000"}
        text = "<PERSON_0> mit IBAN <IBAN_CODE_0>."
        self.assertEqual(
            dg.reidentify_full(text, mapping),
            "Max Mustermann mit IBAN DE89370400440532013000.",
        )

    def test_empty_inputs(self):
        self.assertEqual(dg.reidentify_full("", {"<X_0>": "y"}), "")
        self.assertEqual(dg.reidentify_full("abc", {}), "abc")


# ===========================================================================
# 3. Masker (Analyzer-Ergebnisse -> maskierter Text + Mapping)
# ===========================================================================
class TestMasker(unittest.TestCase):
    def test_basic_masking_and_map(self):
        text = "Max Mustermann wohnt in Weimar."
        # Presidio-/analyze-artige Entities:
        entities = [
            {"entity_type": "PERSON", "start": 0, "end": 14, "score": 0.99},
            {"entity_type": "LOCATION", "start": 24, "end": 30, "score": 0.85},
        ]
        m = dg.Masker()
        masked = m.mask(text, entities)
        self.assertEqual(masked, "<PERSON_0> wohnt in <LOCATION_0>.")
        self.assertEqual(m.reid_map["<PERSON_0>"], "Max Mustermann")
        self.assertEqual(m.reid_map["<LOCATION_0>"], "Weimar")
        # Roundtrip
        self.assertEqual(dg.reidentify_full(masked, m.reid_map), text)

    def test_duplicate_value_shares_placeholder(self):
        text = "Anna und Anna"
        entities = [
            {"entity_type": "PERSON", "start": 0, "end": 4, "score": 0.9},
            {"entity_type": "PERSON", "start": 9, "end": 13, "score": 0.9},
        ]
        m = dg.Masker()
        masked = m.mask(text, entities)
        self.assertEqual(masked, "<PERSON_0> und <PERSON_0>")
        self.assertEqual(len(m.reid_map), 1)

    def test_distinct_values_get_distinct_numbers(self):
        text = "Anna und Bob"
        entities = [
            {"entity_type": "PERSON", "start": 0, "end": 4, "score": 0.9},
            {"entity_type": "PERSON", "start": 9, "end": 12, "score": 0.9},
        ]
        m = dg.Masker()
        masked = m.mask(text, entities)
        self.assertEqual(masked, "<PERSON_0> und <PERSON_1>")

    def test_overlap_resolution_keeps_higher_score(self):
        text = "Frankfurt"
        entities = [
            {"entity_type": "LOCATION", "start": 0, "end": 9, "score": 0.9},
            {"entity_type": "PERSON", "start": 0, "end": 9, "score": 0.4},
        ]
        m = dg.Masker()
        masked = m.mask(text, entities)
        self.assertEqual(masked, "<LOCATION_0>")

    def test_shared_masker_across_messages(self):
        """Derselbe Wert in zwei Nachrichten teilt den Platzhalter."""
        m = dg.Masker()
        e = [{"entity_type": "PERSON", "start": 0, "end": 4, "score": 0.9}]
        self.assertEqual(m.mask("Anna sagt", e), "<PERSON_0> sagt")
        self.assertEqual(m.mask("Anna ok", e), "<PERSON_0> ok")
        self.assertEqual(len(m.reid_map), 1)


# ===========================================================================
# 4. Streaming-Hook end-to-end (mit injiziertem Mapping, ohne litellm/presidio)
# ===========================================================================
class TestStreamingHook(unittest.IsolatedAsyncioTestCase):
    async def test_hook_reidentifies_split_placeholder(self):
        guard = dg.DatenschleuseGuardrail()
        request_data = {"metadata": {dg.REID_MAP_KEY: {"<PERSON_1>": "Max Mustermann"}}}

        # Platzhalter ueber Chunk-Grenze gesplittet:
        chunks = [
            make_chunk("Guten Tag, <PERS"),
            make_chunk("ON_1> hat"),
            make_chunk(" angerufen"),
            make_chunk(None, finish_reason="stop"),  # finish-Chunk ohne Text
        ]

        out = []
        async for c in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None, response=async_gen(chunks), request_data=request_data
        ):
            out.append(c)

        text = collect_text_from_hook_output(out)
        self.assertEqual(text, "Guten Tag, Max Mustermann hat angerufen")
        self.assertNotIn("<PERSON_1>", text)

    async def test_hook_passes_through_without_map(self):
        guard = dg.DatenschleuseGuardrail()
        request_data = {"metadata": {}}  # kein Mapping
        chunks = [make_chunk("hallo "), make_chunk("welt")]
        out = []
        async for c in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None, response=async_gen(chunks), request_data=request_data
        ):
            out.append(c)
        self.assertEqual(collect_text_from_hook_output(out), "hallo welt")

    async def test_hook_reads_litellm_metadata_key(self):
        """Mapping auch unter 'litellm_metadata' auffindbar."""
        guard = dg.DatenschleuseGuardrail()
        request_data = {"litellm_metadata": {dg.REID_MAP_KEY: {"<LOCATION_0>": "Weimar"}}}
        chunks = [make_chunk("Ort: <LOCA"), make_chunk("TION_0>.")]
        out = []
        async for c in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None, response=async_gen(chunks), request_data=request_data
        ):
            out.append(c)
        self.assertEqual(collect_text_from_hook_output(out), "Ort: Weimar.")


# ===========================================================================
# 5. Pre-Call-Hook (Presidio gemockt) + Fail-closed
# ===========================================================================
class TestPreCallHook(unittest.IsolatedAsyncioTestCase):
    async def test_pre_call_masks_and_stores_map(self):
        guard = dg.DatenschleuseGuardrail()

        # _analyze mocken: liefert deterministische Entities zurueck.
        async def fake_analyze(text):
            if "Max Mustermann" in text:
                idx = text.index("Max Mustermann")
                return [{"entity_type": "PERSON", "start": idx, "end": idx + 14, "score": 0.99}]
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]

        data = {
            "messages": [
                {"role": "system", "content": "Du bist hilfreich."},
                {"role": "user", "content": "Max Mustermann braucht Hilfe."},
            ]
        }
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        self.assertEqual(out["messages"][1]["content"], "<PERSON_0> braucht Hilfe.")
        self.assertEqual(out["metadata"][dg.REID_MAP_KEY], {"<PERSON_0>": "Max Mustermann"})

    async def test_pre_call_fail_closed_blocks_on_analyzer_error(self):
        """Fail-closed: wenn der Analyzer nicht erreichbar ist, MUSS der Request
        geblockt werden (Exception), nicht unmaskiert durchgehen."""
        guard = dg.DatenschleuseGuardrail()

        async def broken_analyze(text):
            raise dg.DatenschleuseBlocked("Presidio down (simuliert)")

        guard._analyze = broken_analyze  # type: ignore[method-assign]

        data = {"messages": [{"role": "user", "content": "Max Mustermann hier."}]}
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )

    async def test_pre_call_appends_anonymization_notice_to_existing_system_msg(self):
        guard = dg.DatenschleuseGuardrail()

        async def fake_analyze(text):
            if "Max Mustermann" in text:
                idx = text.index("Max Mustermann")
                return [{"entity_type": "PERSON", "start": idx, "end": idx + 14, "score": 0.99}]
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]

        data = {
            "messages": [
                {"role": "system", "content": "Du bist hilfreich."},
                {"role": "user", "content": "Max Mustermann braucht Hilfe."},
            ]
        }
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        sys_content = out["messages"][0]["content"]
        self.assertTrue(sys_content.startswith("Du bist hilfreich."))
        self.assertIn(dg.ANONYMIZATION_NOTICE, sys_content)

    async def test_pre_call_inserts_system_msg_when_none_exists(self):
        guard = dg.DatenschleuseGuardrail()

        async def fake_analyze(text):
            if "Max Mustermann" in text:
                idx = text.index("Max Mustermann")
                return [{"entity_type": "PERSON", "start": idx, "end": idx + 14, "score": 0.99}]
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]

        data = {"messages": [{"role": "user", "content": "Max Mustermann braucht Hilfe."}]}
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        self.assertEqual(out["messages"][0]["role"], "system")
        self.assertEqual(out["messages"][0]["content"], dg.ANONYMIZATION_NOTICE)
        self.assertEqual(out["messages"][1]["content"], "<PERSON_0> braucht Hilfe.")

    async def test_pre_call_no_notice_when_nothing_masked(self):
        """Kein Overhead fuer PII-freie Requests: ohne Treffer keine Notice,
        keine zusaetzliche System-Message."""
        guard = dg.DatenschleuseGuardrail()

        async def fake_analyze(text):
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]

        data = {"messages": [{"role": "user", "content": "Wie spaet ist es?"}]}
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        self.assertEqual(len(out["messages"]), 1)
        self.assertEqual(out["messages"][0]["content"], "Wie spaet ist es?")

    async def test_analyze_fail_closed_on_http_error(self):
        """_analyze selbst: HTTP-Fehler -> DatenschleuseBlocked (fail-closed).
        Wir mocken httpx, damit kein echter Container noetig ist."""
        guard = dg.DatenschleuseGuardrail(presidio_analyzer_url="http://unreachable:3000")

        class _FakeClient:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                raise dg.httpx.ConnectError("connection refused (simuliert)")

        orig = dg.httpx.AsyncClient
        dg.httpx.AsyncClient = _FakeClient  # type: ignore[assignment]
        try:
            with self.assertRaises(dg.DatenschleuseBlocked):
                await guard._analyze("Max Mustermann")
        finally:
            dg.httpx.AsyncClient = orig  # type: ignore[assignment]


# ===========================================================================
# 6. Non-Streaming Success-Hook
# ===========================================================================
class TestSuccessHook(unittest.IsolatedAsyncioTestCase):
    async def test_success_hook_replaces_content(self):
        guard = dg.DatenschleuseGuardrail()
        data = {"metadata": {dg.REID_MAP_KEY: {"<PERSON_0>": "Max Mustermann"}}}
        message = types.SimpleNamespace(content="Hallo <PERSON_0>!")
        choice = types.SimpleNamespace(message=message)
        response = types.SimpleNamespace(choices=[choice])

        out = await guard.async_post_call_success_hook(
            data=data, user_api_key_dict=None, response=response
        )
        self.assertEqual(out.choices[0].message.content, "Hallo Max Mustermann!")


# ===========================================================================
# 7. Kollision zwischen Beispiel-Platzhaltern im Hinweis und ECHTEN
#    Platzhaltern (Befund aus dem E2E-Round-Trip-Beweis, DATENSCHLE-67)
# ===========================================================================
class TestNoticePlaceholderCollision(unittest.IsolatedAsyncioTestCase):
    """Der Anonymisierungs-Hinweis nennt Beispiel-Platzhalter. Haben diese
    dieselbe Form wie die ECHTEN (``<TYP_ZAHL>``), koennen sie mit ihnen
    kollidieren.

    Beobachtet im E2E-Lauf (test/e2e_roundtrip.py, AK4): der Hinweis nannte
    ``<PERSON_1>`` als Beispiel, waehrend ``<PERSON_1>`` im selben Request der
    echte Platzhalter fuer "Thomas Schneider" war. Das Modell sieht dann
    denselben Token zweimal in voellig verschiedener Bedeutung -- einmal als
    Erklaerungsbeispiel, einmal als Daten. Greift es das Beispiel auf, macht
    die Re-Identifikation daraus stillschweigend den echten Namen und setzt
    ihn an eine Stelle, an die er nie gehoerte.

    Kein PII-Leck (der Klartext geht nach wie vor nicht raus), aber eine
    falsche Antwort -- exakt dieselbe Fehlerklasse wie der dokumentierte
    Live-Befund vom 2026-07-29 ("Hallo Hans Mueller!"), nur eine Ebene
    subtiler: dort war es ein Beispiel-NAME, hier ein Beispiel-PLATZHALTER.
    """

    # Genau die Form, die Masker._placeholder_for() erzeugt: <TYP_ZAHL>.
    REAL_PLACEHOLDER_SHAPE = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")
    # Jeder platzhalter-AEHNLICHE Token in spitzen Klammern -- also auch
    # Schablonen wie <PERSON_N> oder <TYP_NUMMER>. Siehe zweiten Test.
    ANY_BRACKET_TOKEN = re.compile(r"<[A-Z][A-Z0-9_]*>")

    def test_notice_contains_no_token_masker_could_produce(self):
        collidable = self.REAL_PLACEHOLDER_SHAPE.findall(dg.ANONYMIZATION_NOTICE)
        self.assertEqual(
            collidable, [],
            "Der Hinweis nennt Beispiel-Platzhalter in genau der Form, die der "
            "Masker auch fuer echte Werte vergibt -- sie koennen deshalb mit "
            f"echten Platzhaltern kollidieren: {collidable}",
        )

    def test_notice_contains_no_placeholder_template_either(self):
        """Regression zum teuersten Fehlversuch dieses Items (DATENSCHLE-67).

        Ein erster Fix ersetzte die kollidierenden Beispiele durch die
        Schablone <PERSON_N> und erklaerte dazu "wobei N fuer eine Ziffer
        steht". Gemessen gegen llama3.1:8b: das Modell setzte daraufhin
        PFLICHTBEWUSST eine Ziffer ein und gab <PERSON_1> zurueck, wo
        <PERSON_0> stand -- in 3 von 3 Laeufen, bei temperature 0. Damit war
        JEDER Platzhalter der Antwort unbrauchbar: die Re-Identifikation
        findet <PERSON_1> nicht im Mapping und laesst ihn stehen (stiller
        Fehler, siehe docs/HEADROOM.md) -- oder ersetzt ihn durch eine ANDERE
        Person, falls es zufaellig einen echten <PERSON_1> gibt.

        Die Lehre ist allgemeiner als der eine Token: Ein Hinweis, der dem
        Modell irgendetwas Platzhalter-Foermiges zum Nachbauen hinhaelt, wird
        nachgebaut. Deshalb darf der Hinweis GAR KEINEN Token in spitzen
        Klammern enthalten -- weder echte (<PERSON_1>) noch schablonenhafte
        (<PERSON_N>, <TYP_NUMMER>). Er beschreibt das Prinzip in Worten.
        """
        tokens = self.ANY_BRACKET_TOKEN.findall(dg.ANONYMIZATION_NOTICE)
        self.assertEqual(
            tokens, [],
            "Der Hinweis haelt dem Modell platzhalter-foermige Tokens zum "
            f"Nachbauen hin: {tokens}. Gemessen wurde, dass llama3.1:8b eine "
            "Schablone wie <PERSON_N> mit einer echten Ziffer instanziiert und "
            "damit den Index der echten Platzhalter ueberschreibt.",
        )

    def test_notice_contains_no_angle_bracket_at_all(self):
        """Die Invariante, die wir wirklich behaupten -- und die einzige, die
        haelt (Security-Audit-Finding zu DATENSCHLE-67).

        Die beiden Tests darueber pruefen Regexe auf durchgaengig
        GROSSGESCHRIEBENE Tokens. Damit laufen <Person_1>, <Name_1>,
        <Platzhalter>, <PERSON 1> und <PERSON-1> allesamt durch -- ein
        kuenftiger Bearbeiter, der den Hinweis "verstaendlicher" macht und
        <Person_1> einfuegt, stellt die urspruengliche Falle wieder her, und
        beide Tests bleiben gruen.

        Der Hinweis braucht ueberhaupt keine spitze Klammer: er beschreibt das
        Prinzip in Worten. Also ist das Verbot der oeffnenden Klammer die
        praezise, nicht umgehbare Form der Regel. Die beiden Regex-Tests
        bleiben als Dokumentation der historischen Faelle stehen.
        """
        self.assertNotIn(
            "<", dg.ANONYMIZATION_NOTICE,
            "Der Hinweis enthaelt eine spitze Klammer. Alles, was der Hinweis "
            "dem Modell platzhalter-foermig hinhaelt, baut das Modell nach -- "
            "zweimal in diesem Projekt belegt (Beispiel-Platzhalter, dann "
            "Schablone). Er beschreibt das Prinzip in Worten und braucht "
            "deshalb keine Klammer.",
        )

    def test_notice_still_says_something_useful(self):
        """Gegenprobe zur Verbots-Assertion (Security-Audit-Finding, zweite
        Haelfte): ein auf Leerstring reduzierter Hinweis wuerde jede
        Verbotspruefung bestehen, waehrend die Re-Identifikation still
        degradiert -- das Modell wuesste dann nicht mehr, dass Platzhalter
        Absicht sind, und begaenne sie umzuformulieren oder nachzufragen.

        Deshalb hier die Mindestaussage: der Hinweis muss die drei Dinge
        leisten, wegen denen es ihn gibt. Bewusst auf Schluesselbegriffe
        gepinnt statt auf den Wortlaut -- Umformulieren bleibt erlaubt,
        Aushoehlen nicht.
        """
        notice = dg.ANONYMIZATION_NOTICE
        self.assertGreater(
            len(notice), 150,
            "Hinweis ist auf eine Laenge geschrumpft, die das Prinzip nicht "
            f"mehr erklaeren kann ({len(notice)} Zeichen).",
        )
        for begriff, zweck in (
            ("Platzhalter", "benennt, worum es geht"),
            ("kein Tippfehler", "sagt, dass es Absicht ist"),
            ("exakt", "verlangt woertliche Rueckgabe"),
            ("unveränderter Nummer", "schuetzt den Index (Befund DATENSCHLE-67)"),
        ):
            self.assertIn(
                begriff, notice,
                f"Dem Hinweis fehlt '{begriff}' -- der Teil, der {zweck}.",
            )

    async def test_notice_examples_never_collide_with_real_reid_map(self):
        """Verhaltensnachweis: kein platzhalterfoermiger Token aus dem Hinweis
        darf ein Schluessel des echten reid_map sein."""
        guard = dg.DatenschleuseGuardrail()

        names = ("Maria Meier", "Thomas Schneider")

        async def fake_analyze(text):
            out = []
            for name in names:
                start = 0
                while True:
                    idx = text.find(name, start)
                    if idx < 0:
                        break
                    out.append({"entity_type": "PERSON", "start": idx,
                                "end": idx + len(name), "score": 0.99})
                    start = idx + len(name)
            return out

        guard._analyze = fake_analyze  # type: ignore[method-assign]

        data = {
            "messages": [
                {"role": "user",
                 "content": "Maria Meier hat angerufen. Thomas Schneider war dabei. "
                            "Maria Meier hat erneut angerufen."},
            ]
        }
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        reid_map = out["metadata"][dg.REID_MAP_KEY]
        notice_text = out["messages"][0]["content"]

        # Vorbedingung des Befunds: es gibt ueberhaupt zwei echte Personen-
        # Platzhalter, darunter <PERSON_1>.
        self.assertEqual(sorted(reid_map), ["<PERSON_0>", "<PERSON_1>"])

        tokens_in_notice = set(self.REAL_PLACEHOLDER_SHAPE.findall(notice_text))
        collisions = sorted(tokens_in_notice & set(reid_map))
        self.assertEqual(
            collisions, [],
            "Beispiel-Platzhalter aus dem Hinweis sind gleichzeitig echte "
            f"Platzhalter dieses Requests: {collisions}. Greift das Modell das "
            "Beispiel auf, re-identifiziert die Datenschleuse es zu "
            f"{[reid_map[c] for c in collisions]}.",
        )

    async def test_stable_mapping_same_value_same_placeholder(self):
        """AK4 als schneller Unit-Test (der E2E-Lauf beweist dasselbe gegen den
        echten Stack, braucht dafuer aber Docker)."""
        guard = dg.DatenschleuseGuardrail()

        async def fake_analyze(text):
            out = []
            for name in ("Maria Meier", "Thomas Schneider"):
                start = 0
                while True:
                    idx = text.find(name, start)
                    if idx < 0:
                        break
                    out.append({"entity_type": "PERSON", "start": idx,
                                "end": idx + len(name), "score": 0.99})
                    start = idx + len(name)
            return out

        guard._analyze = fake_analyze  # type: ignore[method-assign]

        data = {"messages": [{"role": "user",
                              "content": "Maria Meier und Thomas Schneider und Maria Meier."}]}
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        masked = out["messages"][-1]["content"]
        self.assertEqual(masked, "<PERSON_0> und <PERSON_1> und <PERSON_0>.")
        self.assertEqual(out["metadata"][dg.REID_MAP_KEY],
                         {"<PERSON_0>": "Maria Meier", "<PERSON_1>": "Thomas Schneider"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
