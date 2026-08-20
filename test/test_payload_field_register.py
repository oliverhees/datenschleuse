"""Unit-Tests fuer das TOP-LEVEL-FELD-REGISTER des Payloads (DATENSCHLE-69).

Hintergrund
-----------
Die Guardrail hatte dieselbe Bauart-Luecke inzwischen fuenfmal, jedes Mal eine
Ebene hoeher oder tiefer entdeckt:

  * DATENSCHLE-57  Content-Part-Typen innerhalb von ``content``
  * DATENSCHLE-64  der ``content``-Container selbst
  * DATENSCHLE-65  die Felder eines Parts
  * DATENSCHLE-66  jedes Feld NEBEN ``content`` (und ``messages`` selbst)
  * DATENSCHLE-69  die ROUTE (``call_type``)

Ursache war jedes Mal dieselbe: gelesen wurde, was man kannte -- alles Uebrige
lief still durch. Der Routen-Fix registrierte die ROUTE, liess aber die FELDER
dieser Route ungeprueft. Das ist die sechste Instanz, auf der letzten noch
offenen Ebene: den TOP-LEVEL-FELDERN des Payloads.

Belegte Leck-Kanaele (litellm 1.97.0, empirisch)
------------------------------------------------
``litellm.utils.get_non_default_completion_params`` (utils.py:3576) filtert
Top-Level-Keys gegen ``litellm.types.utils.all_litellm_params``. Was NICHT in
dieser Liste steht, geht an den Provider -- entweder als benannter
OpenAI-Parameter (``main.py:7154`` fuer ``suffix``) oder ueber ``extra_body``
(``utils.py:4422``). Damit gilt nachweisbar:

  | Feld            | in all_litellm_params | Folge                   |
  |-----------------|-----------------------|-------------------------|
  | ``suffix``      | nein                  | geht raus (direkt)      |
  | ``stop``        | nein                  | geht raus (direkt)      |
  | ``user``        | nein                  | geht raus (direkt)      |
  | ``tools``       | nein                  | geht raus (direkt)      |
  | ``prompt``      | nein                  | geht raus               |
  | beliebiges Feld | nein                  | geht raus (extra_body)  |
  | ``metadata``    | ja                    | bleibt litellm-intern   |

Abgedeckte Findings
-------------------
F1  Geschwisterfelder des ``prompt`` (``suffix``, ``stop``, ``user``) gingen
    unmaskiert hinaus. Angriffsszenario: ein FIM-/Code-Completion-Client legt
    den Kontext HINTER der Einfuegestelle in ``suffix`` -- bei einem Kanzlei-
    oder Praxisdokument stehen dort Mandanten- bzw. Patientendaten.
F2  ``_apply_qi_to_slots`` konnte nur dict-Container. Bei ``prompt`` als LISTE
    (die von OpenAI spezifizierte Batch-Form) wurden die QI-Slots STILL
    uebersprungen -- PLZ und Geburtsjahr gingen in voller Aufloesung hinaus,
    weil der Masker QI-Typen bewusst dem QI-Layer ueberlaesst.
F3  Die Chat-Route hatte gar keine Payload-Formpruefung: ein mitgeschicktes
    Top-Level-``prompt``, ein fehlendes ``messages`` und
    ``tools[].function.description`` liefen ungeprueft hinaus.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_payload_field_register.py" -v
"""

import json
import os
import sys
import types
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402
import qi_state as qs  # noqa: E402

from cryptography.fernet import Fernet  # noqa: E402


# ===========================================================================
# Fixtures
# ===========================================================================
# Deterministischer Presidio-Ersatz im Stil der bestehenden Tests: kein
# Container, keine HTTP-Calls, feste Entity-Positionen.
_NEEDLES = (
    ("Max Mustermann", "PERSON"),
    ("Erika Musterfrau", "PERSON"),
    ("DE02120300000000202051", "IBAN_CODE"),
    ("max@example.com", "EMAIL_ADDRESS"),
)

# Der Wert, an dem ein Leck sichtbar wird: steht er nach dem Hook noch im
# Klartext irgendwo im ausgehenden Payload, ist er auf dem Weg zum Cloud-Modell.
_IBAN = "DE02120300000000202051"
_NAME = "Max Mustermann"


async def fake_analyze(text):
    """Findet alle bekannten Testwerte an ihren echten Positionen im Text."""
    found = []
    for needle, entity_type in _NEEDLES:
        start = 0
        while True:
            idx = text.find(needle, start)
            if idx < 0:
                break
            found.append(
                {
                    "entity_type": entity_type,
                    "start": idx,
                    "end": idx + len(needle),
                    "score": 0.99,
                }
            )
            start = idx + len(needle)
    return found


def _guard(**kwargs):
    guard = dg.DatenschleuseGuardrail(**kwargs)
    guard._analyze = fake_analyze
    return guard


def _plain(value):
    """Der ausgehende Payload als ein durchsuchbarer String.

    Bewusst grob: ein Leck ist ein Leck, egal in welchem Feld der Klartext
    am Ende steht. Genau diese Grobheit hat die F1/F3-PoCs gefunden.

    EINE Ausnahme, und nur diese: ``metadata[REID_MAP_KEY]``. Dort MUSS der
    Klartext stehen -- das Mapping ist der Rueckweg, ohne den die Antwort
    nicht re-identifiziert werden kann. Es ist kein Ausgangskanal:
    ``metadata`` steht in litellms ``all_litellm_params`` und wird von
    ``get_non_default_completion_params`` herausgefiltert, erreicht den
    Provider also nicht. Genau deshalb steht ``metadata`` im Register unter
    PAYLOAD_FIELDS_INFRASTRUCTURE und nicht unter den maskierten Feldern.
    """
    if isinstance(value, dict) and isinstance(value.get("metadata"), dict):
        value = dict(value)
        value["metadata"] = {
            k: v for k, v in value["metadata"].items() if k != dg.REID_MAP_KEY
        }
    return json.dumps(value, ensure_ascii=False, default=str)


class _HookCase(unittest.IsolatedAsyncioTestCase):
    async def run_hook(self, data, call_type, guard=None):
        guard = guard or _guard()
        return await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type=call_type
        )

    async def assert_blocked(self, data, call_type, guard=None):
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await self.run_hook(data, call_type, guard=guard)
        # Gesetz 5: eine Blockmeldung darf NIE einen Client-Wert enthalten.
        self.assertNotIn(_IBAN, str(ctx.exception))
        self.assertNotIn(_NAME, str(ctx.exception))
        return ctx.exception

    async def assert_no_leak(self, data, call_type, guard=None):
        out = await self.run_hook(data, call_type, guard=guard)
        flat = _plain(out)
        self.assertNotIn(_IBAN, flat, "PII im ausgehenden Payload (Leck!)")
        self.assertNotIn(_NAME, flat, "PII im ausgehenden Payload (Leck!)")
        return out


# ===========================================================================
# F1 -- Geschwisterfelder des prompt (Text-Route /v1/completions)
# ===========================================================================
class TestF1TextRouteSiblingFields(_HookCase):
    """Der Commit registrierte die ROUTE und liess die FELDER dieser Route
    ungeprueft: ``_mask_text_prompt`` prueft nur, dass kein ``messages`` da
    ist, dass ``prompt`` existiert und String oder String-Liste ist. Jedes
    andere Feld des Bodys wurde weder maskiert noch geblockt."""

    async def test_suffix_mit_pii_geht_nicht_unmaskiert_raus(self):
        # DER PoC: prompt sauber, die PII steckt im suffix -- genau die
        # FIM-Aufteilung eines Code-/Dokument-Completion-Clients.
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Schreibe die Rechnung fertig:",
            "suffix": f" Kunde {_NAME}, IBAN {_IBAN}",
        }
        await self.assert_no_leak(data, "atext_completion")

    async def test_suffix_wird_ueber_dasselbe_reid_map_maskiert(self):
        # Kein zweites Mapping: derselbe Wert muss in prompt und suffix
        # DENSELBEN Platzhalter bekommen, sonst bricht der Rueckweg.
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": f"Vorgang von {_NAME}:",
            "suffix": f" -- gezeichnet {_NAME}",
        }
        out = await self.assert_no_leak(data, "atext_completion")
        reid = out["metadata"][dg.REID_MAP_KEY]
        platzhalter = [p for p, v in reid.items() if v == _NAME]
        self.assertEqual(
            len(platzhalter), 1, "derselbe Name muss EINEN Platzhalter haben"
        )
        self.assertIn(platzhalter[0], out["prompt"])
        self.assertIn(platzhalter[0], out["suffix"])

    async def test_stop_mit_pii_geht_nicht_unmaskiert_raus(self):
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Fasse zusammen:",
            "stop": [f"Ende {_NAME}"],
        }
        await self.assert_no_leak(data, "atext_completion")

    async def test_user_mit_pii_geht_nicht_unmaskiert_raus(self):
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hallo.",
            "user": "max@example.com",
        }
        out = await self.run_hook(data, "atext_completion")
        self.assertNotIn("max@example.com", _plain(out))

    async def test_unbekanntes_top_level_feld_blockt(self):
        # Kontrollprobe: ein frei erfundenes Feld landet in litellm bei
        # ``extra_body`` und geht damit an den Provider. Was die Datenschleuse
        # nicht prueft, darf nicht rausgehen.
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hallo.",
            "voellig_unbekanntes_feld": f"IBAN {_IBAN}",
        }
        await self.assert_blocked(data, "atext_completion")

    async def test_bekanntes_aber_unbehandeltes_feld_wird_benannt(self):
        # "Was du nicht behandelst, blockt -- und wird benannt."
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hallo.",
            "extra_headers": {"X-Kunde": _NAME},
        }
        exc = await self.assert_blocked(data, "atext_completion")
        self.assertIn("extra_headers", str(exc))

    async def test_steuerparameter_bleiben_unveraendert(self):
        # Das Register darf den Normalbetrieb nicht brechen.
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hallo.",
            "temperature": 0.2,
            "max_tokens": 128,
            "n": 1,
            "stream": False,
            "top_p": 0.9,
            "echo": False,
            "best_of": 1,
        }
        out = await self.run_hook(data, "atext_completion")
        self.assertEqual(out["temperature"], 0.2)
        self.assertEqual(out["max_tokens"], 128)

    async def test_falscher_typ_in_bekanntem_feld_blockt(self):
        # Lehre aus DATENSCHLE-66 F1: ein isinstance-Guard im Mask-Pfad ist
        # immer ein stiller Durchlass. Die Typpruefung gehoert in den
        # Validate-Pfad und muss blocken.
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hallo.",
            "suffix": {"versteckt": f"IBAN {_IBAN}"},
        }
        await self.assert_blocked(data, "atext_completion")

    async def test_temperature_als_freitext_blockt(self):
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hallo.",
            "temperature": f"IBAN {_IBAN}",
        }
        await self.assert_blocked(data, "atext_completion")

    async def test_litellm_interne_felder_passieren(self):
        # metadata/proxy_server_request/secret_fields werden vom Proxy selbst
        # gesetzt (empirisch gegen litellm 1.97.0) und stehen in
        # all_litellm_params -> sie erreichen den Provider nicht.
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hallo.",
            "metadata": {"session_id": "s1"},
            "proxy_server_request": {"body": {}},
            "secret_fields": object(),
        }
        out = await self.run_hook(data, "atext_completion")
        self.assertIn("metadata", out)


# ===========================================================================
# F3 -- die Chat-Route hatte gar keine Payload-Formpruefung
# ===========================================================================
class TestF3ChatRoutePayloadShape(_HookCase):
    async def test_top_level_prompt_unter_chat_calltype_blockt(self):
        # Spiegelbild der bestehenden Regel: die Text-Route blockt ein
        # mitgeschicktes ``messages``. Die Mehrdeutigkeitsregel
        # (security-baseline.md) muss in BEIDE Richtungen gelten.
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "prompt": f"IBAN {_IBAN}",
        }
        await self.assert_blocked(data, "acompletion")

    async def test_fehlendes_messages_unter_chat_calltype_blockt(self):
        data = {"model": "gpt-4o", "prompt": f"IBAN {_IBAN}"}
        await self.assert_blocked(data, "acompletion")

    async def test_chat_ohne_messages_und_ohne_prompt_blockt(self):
        data = {"model": "gpt-4o", "temperature": 0.5}
        await self.assert_blocked(data, "acompletion")

    async def test_tools_description_mit_pii_geht_nicht_raus(self):
        # Braucht keinen Trick: regulaeres Chat-Completion-Feld, wird garantiert
        # uebertragen, traegt in der Praxis Kundennamen und Enum-Listen echter
        # Stammdaten. Diese Route nutzt jeder.
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Bitte pruefen."}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "kontostand",
                        "description": f"Kontostand von {_NAME}, IBAN {_IBAN}",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "kunde": {
                                    "type": "string",
                                    "enum": [_NAME, "Erika Musterfrau"],
                                }
                            },
                        },
                    },
                }
            ],
        }
        out = await self.assert_no_leak(data, "acompletion")
        # Struktur muss benutzbar bleiben (Akzeptanzkriterium aus -66).
        self.assertEqual(out["tools"][0]["type"], "function")
        self.assertEqual(
            out["tools"][0]["function"]["parameters"]["type"], "object"
        )

    async def test_tool_choice_mit_pii_geht_nicht_raus(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Bitte pruefen."}],
            "tool_choice": {
                "type": "function",
                "function": {"name": f"lade_{_NAME}"},
            },
        }
        await self.assert_no_leak(data, "acompletion")

    async def test_tool_choice_string_bleibt_gueltig(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "tool_choice": "auto",
        }
        out = await self.run_hook(data, "acompletion")
        self.assertEqual(out["tool_choice"], "auto")

    async def test_response_format_schema_mit_pii_geht_nicht_raus(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "kunde",
                    "schema": {
                        "type": "object",
                        "description": f"Datensatz von {_NAME}",
                    },
                },
            },
        }
        out = await self.assert_no_leak(data, "acompletion")
        self.assertEqual(out["response_format"]["type"], "json_schema")

    async def test_stop_und_user_auch_auf_der_chat_route(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "stop": [f"Ende {_NAME}"],
            "user": "max@example.com",
        }
        out = await self.assert_no_leak(data, "acompletion")
        self.assertNotIn("max@example.com", _plain(out))

    async def test_unbekanntes_top_level_feld_blockt(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "voellig_unbekanntes_feld": f"IBAN {_IBAN}",
        }
        await self.assert_blocked(data, "acompletion")

    async def test_bekanntes_aber_unbehandeltes_feld_wird_benannt(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "audio": {"voice": "alloy", "format": "wav"},
        }
        exc = await self.assert_blocked(data, "acompletion")
        self.assertIn("audio", str(exc))

    async def test_normaler_chat_request_laeuft_weiter_durch(self):
        # Regression: das Register darf den Hauptpfad nicht brechen.
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"Hallo {_NAME}."}],
            "temperature": 0.7,
            "max_completion_tokens": 512,
            "stream": True,
            "stream_options": {"include_usage": True},
            "parallel_tool_calls": True,
            "seed": 42,
            "metadata": {"session_id": "s1"},
        }
        out = await self.assert_no_leak(data, "acompletion")
        self.assertTrue(out["stream"])
        self.assertEqual(out["seed"], 42)


# ===========================================================================
# F2 -- QI-Generalisierung bei Listen-prompt
# ===========================================================================
def _qi_analyze_factory(entity_map):
    async def fake(text):
        out = []
        for value, etype in entity_map.items():
            idx = text.find(value)
            if idx >= 0:
                out.append(
                    {
                        "entity_type": etype,
                        "start": idx,
                        "end": idx + len(value),
                        "score": 0.9,
                    }
                )
        return out

    return fake


_QI_TEXT = "Patientin, PLZ 81675, Jahrgang 1978, Lehrerin"
_QI_MAP = {
    "81675": "DE_PLZ",
    "1978": "DE_GEBURTSJAHR",
    "Lehrerin": "DE_BERUF",
}


class TestF2QiListSlots(unittest.IsolatedAsyncioTestCase):
    """``_apply_qi_to_slots`` konnte nur dict-Container. Der Text-Pfad
    registriert Listen-Slots als ``(list, int)`` -- fuer die lieferte
    ``container.get(key) if isinstance(container, dict) else None`` immer
    ``None``, der Slot wurde STILL uebersprungen.

    Das ist genau der ``isinstance``-Guard im Verarbeitungspfad, den
    ``security-baseline.md`` verbietet und den der Guardrail im eigenen
    Docstring als "schwerstes Audit-Finding von DATENSCHLE-66" zitiert.

    Quasi-Identifier werden vom Masker BEWUSST nicht ersetzt, weil der
    QI-Layer sie groebern soll. Faellt der aus, gehen PLZ und Geburtsjahr in
    voller Aufloesung hinaus -- und ``prompt: [...]`` ist die von OpenAI
    spezifizierte Batch-Form, also gerade der Fall mit vielen Betroffenen.
    """

    def _guard(self):
        store = qs.QiStateStore(db_path=":memory:", fernet_key=Fernet.generate_key())
        guard = dg.DatenschleuseGuardrail(qi_risk_preset="paranoid", qi_store=store)
        guard._analyze = _qi_analyze_factory(_QI_MAP)
        return guard

    async def test_gleicher_text_gleiches_ergebnis_ueber_alle_drei_wege(self):
        """Identischer QI-Text ueber Chat, String-``prompt`` und
        Listen-``prompt`` muss DASSELBE Ergebnis liefern."""
        chat = await self._guard().async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": _QI_TEXT}],
                "metadata": {"session_id": "a"},
            },
            call_type="acompletion",
        )
        chat_text = next(
            m for m in chat["messages"] if m.get("role") == "user"
        )["content"]

        as_string = await self._guard().async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data={
                "model": "gpt-3.5-turbo-instruct",
                "prompt": _QI_TEXT,
                "metadata": {"session_id": "b"},
            },
            call_type="atext_completion",
        )

        as_list = await self._guard().async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data={
                "model": "gpt-3.5-turbo-instruct",
                "prompt": [_QI_TEXT],
                "metadata": {"session_id": "c"},
            },
            call_type="atext_completion",
        )

        self.assertEqual(as_string["prompt"], chat_text)
        self.assertEqual(as_list["prompt"][0], chat_text)

    async def test_listen_prompt_generalisiert_plz_und_jahrgang(self):
        out = await self._guard().async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data={
                "model": "gpt-3.5-turbo-instruct",
                "prompt": [_QI_TEXT],
                "metadata": {"session_id": "d"},
            },
            call_type="atext_completion",
        )
        text = out["prompt"][0]
        self.assertNotIn("81675", text, "PLZ ging in voller Aufloesung hinaus")
        self.assertNotIn("1978", text, "Jahrgang ging in voller Aufloesung hinaus")
        self.assertIn("Region Bayern", text)
        self.assertIn("Ende der 1970er", text)

    async def test_jeder_eintrag_der_batch_liste_wird_generalisiert(self):
        out = await self._guard().async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data={
                "model": "gpt-3.5-turbo-instruct",
                "prompt": [_QI_TEXT, _QI_TEXT],
                "metadata": {"session_id": "e"},
            },
            call_type="atext_completion",
        )
        for eintrag in out["prompt"]:
            self.assertNotIn("81675", eintrag)
            self.assertNotIn("1978", eintrag)

    async def test_qi_und_hinweis_greifen_gemeinsam_auf_der_batch_liste(self):
        """Regression: der Anonymisierungs-Hinweis (F5) ersetzt Eintraege der
        prompt-Liste, die QI-Slots zeigen per Index auf dieselbe Liste. Wuerde
        der Hinweis die Liste neu aufbauen statt in-place zu ersetzen, zeigten
        die Slots ins Leere und die QI-Generalisierung liefe wieder ins Nichts
        -- diesmal nur an anderer Stelle."""
        guard = self._guard()
        # Direkte PII (loest den Hinweis aus) UND Quasi-Identifier zugleich.
        guard._analyze = _qi_analyze_factory({**_QI_MAP, _NAME: "PERSON"})
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data={
                "model": "gpt-3.5-turbo-instruct",
                "prompt": [f"{_QI_TEXT}, betreut von {_NAME}"],
                "metadata": {"session_id": "h"},
            },
            call_type="atext_completion",
        )
        text = out["prompt"][0]
        self.assertIn(dg.ANONYMIZATION_NOTICE, text)   # Hinweis da
        self.assertNotIn(_NAME, text)                  # direkte PII maskiert
        self.assertNotIn("81675", text)                # QI generalisiert
        self.assertIn("Region Bayern", text)

    async def test_unbekannter_container_typ_blockt_statt_still_zu_ueberspringen(self):
        """Kein neuer ``isinstance``-Zweig, der bei Unbekanntem still
        ueberspringt: ein Container-Typ, den der QI-Layer nicht bedienen kann,
        muss blocken."""
        with self.assertRaises(dg.DatenschleuseBlocked):
            dg.DatenschleuseGuardrail._apply_qi_to_slots(
                [(object(), "prompt")], [("DE_PLZ", "81675")]
            )

    async def test_qi_block_wird_nicht_vom_defensiven_except_verschluckt(self):
        """Der QI-Layer-Aufruf im Hook faengt Exceptions bewusst ab, damit ein
        QI-Fehler die bereits erfolgte direkte Maskierung nicht zunichte macht.
        Ein fail-closed-Block DARF davon nicht verschluckt werden -- sonst
        waere der F2-Fix kosmetisch."""
        guard = self._guard()

        def boom(*_args, **_kwargs):
            raise dg.DatenschleuseBlocked("QI-Slot nicht bedienbar (Test)")

        guard._process_qi = boom
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard.async_pre_call_hook(
                user_api_key_dict=None,
                cache=None,
                data={
                    "model": "gpt-3.5-turbo-instruct",
                    "prompt": _QI_TEXT,
                    "metadata": {"session_id": "f"},
                },
                call_type="atext_completion",
            )

    async def test_nicht_blockende_qi_fehler_blocken_den_request_weiterhin_nicht(self):
        """Gegenprobe: ein GEWOEHNLICHER Fehler im QI-Layer darf den Request
        nach wie vor nicht blocken -- die direkte Maskierung bleibt aktiv."""
        guard = self._guard()

        def boom(*_args, **_kwargs):
            raise RuntimeError("irgendein QI-Fehler")

        guard._process_qi = boom
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data={
                "model": "gpt-3.5-turbo-instruct",
                "prompt": _QI_TEXT,
                "metadata": {"session_id": "g"},
            },
            call_type="atext_completion",
        )
        self.assertIsInstance(out["prompt"], str)


# ===========================================================================
# F5 -- Anonymisierungs-Hinweis auf der Text-Route
# ===========================================================================
class TestF5NoticeOnTextRoute(_HookCase):
    """``_inject_anonymization_notice`` lief nur bei
    ``isinstance(messages, list)``. /v1/completions bekam damit keinen
    Hinweis -- das Modell halluziniert erfahrungsgemaess um unerklaerte
    Platzhalter herum."""

    async def test_hinweis_wird_dem_prompt_vorangestellt(self):
        data = {"model": "gpt-3.5-turbo-instruct", "prompt": f"Konto von {_NAME}."}
        out = await self.run_hook(data, "atext_completion")
        self.assertIn(dg.ANONYMIZATION_NOTICE, out["prompt"])

    async def test_kein_hinweis_ohne_maskierung(self):
        # Kein Overhead fuer PII-freie Requests -- und keine kaputten
        # FIM-/Code-Completions, in denen jedes Zeichen zaehlt.
        data = {"model": "gpt-3.5-turbo-instruct", "prompt": "1 + 1 ="}
        out = await self.run_hook(data, "atext_completion")
        self.assertEqual(out["prompt"], "1 + 1 =")

    async def test_hinweis_bei_listen_prompt_in_jedem_eintrag(self):
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": [f"Konto von {_NAME}.", "Und noch etwas."],
        }
        out = await self.run_hook(data, "atext_completion")
        for eintrag in out["prompt"]:
            self.assertIn(dg.ANONYMIZATION_NOTICE, eintrag)


# ===========================================================================
# F4 -- Vollstaendigkeit von KNOWN_UNSUPPORTED_CALL_TYPES
# ===========================================================================
class TestF4KnownUnsupportedCallTypes(unittest.TestCase):
    """Kein Sicherheitsdefekt (alles blockt ohnehin), nur Meldungsqualitaet:
    ein Betreiber soll den Namen der Route in der Meldung sehen statt nur
    "unbekannt". Die Liste war gegen litellm 1.97.0 unvollstaendig."""

    #: Aus ``litellm.types.utils.CallTypes`` (1.97.0) entnommen -- Routen, die
    #: die alte Liste nicht kannte. Als Konstante hinterlegt, damit der Test
    #: ohne installiertes litellm laeuft.
    FEHLTEN = (
        "acreate_file",
        "afile_content",
        "afile_delete",
        "afile_list",
        "afile_retrieve",
        "acreate_fine_tuning_job",
        "acancel_fine_tuning_job",
        "alist_fine_tuning_jobs",
        "aretrieve_fine_tuning_job",
        "acancel_batch",
        "acreate_assistants",
        "adelete_assistant",
        "aget_assistants",
        "acreate_thread",
        "aget_thread",
        "a_add_message",
        "aget_messages",
        "arun_thread",
        "arun_thread_stream",
        "arun_code",
        "acode_interpreter_tool",
        "acreate_sandbox",
        "adelete_sandbox",
        "acreate_container",
        "adelete_container",
        "aretrieve_container",
        "alist_containers",
        "alist_container_files",
        "aupload_container_file",
        "avector_store_create",
        "avector_store_file_create",
        "avector_store_file_delete",
        "avector_store_file_list",
        "avector_store_file_retrieve",
        "avector_store_file_update",
        "avector_store_file_content",
        "acreate_video",
        "avideo_content",
        "avideo_delete",
        "avideo_edit",
        "avideo_extension",
        "avideo_list",
        "avideo_remix",
        "avideo_retrieve",
        "avideo_retrieve_job",
        "avideo_create_character",
        "avideo_get_character",
        "aingest",
        "aquery",
        "acreate_skill",
    )

    def test_bekannte_routen_werden_beim_namen_genannt(self):
        fehlend = [c for c in self.FEHLTEN if c not in dg.KNOWN_UNSUPPORTED_CALL_TYPES]
        self.assertEqual(
            fehlend,
            [],
            "diese realen litellm-1.97.0-Routen fehlen im Register: "
            f"{fehlend}",
        )

    def test_bekannte_routen_blocken_weiterhin(self):
        for call_type in self.FEHLTEN:
            with self.subTest(call_type=call_type):
                with self.assertRaises(dg.DatenschleuseBlocked):
                    dg.DatenschleuseGuardrail._validate_call_type(call_type)

    def test_allowlist_und_unsupported_ueberschneiden_sich_nicht(self):
        self.assertEqual(
            dg.ALLOWED_CALL_TYPES & dg.KNOWN_UNSUPPORTED_CALL_TYPES, frozenset()
        )


# ===========================================================================
# F1 (Security-Gate 2) -- der Transport-Umschlag
# ===========================================================================
class TestTransportEnvelope(_HookCase):
    """Die siebte Ebene derselben Fehlerklasse:

      Content-Part-Typen -> content-Container -> Message-Felder ->
      Part-Felder -> Routen -> Top-Level-Payload -> TRANSPORT-UMSCHLAG

    Das erste Kriterium der Infrastruktur-Liste lautete: "steht in
    all_litellm_params, erreicht den Provider also nicht". Das ist ZU ENG --
    es prueft nur den BODY. ``headers`` und ``provider_specific_header``
    stehen in all_litellm_params und gehen trotzdem hinaus: als HTTP-Header
    auf der Leitung (main.py:5029 bzw. ProviderSpecificHeaderUtils).

    Die Ironie belegt, dass es unbeabsichtigt war: ``extra_headers`` wurde
    mit exakt der richtigen Begruendung geblockt -- ``headers`` ist derselbe
    Kanal, nur der aeltere Name, und stand auf der Passier-Liste.

    Gemessen wurde nicht geschlossen: ein mitschneidender Provider-Server
    gegen echtes litellm 1.97.0. Von 37 Infrastruktur-Keys erreichen genau
    drei den Provider -- die beiden Header-Keys und ``model_list``, dessen
    Deployment-Eintraege eigene ``extra_headers`` tragen koennen.
    """

    async def test_headers_mit_pii_blockt_auf_der_chat_route(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "headers": {"x-notiz": f"Patient {_NAME}, IBAN {_IBAN}"},
        }
        exc = await self.assert_blocked(data, "acompletion")
        self.assertIn("headers", str(exc))

    async def test_headers_mit_pii_blockt_auf_der_text_route(self):
        data = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hallo.",
            "headers": {"x-notiz": f"IBAN {_IBAN}"},
        }
        await self.assert_blocked(data, "atext_completion")

    async def test_provider_specific_header_mit_pii_blockt(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "provider_specific_header": {
                "custom_llm_provider": "openai",
                "extra_headers": {"x-notiz": f"IBAN {_IBAN}"},
            },
        }
        exc = await self.assert_blocked(data, "acompletion")
        self.assertIn("provider_specific_header", str(exc))

    async def test_model_list_mit_pii_in_extra_headers_blockt(self):
        # Eigener Fund beim Nachmessen: model_list stand auf der Passier-Liste,
        # seine Deployment-Eintraege tragen aber eigene extra_headers -- und
        # die landen auf der Leitung.
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "model_list": [{
                "model_name": "gpt-4o",
                "litellm_params": {
                    "model": "openai/gpt-4o",
                    "extra_headers": {"x-notiz": f"IBAN {_IBAN}"},
                },
            }],
        }
        exc = await self.assert_blocked(data, "acompletion")
        self.assertIn("model_list", str(exc))

    def test_transportkanaele_stehen_auf_keiner_passier_liste(self):
        """Das eigentliche Kriterium, geschaerft: 'erreicht den Provider auf
        KEINEM Weg' -- Body, HTTP-Header oder Verbindungs-Konfiguration."""
        for feld in dg.PAYLOAD_FIELDS_TRANSPORT_CHANNELS:
            with self.subTest(feld=feld):
                self.assertNotIn(feld, dg.PAYLOAD_FIELDS_INFRASTRUCTURE)
                self.assertIn(feld, dg.KNOWN_UNSUPPORTED_PAYLOAD_FIELDS)

    def test_extra_headers_und_headers_werden_gleich_behandelt(self):
        """Derselbe Kanal, zwei Namen -- sie duerfen nie auseinanderlaufen."""
        for feld in ("extra_headers", "headers"):
            self.assertIn(feld, dg.KNOWN_UNSUPPORTED_PAYLOAD_FIELDS)
            self.assertNotIn(feld, dg.PAYLOAD_FIELDS_INFRASTRUCTURE)


# ===========================================================================
# NEU-F1 (Security-Gate 3) -- der vierte Weg: die URL
# ===========================================================================
class TestUrlAndConnectionChannels(_HookCase):
    """Die achte Ebene -- und diesmal lag der Fehler in der MESSMETHODE.

    Das Nachweisverfahren pruefte "Header UND Body des gesamten ausgehenden
    Requests". Die URL stand dort nicht. Genau dort geht ``api_version`` auf
    Azure hinaus, als Query-Parameter:

        /openai/deployments/.../chat/completions?api-version=2024-02-01&notiz=...

    Gegen ``openai/gpt-4o`` ist derselbe Key dicht. Was gegen einen Provider
    dicht ist, muss es gegen einen anderen nicht sein -- die Messung ist
    provider-abhaengig, und das gehoert ins Verfahren.

    Beim Nachmessen mit dem erweiterten Verfahren kamen drei weitere Keys
    heraus, die NIE gemessen worden waren -- schwerer als der gemeldete Fund:

      * ``api_base``   bestimmt, WOHIN der Request geht. Ein client-gesetzter
                       api_base leitet die komplette Anfrage auf einen
                       fremden Server um (gemessen: Request kam dort an).
      * ``api_key``    geht als ``authorization``-Header hinaus.
      * ``mock_response`` unterdrueckt den Aufruf ganz -- nicht messbar, und
                       nach dem eigenen Kriterium darf ungemessen nicht
                       passieren.
    """

    async def test_api_version_injection_blockt(self):
        # Der gemeldete Fall: an eine gueltige Azure-Version wird angehaengt.
        data = {
            "model": "azure/meine-deployment",
            "messages": [{"role": "user", "content": "Hallo."}],
            "api_version": f"2024-02-01&notiz=Patient {_NAME}, IBAN {_IBAN}",
        }
        await self.assert_blocked(data, "acompletion")

    async def test_echte_api_version_laeuft_unveraendert_durch(self):
        # Blocken waere hier zu grob: der Proxy setzt api_version selbst aus
        # dem Query-String eines Azure-Clients. Eng validieren statt blocken.
        data = {
            "model": "azure/meine-deployment",
            "messages": [{"role": "user", "content": "Hallo."}],
            "api_version": "2024-02-01-preview",
        }
        out = await self.run_hook(data, "acompletion")
        self.assertEqual(out["api_version"], "2024-02-01-preview")

    async def test_api_base_blockt(self):
        # Der schwerste der vier: bestimmt das Ziel der Anfrage.
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "api_base": "http://angreifer.example",
        }
        exc = await self.assert_blocked(data, "acompletion")
        self.assertIn("api_base", str(exc))

    async def test_api_key_mit_freitext_blockt(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "api_key": f"Patient {_NAME}, IBAN {_IBAN}",
        }
        await self.assert_blocked(data, "acompletion")

    async def test_echter_api_key_laeuft_unveraendert_durch(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "api_key": "sk-proj-AbC123_x.y-z",
        }
        out = await self.run_hook(data, "acompletion")
        self.assertEqual(out["api_key"], "sk-proj-AbC123_x.y-z")

    async def test_custom_llm_provider_blockt(self):
        # Waehlt den Provider-Handler -- und damit, ob ueberhaupt eine URL mit
        # Query-Parametern gebaut wird. Der Proxy setzt ihn nie selbst.
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "custom_llm_provider": "azure",
        }
        exc = await self.assert_blocked(data, "acompletion")
        self.assertIn("custom_llm_provider", str(exc))

    async def test_mock_response_blockt(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo."}],
            "mock_response": "beliebige Antwort",
        }
        exc = await self.assert_blocked(data, "acompletion")
        self.assertIn("mock_response", str(exc))

    def test_verbindungs_keys_passieren_nicht_ungeprueft(self):
        """Verbindung, Zugang und Steuerung sind nie 'Infrastruktur, die man
        durchlassen kann'. Sie bestimmen, WOHIN die Daten gehen und MIT WESSEN
        Zugangsdaten -- das ist eine schaerfere Frage als 'traegt dieses Feld
        gerade einen Marker?'."""
        for feld in ("api_base", "api_key", "api_version",
                     "custom_llm_provider", "mock_response"):
            with self.subTest(feld=feld):
                self.assertNotIn(feld, dg.PAYLOAD_FIELDS_INFRASTRUCTURE)


# ===========================================================================
# F3 (Security-Gate 2) -- der Beleg darf nicht an einer Version haengen
# ===========================================================================
class TestInfrastructureClaimHoldsAtRuntime(unittest.TestCase):
    """Die Rechtfertigung der Infrastruktur-Liste ist versionsspezifisch.
    Verlaesst ein Key in einer neueren litellm-Version all_litellm_params,
    wird er STILL zum Provider-Kanal -- ohne diesen Test schlaegt nichts an.

    Der Test laeuft nur, wenn litellm installiert ist (die uebrige Suite
    braucht es bewusst nicht), und ist damit in CI/Image scharf und lokal
    unaufdringlich.
    """

    def setUp(self):
        try:
            from litellm.types.utils import all_litellm_params  # noqa: F401
        except Exception:  # noqa: BLE001
            self.skipTest("litellm nicht installiert -- Laufzeitpruefung entfaellt")

    def test_infrastruktur_keys_sind_weiterhin_litellm_intern(self):
        from litellm.types.utils import all_litellm_params

        entwichen = sorted(
            dg.PAYLOAD_FIELDS_INFRASTRUCTURE - set(all_litellm_params)
        )
        self.assertEqual(
            entwichen, [],
            "Diese Keys stehen nicht mehr in all_litellm_params und gehen "
            f"damit als Provider-Parameter hinaus: {entwichen}. Entweder ins "
            "Register aufnehmen (maskiert/validiert) oder blocken.",
        )

    def test_kriterium_allein_genuegt_nicht(self):
        """Bewusst als Test formuliert, weil genau diese Annahme der Defekt
        war: 'steht in all_litellm_params' ist NOTWENDIG, nicht HINREICHEND.

        Der Nachweis ist die Schnittmenge: es gibt Transportkanaele, die das
        alte Kriterium ERFUELLEN und trotzdem hinausgehen. Waere die Menge
        leer, waere das alte Kriterium tragfaehig gewesen.

        ``extra_headers`` gehoert ausdruecklich NICHT dazu -- es stand nie in
        all_litellm_params. Genau deshalb wurde es von Anfang an korrekt
        geblockt, waehrend sein Zwillingsname ``headers`` durchrutschte. Der
        Unterschied zwischen beiden ist die ganze Lehre aus dem Finding.
        """
        from litellm.types.utils import all_litellm_params

        erfuellen_altes_kriterium = sorted(
            dg.PAYLOAD_FIELDS_TRANSPORT_CHANNELS & set(all_litellm_params)
        )
        self.assertTrue(
            erfuellen_altes_kriterium,
            "Kein Transportkanal erfuellt das alte Kriterium -- dann waere es "
            "tragfaehig gewesen und dieser Test haette keinen Gegenstand.",
        )
        self.assertIn("headers", erfuellen_altes_kriterium)
        self.assertNotIn("extra_headers", set(all_litellm_params))

    def test_jeder_transportkanal_blockt(self):
        for feld in dg.PAYLOAD_FIELDS_TRANSPORT_CHANNELS:
            with self.subTest(feld=feld):
                self.assertIn(feld, dg.KNOWN_UNSUPPORTED_PAYLOAD_FIELDS)
                self.assertNotIn(feld, dg.PAYLOAD_FIELDS_INFRASTRUCTURE)


# ===========================================================================
# Register-Invarianten
# ===========================================================================
class TestRegisterInvariants(unittest.TestCase):
    def test_jedes_feld_steht_in_genau_einer_liste(self):
        for route in (dg.CHAT_PAYLOAD_ROUTE, dg.TEXT_PAYLOAD_ROUTE):
            doppelt = set(route.masked) & set(route.validated)
            self.assertEqual(
                doppelt, set(), f"Feld in beiden Listen: {sorted(doppelt)}"
            )

    def test_infrastruktur_felder_kollidieren_nicht_mit_payload_feldern(self):
        for route in (dg.CHAT_PAYLOAD_ROUTE, dg.TEXT_PAYLOAD_ROUTE):
            kollision = dg.PAYLOAD_FIELDS_INFRASTRUCTURE & (
                set(route.masked) | set(route.validated)
            )
            self.assertEqual(kollision, set(), f"Kollision: {sorted(kollision)}")

    def test_benannte_unbehandelte_felder_stehen_in_keiner_allowlist(self):
        for route in (dg.CHAT_PAYLOAD_ROUTE, dg.TEXT_PAYLOAD_ROUTE):
            erlaubt = set(route.masked) | set(route.validated)
            kollision = dg.KNOWN_UNSUPPORTED_PAYLOAD_FIELDS & erlaubt
            self.assertEqual(kollision, set(), f"Kollision: {sorted(kollision)}")


if __name__ == "__main__":
    unittest.main()
