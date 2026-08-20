"""Unit-Tests fuer den DEPLOYMENT-PFAD der Guardrail (DATENSCHLE-69,
Security-Finding F3).

Die Behauptung, die nachgemessen wurde
--------------------------------------
Der Branch kommentierte den Register-Eintrag ``"completion"`` mit "KEIN toter
Eintrag -- CustomGuardrail.async_pre_call_deployment_hook bedient die Route".
Der Auditor hielt fest: genau eine von zwei Aussagen ist wahr, und der Branch
belegt keine.

  (a) ``_pre_call_hook_already_ran`` greift immer -> Eintrag tot, Kommentar
      unbelegt (harmlos).
  (b) Der Pfad ist erreichbar -> JEDER Request blockt, weil der Hook dort
      router-aufgeloeste Deployment-kwargs bekommt, die das Top-Level-Register
      hart blockt. Fail-closed, aber Totalausfall.

GEMESSEN gegen litellm 1.97.0 -- Ergebnis: **(b)**.

Messung 1 (litellm.utils.async_pre_call_deployment_hook direkt gefahren):

    litellm.completion is coroutine : False
    litellm.acompletion is coroutine: True
    wrapper call_type=acompletion      -> hook sah: ['acompletion']
    wrapper call_type=completion       -> hook sah: ['completion']
    wrapper call_type=atext_completion -> hook sah: NICHT AUFGERUFEN
    nach mark_pre_call_hook_ran        -> hook sah: NICHT AUFGERUFEN

Messung 2 (die ECHTE Guardrail durch denselben Hook):

    [SDK / model-level guardrails, KEIN Marker] DatenschleuseBlocked:
        Payload enthaelt 4 Top-Level-Feld(er) ...
    [Proxy-Flow, Marker gesetzt] DURCH

Messung 3 (echter litellm Router, echtes Deployment, mock_response) --
die Top-Level-Keys, die auf dem Deployment-Pfad wirklich ankommen:

    api_base, api_key, caching, client, guardrails, litellm_call_id,
    litellm_trace_id, max_retries, merge_reasoning_content_in_choices,
    messages, metadata, mock_response, model, model_info, stream, timeout,
    use_in_pass_through, use_litellm_proxy, use_xai_oauth

Dazu die fuenf ``user_api_key_*``-Keys, die litellm in
``integrations/custom_guardrail.py:661-666`` selbst aus den kwargs liest, um
``UserAPIKeyAuth`` zu bauen, sowie ``guardrail_to_apply`` (:657).

Zur Korrektur des Kommentars
----------------------------
``litellm.completion`` ist KEINE Coroutine und laeuft deshalb durch den
synchronen ``wrapper`` (``utils.py:1256``), der
``async_pre_call_deployment_hook`` nie aufruft -- nur ``wrapper_async``
(``utils.py:1558``) tut das, an ``:1587``, mit
``call_type = original_function.__name__``. Aus dem synchronen
``litellm.completion`` entsteht also NIE ein ``CallTypes.completion``.
Erreicht der Dispatcher trotzdem einmal ``CallTypes.completion``, reicht
``custom_guardrail.py:668`` korrekt den String ``"completion"`` an unseren
Hook. Der Eintrag ist damit nicht tot, aber auch nicht so belegt, wie der
alte Kommentar behauptete.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm:
die Deployment-kwargs werden aus der obigen MESSUNG nachgebaut.

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_deployment_route.py" -v
"""

import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


_NAME = "Max Mustermann"
_IBAN = "DE02120300000000202051"


async def fake_analyze(text):
    found = []
    for needle, entity_type in ((_NAME, "PERSON"), (_IBAN, "IBAN_CODE")):
        idx = text.find(needle)
        if idx >= 0:
            found.append({
                "entity_type": entity_type,
                "start": idx,
                "end": idx + len(needle),
                "score": 0.99,
            })
    return found


def _guard(**kwargs):
    kwargs.setdefault("presidio_analyzer_url", "http://presidio.invalid")
    kwargs.setdefault("language", "de")
    kwargs.setdefault("image_policy", "pass")
    guard = dg.DatenschleuseGuardrail(**kwargs)
    guard._analyze = fake_analyze
    return guard


def deployment_kwargs(**extra):
    """Die GEMESSENE Form der Deployment-kwargs (litellm 1.97.0, Router-Lauf
    plus die aus custom_guardrail.py gelesenen Auth-Keys)."""
    data = {
        "model": "openai/gpt-4o-mini",
        "messages": [{"role": "user", "content": f"Hallo {_NAME}"}],
        "api_base": "https://api.example.invalid/v1",
        "api_key": "sk-test",
        "caching": False,
        "client": None,
        "guardrails": ["datenschleuse-reid"],
        "litellm_call_id": "c1",
        "litellm_trace_id": "t1",
        "max_retries": 2,
        "merge_reasoning_content_in_choices": False,
        "metadata": {"model_group": "datenschleuse-gpt"},
        "model_info": {"id": "dep-1"},
        "stream": False,
        "timeout": 600,
        "use_in_pass_through": False,
        "use_litellm_proxy": False,
        "use_xai_oauth": False,
        "user_api_key_user_id": "u1",
        "user_api_key_team_id": "t1",
        "user_api_key_end_user_id": "e1",
        "user_api_key_hash": "h1",
        "user_api_key_request_route": "/v1/chat/completions",
    }
    data.update(extra)
    return data


class _Case(unittest.IsolatedAsyncioTestCase):
    async def run_deployment(self, data, guard=None, call_type="acompletion"):
        """Der ECHTE Eingang, nicht der Client-Hook.

        Bewusst ueber ``async_pre_call_deployment_hook``: nur dort steht der
        ContextVar-Merker, der das erweiterte Register freischaltet. Wuerde der
        Test ``async_pre_call_hook`` direkt aufrufen, pruefte er eine Mechanik,
        die es in Produktion so nicht gibt -- genau der Fehler, aus dem F3
        entstanden ist.
        """
        guard = guard or _guard()
        return await guard.async_pre_call_deployment_hook(data, call_type)


class TestDeploymentPayloadIsRegistered(_Case):
    """(b) war der Befund: die gemessene Deployment-Form blockte komplett.
    Fail-closed, aber Totalausfall -- und die erste Betreiberreaktion darauf
    ist, die Guardrail abzuschalten."""

    async def test_gemessene_deployment_kwargs_blocken_nicht_mehr(self):
        out = await self.run_deployment(deployment_kwargs())
        self.assertIsInstance(out, dict)

    async def test_deployment_pfad_maskiert_wirklich(self):
        """Der eigentliche Zweck. Im SDK-/model-level-Setup ist dieser Hook
        die EINZIGE Maskierungsstelle -- "blockt nicht mehr" waere ohne
        "maskiert" ein stilles Leck und damit schlimmer als der Block."""
        out = await self.run_deployment(deployment_kwargs())
        self.assertNotIn(_NAME, json.dumps(out["messages"], ensure_ascii=False))
        self.assertIn("<PERSON_", out["messages"][-1]["content"])

    async def test_unbekannter_key_blockt_auch_auf_dem_deployment_pfad(self):
        """Die Doktrin gilt unveraendert: was nicht im Register steht, blockt.
        Der Deployment-Pfad bekommt ein GROESSERES Register, kein laxeres."""
        data = deployment_kwargs(voellig_unbekanntes_feld="x")
        with self.assertRaises(dg.DatenschleuseBlocked):
            await self.run_deployment(data)

    async def test_blockmeldung_nennt_den_deployment_kontext(self):
        """Ein Betreiber muss aus der Meldung erkennen, dass der Block vom
        Deployment-Pfad kommt -- sonst sucht er an der falschen Stelle."""
        data = deployment_kwargs(voellig_unbekanntes_feld="x")
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await self.run_deployment(data)
        self.assertIn("deployment", str(ctx.exception).lower())


class TestClientPathStaysStrict(_Case):
    """Das erweiterte Register darf AUSSCHLIESSLICH auf dem Deployment-Pfad
    gelten. Liefe es auch auf dem Client-Pfad, haetten wir das
    Transport-Kanal-Register aufgeweicht -- ein client-gesetztes api_base
    leitet den kompletten Verkehr auf einen fremden Server um."""

    async def test_api_base_bleibt_auf_dem_client_pfad_geblockt(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hi"}],
            "api_base": "https://angreifer.invalid/v1",
        }
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _guard().async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data,
                call_type="acompletion",
            )

    async def test_user_api_key_felder_bleiben_auf_dem_client_pfad_geblockt(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hi"}],
            "user_api_key_user_id": "gefaelscht",
        }
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _guard().async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data,
                call_type="acompletion",
            )


class TestCompletionEntryIsHonest(_Case):
    """F3, erster Teil: der Kommentar am Register-Eintrag musste auf das
    Belegbare zurueckgezogen werden."""

    async def test_completion_ist_im_register(self):
        self.assertIn("completion", dg.ALLOWED_CALL_TYPES)

    async def test_completion_wird_wie_der_deployment_pfad_behandelt(self):
        """Beide Strings, die litellms Deployment-Hook an uns reicht
        (custom_guardrail.py:668), muessen die Deployment-Form vertragen."""
        for call_type in ("completion", "acompletion"):
            with self.subTest(call_type=call_type):
                out = await self.run_deployment(
                    deployment_kwargs(), call_type=call_type
                )
                self.assertNotIn(
                    _NAME, json.dumps(out["messages"], ensure_ascii=False)
                )


class TestDeploymentRegisterIsMeasured(_Case):
    """Bauart-Absicherung gegen genau den Fehler, der F3 ausgeloest hat:
    eine Behauptung ueber eine Route, die niemand gemessen hat."""

    async def test_jeder_gemessene_key_steht_im_register(self):
        route = dg.CHAT_PAYLOAD_ROUTE
        erlaubt = (
            set(route.masked)
            | set(route.validated)
            | dg.PAYLOAD_FIELDS_INFRASTRUCTURE
            | dg.PAYLOAD_FIELDS_RESYNCED
            | dg.PAYLOAD_FIELDS_DEPLOYMENT
        )
        fehlend = [k for k in deployment_kwargs() if k not in erlaubt]
        self.assertEqual(
            fehlend, [],
            "GEMESSENE Deployment-Keys fehlen im Register -- "
            "der Deployment-Pfad wuerde blocken.",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
