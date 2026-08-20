"""Unit-Tests fuer den LOGGING-SNAPSHOT ``proxy_server_request.body``
(DATENSCHLE-69, Security-Finding F1).

Hintergrund -- der achte Weg
---------------------------
Dieselbe Bauart-Luecke, inzwischen zum siebten Mal, diesmal NICHT auf dem Weg
zum Provider, sondern auf dem Weg ins LOG. litellm baut in
``add_litellm_data_to_request`` VOR dem Guardrail einen flachen Schnappschuss
des Bodys und haengt ihn an den Request (litellm 1.97.0,
``proxy/litellm_pre_call_utils.py:1690-1692``)::

    _body_snapshot = {k: v for k, v in data.items() if k not in exclude}
    data["proxy_server_request"]["body"] = _body_snapshot

``exclude`` ist ``{"secret_fields", "proxy_server_request"}``. Der
Schnappschuss ist eine FLACHE Kopie: fuer jeden Key haelt er dieselbe
Objekt-Referenz wie ``data``.

Daraus folgt die Regel, die den Defekt erklaert:

  * Ein Feld, das die Guardrail IN-PLACE mutiert (``messages`` -- die
    Message-Dicts werden veraendert, die Liste bleibt dieselbe), ist im
    Schnappschuss automatisch mitmaskiert: beide zeigen auf dasselbe Objekt.
  * Ein Feld, das die Guardrail durch REBINDING maskiert
    (``data[feld] = maskiert``), ist es NICHT: der Schnappschuss haelt weiter
    die alte, unmaskierte Referenz.

Genau die Felder, die DATENSCHLE-69 neu abgesichert hat, maskieren durch
Rebinding -- ``suffix``, ``stop``, ``user``, ``tools``/``tool_choice``/
``functions``/``function_call``/``response_format`` und ``prompt`` als String.
Sie waren auf dem Provider-Weg dicht und im Log im Klartext.

Konsumenten des Schnappschusses laut litellms eigenem Kommentar an der
Fundstelle: ``standard_logging_payload``, ``lago``, ``spend_tracking_utils``,
``streaming_iterator``. ``turn_off_message_logging`` rettet nicht:
``perform_redaction`` (``litellm/litellm_core_utils/redact_messages.py:238-240``)
redigiert ausschliesslich ``messages``, ``prompt`` und ``input`` -- nicht
``suffix``, nicht ``tools``, nicht ``stop``, nicht ``user``.

Warum dieser Test GENERISCH ueber das Register laeuft
-----------------------------------------------------
Ein Test pro heute bekanntem Leck-Feld haette denselben Baufehler wie der
Code: er prueft, was man kennt. Stattdessen iteriert dieser Test ueber
``route.masked`` JEDER Route. Ein neues maskiertes Feld im Register bekommt
seine Snapshot-Pruefung damit automatisch -- ohne dass jemand daran denken
muss. Genau das ist der Unterschied zwischen "den Einzelfall repariert" und
"die Fehlerklasse geschlossen".

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_logging_snapshot.py" -v
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


# ===========================================================================
# Fixtures
# ===========================================================================
_NEEDLES = (
    ("Max Mustermann", "PERSON"),
    ("DE02120300000000202051", "IBAN_CODE"),
)
_IBAN = "DE02120300000000202051"
_NAME = "Max Mustermann"


async def fake_analyze(text):
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


#: Die Ausschlussmenge, mit der litellm den Schnappschuss VOR unserem Hook
#: baut -- fuer den Fixture-Aufbau.
#:
#: Hier stand fruehr eine hartcodierte Kopie mit dem Kommentar "exakt
#: litellms eigene Ausschlussmenge". Das war derselbe Baufehler wie im Code
#: (Security-F1b): der Test duplizierte die Annahme, statt sie zu pruefen --
#: und konnte eine Abweichung deshalb prinzipiell nicht finden. Zwei Kopien
#: derselben Vermutung sehen aus wie eine Bestaetigung.
#:
#: Jetzt wird GEMESSEN: die Zuweisung wird aus dem Quelltext des
#: installierten litellm gelesen. Ohne installiertes litellm faellt der
#: Fixture-Aufbau auf die kleinste bekannte Form zurueck -- das ist fuer
#: DIESE Datei unkritisch, weil sie den Klartext-Gehalt des Schnappschusses
#: misst und nicht den Vertrag. Der Vertrag selbst hat einen eigenen,
#: messenden Test: ``test_snapshot_exclude_contract.py``.
from test_snapshot_exclude_contract import (  # noqa: E402
    _litellm_snapshot_exclude_or_default,
)

_LITELLM_SNAPSHOT_EXCLUDE = _litellm_snapshot_exclude_or_default()


def as_proxy_would(body):
    """Baut den Request so auf, wie der litellm-Proxy ihn dem Guardrail
    uebergibt -- inklusive des flachen Logging-Schnappschusses."""
    data = dict(body)
    data.setdefault("metadata", {})
    data["proxy_server_request"] = {
        "url": "http://proxy/v1/chat/completions",
        "method": "POST",
        "headers": {},
        "body": None,
    }
    data["proxy_server_request"]["body"] = {
        k: v for k, v in data.items() if k not in _LITELLM_SNAPSHOT_EXCLUDE
    }
    return data


def snapshot_of(out):
    """Der Logging-Schnappschuss als durchsuchbarer String -- VOLLSTAENDIG.

    Hier wurde das Re-Id-Mapping herausgefiltert, mit Verweis auf "einen
    eigenen Test in test_reid_map_transport.py". Diese Datei EXISTIERTE
    NICHT. Der Filter verwies also auf eine leere Stelle: die gruene Suite
    konnte den Klartext im Schnappschuss gar nicht finden, weil sie genau
    an der Stelle wegsah, an der er stand.

    Beides ist behoben. Die Datei gibt es jetzt (sie misst den Transport des
    Mappings), und der Filter hier ist weg -- seit Security-F4 reist das
    Mapping versiegelt, es gibt also nichts mehr auszunehmen.

    Lehre, die den Filter ueberlebt: eine Ausnahme in einer Messung ist eine
    Behauptung. Sie braucht einen Beleg, der wirklich existiert -- sonst ist
    sie ein blinder Fleck mit Fussnote.
    """
    body = out.get("proxy_server_request", {}).get("body")
    return json.dumps(body, ensure_ascii=False, default=str)


#: Fuer jedes registrierte maskierte Feld eine Wertform, die es real annehmen
#: kann -- mit der PII an genau der Stelle, an der sie in der Praxis steht.
#: Eine Messung ist nur so gut wie ihre Wertform: ein Marker in der falschen
#: Struktur misst nichts (dieselbe Lehre wie beim Transport-Kanal-Register).
_FIELD_VALUES = {
    "messages": [{"role": "user", "content": f"Hallo {_NAME}, IBAN {_IBAN}"}],
    "prompt": f"Konto von {_NAME}, IBAN {_IBAN}",
    "suffix": f" -- Kunde {_NAME}, IBAN {_IBAN}",
    "stop": [f"Ende {_NAME}", _IBAN],
    "user": _NAME,
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "buchen",
                "description": f"Bucht fuer {_NAME} auf IBAN {_IBAN}",
            },
        }
    ],
    "tool_choice": {
        "type": "function",
        "function": {"name": "buchen", "description": f"fuer {_NAME}"},
    },
    "functions": [{"name": "buchen", "description": f"Konto {_IBAN}"}],
    "function_call": {"name": "buchen", "arguments": json.dumps({"kunde": _NAME})},
    "response_format": {
        "type": "json_schema",
        "json_schema": {
            "name": "rechnung",
            "schema": {
                "type": "object",
                "description": f"Rechnung von {_NAME}, IBAN {_IBAN}",
                "properties": {},
            },
        },
    },
}


def _base_body(route):
    """Minimaler, gueltiger Body fuer eine Route."""
    if route is dg.CHAT_PAYLOAD_ROUTE:
        return {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}]}
    return {"model": "gpt-3.5-turbo-instruct", "prompt": "Hi"}


#: Liste statt dict: ``_PayloadRoute`` traegt ein dict (``validated``) und ist
#: damit nicht hashbar -- als dict-Key waere sie ein TypeError beim Import.
_ROUTE_CALL_TYPE = (
    (dg.CHAT_PAYLOAD_ROUTE, "acompletion"),
    (dg.TEXT_PAYLOAD_ROUTE, "atext_completion"),
)


# ===========================================================================
# F1 -- der Schnappschuss darf nach dem Hook keinen Klartext mehr halten
# ===========================================================================
class TestLoggingSnapshotNoPlaintext(unittest.IsolatedAsyncioTestCase):
    """Der Kern des Findings, generisch ueber das Register gefahren."""

    async def _run(self, data, call_type):
        return await _guard().async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type=call_type
        )

    async def test_jedes_registrierte_maskierte_feld_ist_im_snapshot_dicht(self):
        """DER Test. Fuer JEDE Route und JEDES in ``route.masked``
        registrierte Feld: PII hinein, Hook laufen lassen, Schnappschuss
        pruefen.

        Vor dem Fix schlaegt das fuer alle rebindenden Felder fehl -- also
        fuer alle ausser ``messages``.
        """
        geprueft = 0
        for route, call_type in _ROUTE_CALL_TYPE:
            for feld in route.masked:
                self.assertIn(
                    feld,
                    _FIELD_VALUES,
                    f"Register-Feld {feld!r} hat keine Testwertform -- ein "
                    "neues maskiertes Feld MUSS hier eine bekommen, sonst "
                    "misst dieser Test es nicht.",
                )
                with self.subTest(route=route.name, feld=feld):
                    body = _base_body(route)
                    body[feld] = _FIELD_VALUES[feld]
                    data = as_proxy_would(body)
                    out = await self._run(data, call_type)
                    flat = snapshot_of(out)
                    self.assertNotIn(
                        _NAME, flat, f"Klartext-Name im Logging-Snapshot ({feld})"
                    )
                    self.assertNotIn(
                        _IBAN, flat, f"Klartext-IBAN im Logging-Snapshot ({feld})"
                    )
                    geprueft += 1
        # Bauart-Absicherung: der Test muss wirklich etwas gefahren haben.
        self.assertGreaterEqual(geprueft, 10)

    async def test_snapshot_bleibt_fuer_konsumenten_brauchbar(self):
        """Der Schnappschuss darf nicht einfach geleert werden.

        ``spend_tracking_utils`` und ``standard_logging_payload`` lesen ihn.
        Ein leerer Body waere zwar dicht, wuerde aber die Kostenerfassung des
        Betreibers stillschweigend kaputtmachen -- ein Fix, der einen anderen
        Defekt erzeugt. Der Schnappschuss muss also weiterhin die Struktur
        tragen, nur eben die MASKIERTE.
        """
        body = _base_body(dg.CHAT_PAYLOAD_ROUTE)
        body["messages"] = [{"role": "user", "content": f"Hallo {_NAME}"}]
        out = await self._run(as_proxy_would(body), "acompletion")
        snap = out["proxy_server_request"]["body"]
        self.assertIsInstance(snap, dict)
        self.assertEqual(snap.get("model"), "gpt-4o")
        self.assertIn("messages", snap)

    async def test_snapshot_traegt_den_maskierten_wert(self):
        """Nicht nur "kein Klartext", sondern der RICHTIGE Wert: der
        Schnappschuss muss denselben Platzhalter tragen wie das Nutzfeld."""
        body = _base_body(dg.TEXT_PAYLOAD_ROUTE)
        body["prompt"] = f"Konto von {_NAME}"
        out = await self._run(as_proxy_would(body), "atext_completion")
        snap = out["proxy_server_request"]["body"]
        self.assertEqual(snap["prompt"], out["prompt"])
        self.assertIn("<PERSON_", snap["prompt"])

    async def test_neue_felder_im_body_landen_ebenfalls_maskiert_im_snapshot(self):
        """Der Schnappschuss wird NEU GEBAUT, nicht feldweise nachgezogen.

        Ein feldweiser Re-Sync waere derselbe Baufehler noch einmal: er deckt
        die Felder ab, an die jemand gedacht hat. Der Neubau deckt alles ab,
        was im Payload steht -- auch das, was ein kuenftiger Commit
        hinzufuegt.
        """
        body = _base_body(dg.CHAT_PAYLOAD_ROUTE)
        body["messages"] = [{"role": "user", "content": f"Hallo {_NAME}"}]
        body["user"] = _NAME
        out = await self._run(as_proxy_would(body), "acompletion")
        snap = out["proxy_server_request"]["body"]
        self.assertEqual(snap["user"], out["user"])
        # Der KOMPLETTE Schnappschuss, ``metadata`` eingeschlossen. Die
        # frueher hier ausgenommene Klartext-Zuordnung gibt es nicht mehr:
        # das Mapping reist seit Security-F4 versiegelt.
        self.assertNotIn(_NAME, json.dumps(snap, ensure_ascii=False, default=str))


class TestLoggingSnapshotShape(unittest.IsolatedAsyncioTestCase):
    """Die FORM des Schnappschusses. Was wir nicht pruefen koennen, blockt --
    dieselbe Doktrin wie ueberall sonst im Register."""

    async def _run(self, data, call_type="acompletion"):
        return await _guard().async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type=call_type
        )

    async def _assert_blocked(self, data):
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await self._run(data)
        self.assertNotIn(_NAME, str(ctx.exception))
        self.assertNotIn(_IBAN, str(ctx.exception))
        return ctx.exception

    async def test_ohne_proxy_server_request_laeuft_alles_normal(self):
        """SDK-/Testpfad ohne Proxy: kein Schnappschuss, nichts zu tun."""
        data = {"model": "gpt-4o", "messages": [{"role": "user", "content": f"Hi {_NAME}"}]}
        out = await self._run(data)
        self.assertNotIn("proxy_server_request", out)

    async def test_proxy_server_request_ohne_body_bleibt_unangetastet(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"Hi {_NAME}"}],
            "proxy_server_request": {"url": "http://p/x", "method": "POST"},
        }
        out = await self._run(data)
        self.assertNotIn("body", out["proxy_server_request"])

    async def test_proxy_server_request_falscher_typ_blockt(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hi"}],
            "proxy_server_request": "nicht-geprueft",
        }
        await self._assert_blocked(data)

    async def test_body_als_string_blockt(self):
        """Ein roher JSON-String als Body traegt denselben Klartext, ist aber
        keine Struktur, die wir neu bauen koennen -> fail-closed."""
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hi"}],
            "proxy_server_request": {"body": json.dumps({"messages": []})},
        }
        await self._assert_blocked(data)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
