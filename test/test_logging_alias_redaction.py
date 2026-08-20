"""Die ZWEITE Referenz auf die Nutzfelder (DATENSCHLE-69, Runde 4, F1).

Der Befund
----------
Die Block-Redaktion redigierte per REBINDING::

    data[feld] = MARKER
    data["messages"] = [...]

Ein Rebinding ersetzt den Wert AN EINEM SCHLUESSEL. Es erreicht per
Konstruktion keinen Alias -- also niemanden, der dieselbe Liste bzw. dieselben
Dicts noch anderweitig haelt. Genau das ist die Fehlerform aus Runde 1, nur
eine Ebene hoeher.

Gemessen (Auditor, Runde 4)::

    [1] data['messages']              -> "<withheld-by-datenschleuse: ...>"  Klartext? False
    [2] logging_obj.messages (Alias)  -> [{"role":"user","content":"Hallo Max ...  Klartext? True
        identisches Objekt wie vor dem Hook: True

Die Messluecke daneben war Teil des Befunds: ``test_logging_snapshot.py:363``
prueft ``data.get("messages")`` -- also den rebindeten Slot -- obwohl sein
eigener Docstring ``litellm_logging_obj`` als Grund nennt. Der Test KONNTE
den Befund prinzipiell nicht finden. Diese Datei misst deshalb ausschliesslich
die zweite Referenz.

Die Beweisfrage -- und warum beide bisherigen Beschreibungen daneben lagen
------------------------------------------------------------------------
Der Auditor konnte nicht messen, ob litellm den Alias wirklich haelt (litellm
ist hier nicht installiert). Belegt ist es jetzt aus dem Quelltext von
litellm 1.97.0 -- derselben Version, gegen die die uebrigen Befunde dieses
Items geschrieben sind:

* ``proxy/common_request_processing.py:1403-1412`` -- ``function_setup(...)``
  laeuft VOR den pre-call-Hooks (Kommentar dort woertlich: *"IMPORTANT Note:
  - initialize this before running pre-call checks"*), Ergebnis landet als
  ``self.data["litellm_logging_obj"] = logging_obj``. Das Objekt haengt also
  wirklich im ``data``, das dieser Hook sieht.
* ``utils.py:869`` + ``:1006`` -- ``messages = kwargs["messages"]``, dann
  ``Logging(messages=messages, ...)``. Dieselbe Listenreferenz.
* ``utils.py:1034`` -- ``function_setup`` ruft noch
  ``update_environment_variables()``, das ``model_call_details["messages"]``
  fuellt. Beide Schluessel existieren also, wenn wir dran sind.
* ``litellm_core_utils/litellm_logging.py:317`` und ``:329-333`` -- und hier
  liegt der Punkt, den BEIDE bisherigen Beschreibungen verfehlt haben::

      _input: Final[str | None] = messages          # :317  -> KEINE Kopie
      ...
      # Shallow copy of the outer list only (inner message dicts are shared).
      # Safe because the logging layer does not mutate individual message dicts.
      self.messages = copy.copy(messages)           # :333

Daraus folgt genau dreierlei:

1. ``model_call_details["input"]`` ist die **identische** Liste.
2. ``logging_obj.messages`` ist eine **andere** Liste mit **denselben**
   Message-Dicts.
3. Deshalb ist der alte Docstring ("mit DERSELBEN messages-Liste
   konstruiert") ungenau -- er wird mit diesem Commit korrigiert. Und deshalb
   reicht auch ``messages[:] = [...]`` allein NICHT: das mutiert nur die
   aeussere Liste und erreicht ``logging_obj.messages`` nie. Nur das
   In-place-Leeren der Message-DICTS erreicht beide Wege.

Der Fix ist darum dreiteilig: Dicts in place leeren, aeussere Liste in place
kuerzen, und ``litellm_logging_obj`` ausdruecklich neutralisieren -- letzteres
ueber ``Logging.update_messages()`` (``litellm_logging.py:616-623``), eine
offizielle API, deren Docstring sie genau fuer pre-call-Hooks vorsieht.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest discover -s test \\
        -p "test_logging_alias_redaction.py" -v
"""

import copy
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


class FakeLitellmLogging:
    """Baut litellm 1.97.0s ``Logging``-Objekt in genau den Punkten nach, auf
    die es hier ankommt -- Zeilennachweise im Modul-Docstring.

    Bewusst KEIN Mock mit ``MagicMock``: ein Mock haette jede beliebige
    Zugriffsform akzeptiert und damit auch einen Fix gruen gemeldet, der die
    echten Referenzen verfehlt. Was gemessen werden soll, muss echt gebaut
    sein.
    """

    def __init__(self, messages):
        # :317 -- KEINE Kopie. Identische Liste.
        _input = messages
        # :333 -- flache Kopie: neue aeussere Liste, GETEILTE Dicts.
        self.messages = copy.copy(messages)
        # :390-397 (input) und :544-548 via update_environment_variables
        # (messages), beides vor Rueckgabe aus function_setup.
        self.model_call_details = {
            "input": _input,
            "messages": self.messages,
            "model": "gpt-4o",
        }

    def update_messages(self, messages):
        """:616-623 -- die offizielle API fuer pre-call-Hooks. Setzt beides."""
        self.messages = messages
        self.model_call_details["messages"] = messages


def _guard(**kwargs):
    kwargs.setdefault("presidio_analyzer_url", "http://presidio.invalid")
    kwargs.setdefault("language", "de")
    kwargs.setdefault("image_policy", "pass")
    return dg.DatenschleuseGuardrail(**kwargs)


def _als_text(wert):
    return json.dumps(wert, ensure_ascii=False, default=str)


def _proxy_data(messages):
    """Der Request, wie der Proxy ihn uebergibt -- inklusive des
    ``litellm_logging_obj``, das ``function_setup`` vorher hineingelegt hat.

    ``litellm_logging_obj`` steht in PAYLOAD_FIELDS_INFRASTRUCTURE, die
    Guardrail ERWARTET das Objekt also im ``data``. Es steht NICHT in
    LOGGING_SNAPSHOT_EXCLUDE.
    """
    data = {
        "model": "gpt-4o",
        "messages": messages,
        "metadata": {},
        # Ein unbekanntes Feld erzwingt den Block in der FORMPRUEFUNG --
        # also bevor irgendetwas maskiert wurde. Der haerteste Fall: alle
        # Referenzen tragen dann den kompletten Rohtext.
        "audio": {"voice": "alloy"},
    }
    data["litellm_logging_obj"] = FakeLitellmLogging(messages)
    data["proxy_server_request"] = {
        "url": "http://proxy/v1/chat/completions",
        "method": "POST",
        "headers": {},
        "body": {"model": "gpt-4o", "messages": messages},
    }
    return data


class _Case(unittest.IsolatedAsyncioTestCase):
    def _messages(self):
        return [
            {"role": "user", "content": f"Hallo {_NAME}, IBAN {_IBAN}"},
            {"role": "user", "content": f"Und nochmal {_NAME}"},
        ]

    async def _blocked(self, data, call_type="acompletion"):
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _guard().async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type=call_type
            )
        return data

    def assert_kein_klartext(self, wert, wo):
        text = _als_text(wert)
        self.assertNotIn(_NAME, text, f"Klartext-Name in {wo}")
        self.assertNotIn(_IBAN, text, f"Klartext-IBAN in {wo}")


class TestDerAliasIstEchtGebaut(_Case):
    """BAUART-ABSICHERUNG -- und der wichtigste Test der Datei.

    Wenn das Fake den Alias nicht wirklich haelt, misst der Rest nichts und
    ist gruen, ohne etwas zu belegen. Genau diese Klasse Fehler ist der
    Grund, warum es diese Datei gibt.
    """

    def test_input_ist_die_identische_liste(self):
        msgs = self._messages()
        obj = FakeLitellmLogging(msgs)
        self.assertIs(
            obj.model_call_details["input"], msgs,
            "model_call_details['input'] muss dieselbe Liste sein (litellm :317)",
        )

    def test_messages_ist_eine_flache_kopie(self):
        msgs = self._messages()
        obj = FakeLitellmLogging(msgs)
        self.assertIsNot(
            obj.messages, msgs,
            "logging_obj.messages ist eine ANDERE Liste (copy.copy, :333)",
        )
        self.assertIs(
            obj.messages[0], msgs[0],
            "...aber die Message-DICTS sind dieselben Objekte",
        )

    def test_rebinding_erreicht_den_alias_nachweislich_nicht(self):
        """Der Kern des Befunds, isoliert: warum ``data[key] = X`` versagt."""
        msgs = self._messages()
        data = {"messages": msgs}
        obj = FakeLitellmLogging(msgs)

        data["messages"] = "<redigiert>"  # das alte Vorgehen

        self.assertIn(_NAME, _als_text(obj.messages))
        self.assertIn(_NAME, _als_text(obj.model_call_details["input"]))

    def test_nur_die_aeussere_liste_zu_kuerzen_reicht_ebenfalls_nicht(self):
        """Auch die naheliegende Verbesserung traegt nur halb -- deshalb ist
        der Fix dreiteilig und nicht zweiteilig."""
        msgs = self._messages()
        obj = FakeLitellmLogging(msgs)

        msgs[:] = [{"role": "user", "content": "<redigiert>"}]  # in place, aber nur aussen

        # Die identische Liste ist erreicht ...
        self.assertNotIn(_NAME, _als_text(obj.model_call_details["input"]))
        # ... die flache Kopie NICHT.
        self.assertIn(
            _NAME, _als_text(obj.messages),
            "copy.copy haelt eine eigene aeussere Liste -- messages[:] erreicht sie nie",
        )


class TestZweiteReferenzTraegtKeinenKlartext(_Case):
    """DER BEFUND. Gemessen wird ausschliesslich die ZWEITE Referenz --
    nie ``data['messages']``, den der alte Test geprueft hat."""

    async def test_logging_obj_messages_ist_redigiert(self):
        msgs = self._messages()
        data = _proxy_data(msgs)
        obj = data["litellm_logging_obj"]
        await self._blocked(data)
        self.assert_kein_klartext(obj.messages, "logging_obj.messages")

    async def test_model_call_details_input_ist_redigiert(self):
        """Die IDENTISCHE Liste (litellm :317) -- der Weg, den bisher
        niemand benannt hat."""
        msgs = self._messages()
        data = _proxy_data(msgs)
        obj = data["litellm_logging_obj"]
        await self._blocked(data)
        self.assert_kein_klartext(
            obj.model_call_details["input"], "model_call_details['input']"
        )

    async def test_model_call_details_messages_ist_redigiert(self):
        msgs = self._messages()
        data = _proxy_data(msgs)
        obj = data["litellm_logging_obj"]
        await self._blocked(data)
        self.assert_kein_klartext(
            obj.model_call_details["messages"], "model_call_details['messages']"
        )

    async def test_die_urspruenglichen_message_dicts_sind_geleert(self):
        """Die Dicts selbst -- der einzige Weg, der BEIDE Referenzen
        gleichzeitig erreicht. Wer sie haelt, haelt sonst den Klartext.

        Gemessen an den Dicts, die VOR dem Hook existierten: ein Fix, der
        nur neue Dicts einsetzt, laesst die alten unberuehrt im Alias
        stehen."""
        msgs = self._messages()
        dicts_vorher = list(msgs)
        data = _proxy_data(msgs)
        await self._blocked(data)
        for i, msg in enumerate(dicts_vorher):
            self.assert_kein_klartext(msg, f"urspruengliches Message-Dict [{i}]")


class TestRedaktionBleibtBrauchbar(_Case):
    """Ein Fix, der einen anderen Defekt erzeugt, ist kein Fix."""

    async def test_messages_bleibt_eine_liste(self):
        """F7: ``messages`` steht in _ALLE_MASKIERTEN_FELDER und wurde damit
        zu einem STRING. Ein String ist iterierbar -- Konsumenten stuerzen
        nicht ab, sie lesen ZEICHEN. Der Zweig
        ``if isinstance(data.get("messages"), list)`` war damit toter Code."""
        msgs = self._messages()
        data = _proxy_data(msgs)
        await self._blocked(data)
        self.assertIsInstance(
            data["messages"], list,
            "messages muss eine Liste bleiben -- ein String wird zeichenweise gelesen",
        )
        for msg in data["messages"]:
            self.assertIsInstance(msg, dict)
            self.assertIn("role", msg)

    async def test_der_block_bleibt_ein_block(self):
        """Der Aufraeumer darf die urspruengliche Ausnahme nie verdraengen."""
        msgs = self._messages()
        data = _proxy_data(msgs)
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _guard().async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="acompletion"
            )

    async def test_fehlendes_logging_obj_bricht_nicht(self):
        """Nicht jeder Aufrufer legt eines hinein (Tests, aeltere Versionen,
        andere Routen). Der Aufraeumer muss das aushalten."""
        msgs = self._messages()
        data = _proxy_data(msgs)
        del data["litellm_logging_obj"]
        await self._blocked(data)
        self.assert_kein_klartext(data["messages"], "data['messages']")

    async def test_logging_obj_ohne_update_messages_wird_trotzdem_redigiert(self):
        """Eine aeltere/andere litellm-Version kennt ``update_messages``
        vielleicht nicht. Dann muss der direkte Weg trotzdem greifen -- der
        Fix darf nicht an einer API haengen, die es woanders nicht gibt."""
        msgs = self._messages()

        class Fremd:
            def __init__(self, messages):
                self.messages = copy.copy(messages)
                self.model_call_details = {"input": messages}

        data = _proxy_data(msgs)
        data["litellm_logging_obj"] = Fremd(msgs)
        obj = data["litellm_logging_obj"]
        await self._blocked(data)
        self.assert_kein_klartext(obj.messages, "Fremd.messages")
        self.assert_kein_klartext(
            obj.model_call_details["input"], "Fremd.model_call_details['input']"
        )


if __name__ == "__main__":
    unittest.main()
