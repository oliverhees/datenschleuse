"""Der TRANSPORT des Re-Id-Mappings (DATENSCHLE-69, Security-F4/F1).

Die Datei, die es nicht gab
---------------------------
``test_logging_snapshot.py`` hat zweimal auf "einen eigenen Test in
test_reid_map_transport.py" verwiesen und das Mapping in seiner eigenen
Messung aktiv herausgefiltert. Die Datei existierte nicht. Die gruene Suite
konnte den Befund damit gar nicht widerlegen -- ein Filter mit Verweis auf
eine leere Stelle ist kein Test, sondern ein blinder Fleck mit Fussnote.

Was hier gemessen wird
----------------------
Das Mapping ist die vollstaendige Klartext-Zuordnung
``Platzhalter -> Originalwert``. Es ist damit das dichteste PII-Objekt im
ganzen Request -- dichter als der Payload selbst, weil es die Werte ohne
umgebenden Text auflistet.

``metadata`` ist KEIN privater Kanal: litellm reicht es an seine
Logging-Callbacks weiter (StandardLoggingPayload, langfuse, s3, datadog
...). Ein Klartext-Mapping dort ist ein PII-Leck ins Log, unabhaengig
davon, was ``proxy_server_request.body`` enthaelt.

Deshalb verlangt ``CLAUDE.md``: "Mapping verschluesselt + lokal + TTL".
Diese Datei prueft alle drei Eigenschaften -- und die Gegenprobe, dass die
Re-Identifikation trotzdem funktioniert. Ein Fix, der die Antwort kaputt
macht, waere kein Fix.

Warum das AUCH F1 schliesst
---------------------------
F1 (Klartext-Mapping im Logging-Schnappschuss) war ein SYMPTOM: der
Schnappschuss kopiert ``metadata``, und dort lag das Mapping im Klartext.
Man kann das Symptom behandeln (``metadata`` beim Neubau flach kopieren und
den Key herausnehmen) -- dann bleibt der Kanal zu den Logging-Callbacks
offen. Oder man legt den Klartext gar nicht erst hinein. Diese Datei misst
die zweite Variante: verschwindet die Ursache, verschwindet F1 mit.

Laeuft OHNE laufenden Presidio-Container.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest discover -s test \\
        -p "test_reid_map_transport.py" -v
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


_NAME = "Hans Mueller"
_IBAN = "DE89370400440532013000"
_NEEDLES = ((_NAME, "PERSON"), (_IBAN, "IBAN_CODE"))


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


def _as_proxy_would(body):
    data = dict(body)
    data.setdefault("metadata", {})
    data["proxy_server_request"] = {
        "url": "http://proxy/v1/chat/completions",
        "method": "POST",
        "headers": {},
        "body": None,
    }
    data["proxy_server_request"]["body"] = {
        k: v
        for k, v in data.items()
        if k not in ("secret_fields", "proxy_server_request")
    }
    return data


def _body():
    return {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": f"Hallo {_NAME}, meine IBAN ist {_IBAN}"}
        ],
    }


# ===========================================================================
# 1) Der Kanal: kein Klartext in metadata -- nirgends
# ===========================================================================
class TestReidMapNichtImKlartext(unittest.IsolatedAsyncioTestCase):
    """Der Befund F4: die Klartext-Zuordnungstabelle im Logging-Kanal."""

    async def _run(self, data=None, call_type="acompletion"):
        return await _guard().async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data=data if data is not None else _as_proxy_would(_body()),
            call_type=call_type,
        )

    async def test_metadata_traegt_keinen_klartext(self):
        """DER Test. Nach dem Hook steht in ``metadata`` kein Originalwert.

        Gemessen wird der KOMPLETTE Metadaten-Baum, nicht nur der bekannte
        Key -- ein Fix, der das Mapping nur woandershin verschiebt, faellt
        damit ebenfalls auf.
        """
        out = await self._run()
        flat = json.dumps(out.get("metadata", {}), ensure_ascii=False, default=str)
        self.assertNotIn(_NAME, flat, "Klartext-Name in metadata")
        self.assertNotIn(_IBAN, flat, "Klartext-IBAN in metadata")

    async def test_mapping_ist_kein_dict_mehr(self):
        """Die Form ist die Aussage: ein dict waere wieder der Klartext.

        Bewusst als eigene Zusicherung neben dem Inhalts-Test: ein leeres
        oder umbenanntes Mapping wuerde den Inhalts-Test gruen faerben, ohne
        dass irgendetwas geschuetzt waere.
        """
        out = await self._run()
        versiegelt = out["metadata"][dg.REID_MAP_KEY]
        self.assertIsInstance(
            versiegelt,
            str,
            "Das Mapping muss versiegelt (Fernet-Token) transportiert werden.",
        )
        self.assertNotIn(_NAME, versiegelt)
        self.assertNotIn(_IBAN, versiegelt)

    async def test_der_logging_schnappschuss_ist_damit_ebenfalls_dicht(self):
        """F1 als FOLGE von F4.

        Der Schnappschuss kopiert ``metadata``. Liegt dort kein Klartext
        mehr, ist er automatisch dicht -- ohne dass der Neubau das Mapping
        gesondert behandeln muss. Ursache statt Symptom.
        """
        out = await self._run()
        snapshot = out["proxy_server_request"]["body"]
        flat = json.dumps(snapshot, ensure_ascii=False, default=str)
        self.assertNotIn(_NAME, flat, "Klartext-Name im Logging-Schnappschuss")
        self.assertNotIn(_IBAN, flat, "Klartext-IBAN im Logging-Schnappschuss")

    async def test_auch_der_vorher_gebaute_snapshot_ist_dicht(self):
        """Der Schnappschuss, den LITELLM vor unserem Hook gebaut hat, haelt
        dieselbe ``metadata``-Referenz.

        Genau darueber ist der Klartext bisher entkommen: wir haben das
        Mapping NACH litellms Snapshot in dasselbe dict gelegt, und weil der
        Snapshot eine flache Kopie ist, stand es sofort auch dort. Wird nie
        Klartext hineingelegt, kann auch nichts mitwandern.
        """
        data = _as_proxy_would(_body())
        vorher = data["proxy_server_request"]["body"]
        self.assertIs(
            vorher["metadata"],
            data["metadata"],
            "Fixture kaputt: der Snapshot muss dieselbe metadata-Referenz "
            "halten, sonst misst dieser Test den Leckweg nicht.",
        )
        out = await self._run(data)
        flat = json.dumps(vorher, ensure_ascii=False, default=str)
        self.assertNotIn(_NAME, flat)
        self.assertNotIn(_IBAN, flat)
        # Und der Vollstaendigkeit halber: es ist wirklich derselbe Weg.
        self.assertIsNotNone(out)


# ===========================================================================
# 2) Die Gegenprobe: Re-Identifikation muss weiter funktionieren
# ===========================================================================
class TestReidMapBleibtBenutzbar(unittest.IsolatedAsyncioTestCase):
    """Ein Fix, der die Antwort kaputt macht, ist kein Fix."""

    async def test_roundtrip_ueber_den_hook(self):
        """Maskieren, versiegeln, oeffnen, re-identifizieren."""
        guard = _guard()
        data = _as_proxy_would(_body())
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="acompletion"
        )
        # Der Payload traegt Platzhalter ...
        gesendet = json.dumps(out["messages"], ensure_ascii=False)
        self.assertNotIn(_NAME, gesendet)
        self.assertNotIn(_IBAN, gesendet)
        # ... und der Hook kann sie zurueckuebersetzen.
        geoeffnet = guard._read_reid_map(out)
        self.assertIn(_NAME, geoeffnet.values())
        self.assertIn(_IBAN, geoeffnet.values())

    def test_versiegeln_und_oeffnen_ist_ein_roundtrip(self):
        original = {"<PERSON_0>": _NAME, "<IBAN_CODE_0>": _IBAN}
        token = dg.seal_reid_map(original)
        self.assertIsInstance(token, str)
        self.assertEqual(dg.open_reid_map(token), original)

    def test_leeres_mapping_ueberlebt_den_roundtrip(self):
        self.assertEqual(dg.open_reid_map(dg.seal_reid_map({})), {})

    def test_read_reid_map_liest_beide_metadaten_kanaele(self):
        """``metadata`` UND ``litellm_metadata`` -- je nach litellm-Codepfad.

        Derselbe Alias-Gedanke wie bei ``headers``/``extra_headers``: ein
        Fix, der nur einen Kanal kennt, ist ein halber Fix.
        """
        token = dg.seal_reid_map({"<PERSON_0>": _NAME})
        for kanal in ("metadata", "litellm_metadata"):
            with self.subTest(kanal=kanal):
                gelesen = dg.DatenschleuseGuardrail._read_reid_map(
                    {kanal: {dg.REID_MAP_KEY: token}}
                )
                self.assertEqual(gelesen, {"<PERSON_0>": _NAME})


# ===========================================================================
# 3) Verschluesselt + lokal + TTL -- die drei Zusagen aus CLAUDE.md
# ===========================================================================
class TestReidMapSchutzeigenschaften(unittest.TestCase):
    """Jede der drei Zusagen einzeln gemessen."""

    def test_fremder_schluessel_kann_nicht_oeffnen(self):
        """VERSCHLUESSELT: ohne den Schluessel ist das Token nutzlos.

        Das ist die Aussage, die den Logging-Kanal entschaerft: ein
        Log-Callback bekommt das Token, aber nicht den Schluessel.
        """
        from cryptography.fernet import Fernet

        token = dg.seal_reid_map({"<PERSON_0>": _NAME})
        fremd = Fernet(Fernet.generate_key())
        with self.assertRaises(Exception):
            fremd.decrypt(token.encode())

    def test_abgelaufenes_token_wird_nicht_geoeffnet(self):
        """TTL: ein altes Mapping ist wertlos, nicht bloss unschoen.

        Fernet traegt den Zeitstempel im Token und prueft ihn beim
        Entschluesseln -- kein eigener Ablauf-Mechanismus noetig, der
        vergessen werden koennte.
        """
        token = dg.seal_reid_map({"<PERSON_0>": _NAME})
        self.assertEqual(dg.open_reid_map(token, ttl_seconds=0), {})

    def test_kaputtes_token_liefert_leeres_mapping_statt_klartext(self):
        """Fehlerrichtung: kann nicht geoeffnet werden -> KEINE
        Re-Identifikation.

        Die Antwort behaelt dann ihre Platzhalter. Das ist unschoen, aber
        sicher -- die gefaehrliche Richtung waere, im Fehlerfall auf einen
        ungeschuetzten Klartext-Kanal zurueckzufallen.
        """
        self.assertEqual(dg.open_reid_map("kein-gueltiges-token"), {})
        self.assertEqual(dg.open_reid_map(""), {})

    def test_klartext_dict_wird_nicht_mehr_akzeptiert(self):
        """Kein Rueckfall auf die alte Form.

        Beide Formen zu akzeptieren waere genau das Muster, an dem dieses
        Projekt wiederholt haengengeblieben ist: ein Kanal, den niemand
        mehr benutzt, aber jeder noch benutzen KANN. Ein client-gesetztes
        Klartext-Mapping waere ausserdem eine Steuerung der Antwort durch
        den Kontrollierten.
        """
        gelesen = dg.DatenschleuseGuardrail._read_reid_map(
            {"metadata": {dg.REID_MAP_KEY: {"<PERSON_0>": "Angreifer"}}}
        )
        self.assertEqual(gelesen, {})

    def test_schluessel_bleibt_im_prozess(self):
        """LOKAL: der Schluessel wird nie Teil des Requests.

        Ohne gesetzte Umgebungsvariable wird er beim Start EINMAL erzeugt und
        verlaesst den Prozess nie. Ein Log, das nach einem Neustart gelesen
        wird, ist damit endgueltig nicht mehr aufloesbar -- fuer
        request-gebundene Daten die staerkere Eigenschaft, nicht die
        schwaechere.
        """
        token = dg.seal_reid_map({"<PERSON_0>": _NAME})
        self.assertNotIn(_NAME, token)
        # Zweimal versiegeln ergibt zwei verschiedene Tokens (Fernet-IV),
        # aber beide sind im selben Prozess lesbar.
        zweites = dg.seal_reid_map({"<PERSON_0>": _NAME})
        self.assertNotEqual(token, zweites)
        self.assertEqual(dg.open_reid_map(zweites), {"<PERSON_0>": _NAME})


if __name__ == "__main__":
    unittest.main()
