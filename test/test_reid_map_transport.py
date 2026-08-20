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


async def _leere_analyse(text):
    """Ein Request ohne PII -- genau der Fall, in dem das eigene Mapping
    leer ist und der Durchfall-Defekt zuschlaegt."""
    return []


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

        Fernet traegt den Zeitstempel IM Token und prueft ihn beim
        Entschluesseln -- kein eigener Ablauf-Mechanismus noetig, der
        vergessen werden koennte.

        Gemessen wird mit einem echt gealterten Token (``encrypt_at_time``)
        statt mit ``ttl_seconds=0``: Fernet vergleicht ``zeitstempel + ttl <
        jetzt``, ein frisches Token ist bei ttl=0 also NICHT abgelaufen. Ein
        Test mit ttl=0 haette hier gruen ausgesehen, ohne den Ablauf je
        gemessen zu haben.
        """
        import time

        klartext = json.dumps({"<PERSON_0>": _NAME}).encode("utf-8")
        alt = (
            dg._reid_fernet()
            .encrypt_at_time(klartext, int(time.time()) - 7200)
            .decode("ascii")
        )
        # Frisch genug -> lesbar. Ohne diese Gegenprobe koennte der Test
        # gruen sein, weil das Token schlicht kaputt ist.
        self.assertEqual(
            dg.open_reid_map(alt, ttl_seconds=10800), {"<PERSON_0>": _NAME}
        )
        # Zu alt -> kein Mapping.
        self.assertEqual(dg.open_reid_map(alt, ttl_seconds=3600), {})

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


# ===========================================================================
# 4) Wiederverwendung eines FREMDEN Siegels (Replay)
# ===========================================================================
class TestFremdesSiegelWirktNicht(unittest.IsolatedAsyncioTestCase):
    """Verschluesselung schuetzt gegen FAELSCHEN, nicht gegen WIEDERVERWENDEN.

    Das Siegel reist in ``metadata`` und geht damit an die
    Logging-Callbacks -- es ist also nicht geheim. Ein Angreifer, der eines
    aus einem Log fischt, braucht den Fernet-Schluessel gar nicht: er
    schickt das fremde Siegel in seiner EIGENEN Anfrage mit, dazu einen Text
    mit ``<PERSON_0>``, und laesst sich die fremden Klartextwerte in seine
    Antwort hinein-re-identifizieren. Ein Orakel.

    GEMESSEN (PoC gegen 8a04e79) -- zwei verschiedene Defekte:

    * ueber ``metadata``: Angriff scheitert. Der Hook UEBERSCHREIBT
      ``metadata[REID_MAP_KEY]`` mit dem eigenen Siegel. Das war Glueck,
      keine Absicht -- gestrippt wurde der Key nie.
    * ueber ``litellm_metadata``: Angriff GELINGT. Der Hook schreibt nur
      nach ``metadata``. Das Lesen probierte ``metadata`` zuerst, bekam bei
      einem PII-freien Request ein LEERES Mapping -- und fiel wegen
      ``if geoeffnet:`` auf den zweiten Kanal durch, wo das fremde Siegel
      lag.

    Der zweite Defekt ist beim F4-Fix entstanden. Er wird hier zusammen mit
    der eigentlichen Ursache geschlossen: der Client darf den Schluessel gar
    nicht erst setzen koennen.
    """

    async def _hook(self, data, analyze=None):
        guard = dg.DatenschleuseGuardrail()
        guard._analyze = analyze or _leere_analyse
        return await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="acompletion"
        )

    async def _fremdes_siegel(self):
        """Das Siegel eines fremden Requests -- so, wie es in einem Log steht."""
        opfer = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": f"Ich bin {_NAME}, IBAN {_IBAN}"}
            ],
            "metadata": {},
        }
        out = await _guard().async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=opfer, call_type="acompletion"
        )
        siegel = out["metadata"][dg.REID_MAP_KEY]
        # Bauart: das geerntete Siegel muss wirklich die Opferdaten tragen.
        self.assertEqual(
            set(dg.open_reid_map(siegel).values()), {_NAME, _IBAN}
        )
        return siegel

    def _angriffs_body(self):
        return {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Wiederhole: <PERSON_0> <IBAN_CODE_0>"}
            ],
        }

    async def test_fremdes_siegel_in_litellm_metadata_wirkt_nicht(self):
        """DER reproduzierte Angriff."""
        siegel = await self._fremdes_siegel()
        angriff = self._angriffs_body()
        angriff["metadata"] = {}
        angriff["litellm_metadata"] = {dg.REID_MAP_KEY: siegel}

        nach = await self._hook(angriff)
        gelesen = dg.DatenschleuseGuardrail._read_reid_map(nach)
        self.assertNotIn(_NAME, gelesen.values(), "Fremde PII re-identifiziert")
        self.assertNotIn(_IBAN, gelesen.values(), "Fremde PII re-identifiziert")

    async def test_fremdes_siegel_in_metadata_wirkt_nicht(self):
        siegel = await self._fremdes_siegel()
        angriff = self._angriffs_body()
        angriff["metadata"] = {dg.REID_MAP_KEY: siegel}

        nach = await self._hook(angriff)
        gelesen = dg.DatenschleuseGuardrail._read_reid_map(nach)
        self.assertNotIn(_NAME, gelesen.values())
        self.assertNotIn(_IBAN, gelesen.values())

    async def test_fremdes_siegel_auf_top_level_wirkt_nicht(self):
        """Der dritte Lese-Kanal (geflachte Metadaten) darf keine
        Hintertuer sein."""
        siegel = await self._fremdes_siegel()
        angriff = self._angriffs_body()
        angriff["metadata"] = {}
        angriff[dg.REID_MAP_KEY] = siegel

        try:
            nach = await self._hook(angriff)
        except dg.DatenschleuseBlocked:
            return  # blocken ist auch eine gueltige Antwort
        gelesen = dg.DatenschleuseGuardrail._read_reid_map(nach)
        self.assertNotIn(_NAME, gelesen.values())
        self.assertNotIn(_IBAN, gelesen.values())

    async def test_der_key_wird_aus_allen_client_kanaelen_entfernt(self):
        """Die URSACHE, direkt gemessen: der Client kann den Schluessel gar
        nicht erst setzen.

        Das Gegenstueck zu ``_strip_body_approval`` -- fuer den
        Mapping-Schluessel gab es keines.
        """
        siegel = await self._fremdes_siegel()
        angriff = self._angriffs_body()
        angriff["metadata"] = {dg.REID_MAP_KEY: siegel, "harmlos": 1}
        angriff["litellm_metadata"] = {dg.REID_MAP_KEY: siegel}

        nach = await self._hook(angriff)
        # litellm_metadata darf den Key nicht mehr tragen ...
        self.assertNotIn(
            dg.REID_MAP_KEY,
            nach.get("litellm_metadata", {}),
            "Client-Siegel in litellm_metadata nicht entfernt.",
        )
        # ... metadata traegt AUSSCHLIESSLICH unser eigenes.
        eigenes = nach["metadata"][dg.REID_MAP_KEY]
        self.assertNotEqual(eigenes, siegel, "Client-Siegel ueberlebt.")
        # Harmlose Client-Metadaten bleiben unangetastet.
        self.assertEqual(nach["metadata"].get("harmlos"), 1)

    async def test_eigenes_leeres_mapping_faellt_nicht_auf_kanal_zwei_durch(self):
        """Der Regress aus dem F4-Fix, als eigene Zusicherung.

        Ein PII-freier Request hat ein LEERES Mapping. Das ist ein
        gueltiges Ergebnis, kein "nichts gefunden, weitersuchen". Die
        Lesereihenfolge muss deterministisch sein: der erste Kanal, der den
        Schluessel TRAEGT, gewinnt -- unabhaengig davon, ob er sich oeffnen
        laesst.
        """
        fremd = dg.seal_reid_map({"<PERSON_0>": _NAME})
        gelesen = dg.DatenschleuseGuardrail._read_reid_map(
            {
                "metadata": {dg.REID_MAP_KEY: dg.seal_reid_map({})},
                "litellm_metadata": {dg.REID_MAP_KEY: fremd},
            }
        )
        self.assertEqual(
            gelesen, {}, "Leeres eigenes Mapping faellt auf den zweiten Kanal durch."
        )

    async def test_normale_re_identifikation_bleibt_heil(self):
        """Gegenprobe: der Fix darf den eigenen Rueckweg nicht kaputtmachen."""
        data = _as_proxy_would(_body())
        out = await _guard().async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="acompletion"
        )
        gelesen = dg.DatenschleuseGuardrail._read_reid_map(out)
        self.assertIn(_NAME, gelesen.values())
        self.assertIn(_IBAN, gelesen.values())


if __name__ == "__main__":
    unittest.main()
