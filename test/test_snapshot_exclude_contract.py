"""Der VERTRAG der Snapshot-Ausschlussmenge (DATENSCHLE-69, Security-F1b).

Warum es diese Datei gibt
-------------------------
Der erste F1-Fix baute ``LOGGING_SNAPSHOT_EXCLUDE`` gegen eine ANGENOMMENE
litellm-Konstante -- und der zugehoerige Test hat die Annahme dupliziert
statt sie zu pruefen. Zwei Kopien derselben Vermutung sehen aus wie eine
Bestaetigung, sind aber keine. Genau daran ist die Runde gescheitert.

Diese Datei zieht die Konsequenz und trennt ZWEI Aussagen, die vorher
vermischt waren:

1. Die SICHERHEITS-Aussage (``TestCredentialsNeverInSnapshot``): im
   Logging-Schnappschuss steht kein Zugangs-Token. Sie haengt an keiner
   litellm-Version, laeuft immer und ist der eigentliche Schutz.

2. Die VERTRAGS-Aussage (``TestSnapshotExcludeMatchesLitellm``): unsere
   Ausschlussmenge deckt die des INSTALLIERTEN litellm ab. Sie wird
   GEMESSEN -- die Konstante wird aus dem litellm-Quelltext gelesen, nicht
   hier abgeschrieben. Ohne installiertes litellm gibt es keine Messung und
   der Test sagt das offen (skip), statt eine Vermutung als Messung zu
   verkaufen.

Die Richtung des Vertrags ist Absicht: unsere Menge muss eine OBERMENGE
sein, keine Gleichheit.

  * Ein Key zu WENIG (litellm schliesst ihn aus, wir nicht) ist der
    gefaehrliche Fall: er landet im Schnappschuss, obwohl litellm ihn
    bewusst herausgehalten hat. Genau so ist ``api_key`` hineingeraten.
  * Ein Key zu VIEL (wir schliessen ihn aus, litellm nicht) zeigt den
    Konsumenten weniger als frueher -- nie mehr. Kein Leck.

Der zurueckgezogene Denkfehler
------------------------------
Der alte Kommentar im Guardrail behauptete, Versionsdrift sei "in BEIDE
Richtungen harmlos -- wir nehmen einen Key zu viel auf (er ist dann
maskiert oder registriert, also geprueft)". Das traegt nicht: ``api_key``
ist VALIDIERT, nicht maskiert. Der Formpruefer sagt "sieht aus wie ein
Token" und laesst ihn unveraendert durch. Ein Token, das die Formpruefung
besteht, ist immer noch ein Token im Log (Gesetz 5,
``docs/foundation/security-baseline.md``: keine Tokens in Logs).

Laeuft OHNE laufenden Presidio-Container. Die Vertrags-Klasse laeuft nur
MIT installiertem litellm; die Sicherheits-Klasse laeuft immer.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest test.test_snapshot_exclude_contract -v
"""

import ast
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


_CLIENT_TOKEN = "sk-CLIENT-XKEY-must-never-be-logged"


async def _no_pii(text):
    """Kein Presidio noetig: dieser Test misst Zugangs-Token, nicht PII."""
    return []


def _guard(**kwargs):
    guard = dg.DatenschleuseGuardrail(**kwargs)
    guard._analyze = _no_pii
    return guard


def _as_proxy_would(body):
    """Baut den Request samt flachem Logging-Schnappschuss auf.

    Der Schnappschuss wird hier ABSICHTLICH mit litellms gemessener Menge
    gebaut -- also ohne die Credential-Keys. Das bildet den Ist-Zustand des
    Proxys nach: ``api_key`` steht dort NICHT im Schnappschuss, bevor unser
    Hook laeuft. Taucht er hinterher darin auf, hat unser Re-Sync ihn
    hineingetragen -- und genau das ist der Befund.
    """
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
        if k not in _litellm_snapshot_exclude_or_default()
    }
    return data


# ===========================================================================
# Messung: litellms Ausschlussmenge aus dem QUELLTEXT lesen
# ===========================================================================
def _extract_body_snapshot_exclude(source: str):
    """Liest ``_body_snapshot_exclude`` aus litellms Quelltext.

    Die Konstante ist eine LOKALE Variable in
    ``add_litellm_data_to_request`` -- importierbar ist sie also nicht. Statt
    sie abzuschreiben (der Fehler, der zu diesem Test gefuehrt hat), wird der
    Quelltext geparst.

    Beherrscht beide bisher gesehenen Schreibweisen:
        _body_snapshot_exclude = {"a", "b"}
        _body_snapshot_exclude = frozenset({"a", "b"}) | _ANDERE_MENGE

    Gibt ``None`` zurueck, wenn die Zuweisung nicht gefunden oder nicht
    ausgewertet werden kann. ``None`` heisst ausdruecklich "nicht gemessen"
    und fuehrt zum skip -- nie zu einem stillen Durchwinken.
    """
    baum = ast.parse(source)

    # Alle einfachen Mengen-Zuweisungen einsammeln, damit ein ``A | B`` seine
    # Namen aufloesen kann.
    bekannt = {}

    def als_menge(knoten):
        if isinstance(knoten, ast.Set):
            werte = set()
            for element in knoten.elts:
                if not isinstance(element, ast.Constant) or not isinstance(
                    element.value, str
                ):
                    return None
                werte.add(element.value)
            return werte
        # frozenset({...}) / set({...})
        if (
            isinstance(knoten, ast.Call)
            and isinstance(knoten.func, ast.Name)
            and knoten.func.id in ("frozenset", "set")
            and len(knoten.args) == 1
        ):
            return als_menge(knoten.args[0])
        if isinstance(knoten, ast.Name):
            return bekannt.get(knoten.id)
        if isinstance(knoten, ast.BinOp) and isinstance(knoten.op, ast.BitOr):
            links = als_menge(knoten.left)
            rechts = als_menge(knoten.right)
            if links is None or rechts is None:
                return None
            return links | rechts
        return None

    gefunden = None
    for knoten in ast.walk(baum):
        if not isinstance(knoten, ast.Assign):
            continue
        for ziel in knoten.targets:
            if not isinstance(ziel, ast.Name):
                continue
            wert = als_menge(knoten.value)
            if wert is None:
                continue
            bekannt[ziel.id] = wert
            if ziel.id == "_body_snapshot_exclude":
                gefunden = wert
    return None if gefunden is None else frozenset(gefunden)


def _installiertes_litellm_exclude():
    """Die GEMESSENE Menge des installierten litellm -- oder ``None``."""
    try:
        import inspect

        from litellm.proxy import litellm_pre_call_utils
    except Exception:
        return None
    try:
        quelle = inspect.getsource(litellm_pre_call_utils)
    except Exception:
        return None
    return _extract_body_snapshot_exclude(quelle)


def _litellm_snapshot_exclude_or_default():
    """Fuer den Fixture-Aufbau: gemessen, wenn moeglich; sonst die kleinste
    bekannte Form. Die kleinste Form ist hier die KONSERVATIVE Wahl -- sie
    legt ``api_key`` in den Ausgangs-Schnappschuss NICHT hinein und laesst
    den Test damit genau das messen, was unser Re-Sync tut."""
    gemessen = _installiertes_litellm_exclude()
    if gemessen is not None:
        return gemessen
    return frozenset({"secret_fields", "proxy_server_request"})


# ===========================================================================
# 1) Die Sicherheits-Aussage -- laeuft IMMER
# ===========================================================================
class TestCredentialsNeverInSnapshot(unittest.IsolatedAsyncioTestCase):
    """Kein Zugangs-Token im Logging-Schnappschuss. Punkt.

    Diese Klasse haengt an keiner litellm-Version. Sie misst das Verhalten
    unseres eigenen Re-Syncs und ist der Test, der den Befund F1b haelt.
    """

    async def _run(self, data, call_type="acompletion"):
        return await _guard().async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type=call_type
        )

    def _body(self):
        return {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hallo"}],
        }

    async def test_pass_through_api_key_landet_nicht_im_snapshot(self):
        """DER Befund F1b.

        ``litellm_pre_call_utils`` setzt ``data["api_key"]`` aus dem
        ``x-api-key``-Header, sobald Pass-Through-Auth aktiv ist -- ein
        ausdruecklich unterstuetztes Setup (1.96.2, Zeile 1422). Der
        Schnappschuss entsteht DANACH (Zeile 1590).

        GEMESSENE KORREKTUR am urspruenglichen Befund: auf den hier
        pruefbaren Versionen (1.94.0, 1.96.2) steht ``api_key`` damit schon
        in litellms EIGENEM Schnappschuss -- unser Re-Sync hat ihn nicht
        hineingetragen, er war bereits drin. F1b ist auf diesen Versionen
        also kein Regress unseres Fixes, sondern ein vorbestehendes Leck.

        Fuer die Zusicherung aendert das nichts, und genau deshalb ist sie so
        formuliert: NACH unserem Hook steht kein Token im Schnappschuss --
        unabhaengig davon, wer es hineingelegt hat. Wo litellm den Key selbst
        ausschliesst, halten wir ihn ebenfalls heraus; wo litellm ihn drin
        laesst, sind wir strenger als litellm. Beides ist dieselbe Regel.
        """
        body = self._body()
        body["api_key"] = _CLIENT_TOKEN
        data = _as_proxy_would(body)

        # Bauart-Absicherung: das Token muss im Payload ueberhaupt ankommen,
        # sonst misst der Test nichts.
        self.assertEqual(data.get("api_key"), _CLIENT_TOKEN)

        out = await self._run(data)
        snapshot = out["proxy_server_request"]["body"]

        self.assertNotIn(
            "api_key",
            snapshot,
            "Zugangs-Token im Logging-Schnappschuss (Gesetz 5, "
            "security-baseline.md: keine Tokens in Logs).",
        )
        self.assertNotIn(
            _CLIENT_TOKEN,
            json.dumps(snapshot, ensure_ascii=False, default=str),
            "Der Token-WERT steht im Schnappschuss.",
        )

    async def test_api_key_erreicht_den_provider_unveraendert(self):
        """Die Gegenprobe zum Fix: aus dem LOG heraushalten heisst NICHT,
        ihn kaputtzumachen. Pass-Through-Auth muss weiter funktionieren --
        das Token gehoert in den Payload, nur eben nicht in den
        Schnappschuss."""
        body = self._body()
        body["api_key"] = _CLIENT_TOKEN
        out = await self._run(_as_proxy_would(body))
        self.assertEqual(
            out.get("api_key"),
            _CLIENT_TOKEN,
            "Der Fix darf Pass-Through-Auth nicht beschaedigen.",
        )

    async def test_uebrige_credential_keys_kommen_gar_nicht_erst_so_weit(self):
        """Die anderen drei Credential-Keys sind auf einer FRUEHEREN Stufe
        dicht -- und das ist hier die Aussage.

        ``headers``, ``extra_headers`` und ``provider_specific_header``
        stehen in ``PAYLOAD_FIELDS_TRANSPORT_CHANNELS`` und blocken schon in
        der Formpruefung, lange vor dem Re-Sync. Sie koennen den
        Schnappschuss also nicht erreichen.

        Warum sie trotzdem in ``SNAPSHOT_CREDENTIAL_KEYS`` stehen: der
        Ausschluss ist die zweite Schranke. Wuerde einer von ihnen je ins
        Register wandern (weil ein kuenftiger Beitrag ihn "behandelt"), waere
        er ohne diesen Eintrag sofort im Log. Der Ausschluss kostet nichts --
        Richtung "ein Key zu viel" ist die harmlose -- und haelt genau dann,
        wenn die erste Schranke faellt.

        Ein Test pro Key, damit ein Teil-Regress nicht von einem gruenen
        Sammel-Assert verdeckt wird.
        """
        for key in sorted(dg.SNAPSHOT_CREDENTIAL_KEYS - {"api_key"}):
            with self.subTest(key=key):
                data = _as_proxy_would(self._body())
                data[key] = _CLIENT_TOKEN
                with self.assertRaises(
                    dg.DatenschleuseBlocked,
                    msg=f"{key!r} muss fail-closed blocken.",
                ):
                    await self._run(data)

    def test_credential_keys_sind_vom_ausschluss_gedeckt(self):
        """Bauart: jeder Credential-Key ist auch wirklich ausgeschlossen.

        Trennt die Absicht (``SNAPSHOT_CREDENTIAL_KEYS``) von der Wirkung
        (``LOGGING_SNAPSHOT_EXCLUDE``). Ein Key, den jemand der Absichts-
        Menge hinzufuegt, ohne dass er in der Wirkungs-Menge landet, waere
        eine stille Luege.
        """
        self.assertTrue(
            dg.SNAPSHOT_CREDENTIAL_KEYS <= dg.LOGGING_SNAPSHOT_EXCLUDE,
            "Credential-Keys stehen nicht vollstaendig im Ausschluss.",
        )
        self.assertIn("api_key", dg.LOGGING_SNAPSHOT_EXCLUDE)

    async def test_snapshot_bleibt_fuer_die_kostenerfassung_brauchbar(self):
        """Der Fix darf den Schnappschuss nicht leeren -- ``spend_tracking``
        und ``standard_logging_payload`` lesen ihn."""
        out = await self._run(_as_proxy_would(self._body()))
        snapshot = out["proxy_server_request"]["body"]
        self.assertEqual(snapshot.get("model"), "gpt-4o")
        self.assertIn("messages", snapshot)


# ===========================================================================
# 2) Die Vertrags-Aussage -- GEMESSEN gegen das installierte litellm
# ===========================================================================
class TestSnapshotExcludeMatchesLitellm(unittest.TestCase):
    """Unsere Ausschlussmenge gegen die des installierten litellm.

    Kein Abschreiben: die Konstante wird aus litellms Quelltext geparst.
    Ohne installiertes litellm wird uebersprungen -- eine ehrliche
    Nicht-Messung ist besser als eine duplizierte Annahme.
    """

    def setUp(self):
        self.gemessen = _installiertes_litellm_exclude()
        if self.gemessen is None:
            self.skipTest(
                "litellm ist in dieser Umgebung nicht installiert (oder die "
                "Zuweisung _body_snapshot_exclude ist nicht mehr auffindbar) "
                "-- der Vertrag ist hier NICHT gemessen. Die Sicherheits-"
                "Aussage in TestCredentialsNeverInSnapshot laeuft trotzdem."
            )

    def test_unsere_menge_deckt_litellms_menge_ab(self):
        """Die Vertragsrichtung: Obermenge, nicht Gleichheit.

        Fehlt uns ein Key, den litellm ausschliesst, tragen wir ihn beim
        Neubau ins Log -- der Defekt F1b. Haben wir einen mehr, sehen die
        Konsumenten weniger. Nur die erste Richtung ist ein Leck.
        """
        fehlend = sorted(self.gemessen - dg.LOGGING_SNAPSHOT_EXCLUDE)
        self.assertEqual(
            fehlend,
            [],
            "LOGGING_SNAPSHOT_EXCLUDE ist zu klein: das installierte litellm "
            f"haelt {fehlend} aus dem Schnappschuss heraus, unser Re-Sync "
            "traegt sie wieder hinein.",
        )

    def test_die_messung_hat_wirklich_etwas_gemessen(self):
        """Bauart-Absicherung: ein leeres Parse-Ergebnis wuerde den Test
        oben trivial gruen faerben."""
        self.assertIn("proxy_server_request", self.gemessen)
        self.assertIn("secret_fields", self.gemessen)


class TestExcludeExtractor(unittest.TestCase):
    """Der Parser selbst -- er ist die Messvorrichtung und muss stimmen.

    Ohne diese Tests waere die Messung oben nur so vertrauenswuerdig wie ein
    ungeprueftes Stueck Regex-Logik. Beide real gesehenen Schreibweisen
    werden abgedeckt, damit ein litellm-Upgrade den Vertrag nicht still in
    einen skip verwandelt.
    """

    def test_einfaches_mengen_literal(self):
        quelle = 'def f():\n    _body_snapshot_exclude = {"a", "b"}\n'
        self.assertEqual(
            _extract_body_snapshot_exclude(quelle), frozenset({"a", "b"})
        )

    def test_frozenset_mit_vereinigung_ueber_namen(self):
        quelle = (
            "def f():\n"
            '    _CRED = frozenset({"api_key", "headers"})\n'
            '    _body_snapshot_exclude = frozenset({"secret_fields"}) | _CRED\n'
        )
        self.assertEqual(
            _extract_body_snapshot_exclude(quelle),
            frozenset({"secret_fields", "api_key", "headers"}),
        )

    def test_unauffindbare_zuweisung_meldet_none(self):
        """Nicht gefunden heisst ``None`` -- also skip, nicht "leere Menge,
        alles gut"."""
        self.assertIsNone(_extract_body_snapshot_exclude("x = 1\n"))

    def test_nicht_auswertbare_form_meldet_none(self):
        """Eine Form, die wir nicht sicher lesen koennen, ist eine
        Nicht-Messung -- kein stilles Durchwinken."""
        quelle = "def f():\n    _body_snapshot_exclude = set(irgendwas())\n"
        self.assertIsNone(_extract_body_snapshot_exclude(quelle))


if __name__ == "__main__":
    unittest.main()
