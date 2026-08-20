"""Das Betreiber-Geheimnis des Freigabe-Headers (DATENSCHLE-69, Runde 4, F2).

Der Befund
----------
``_operator_approved`` verglich zwei ``str`` mit ``hmac.compare_digest``.
Diese Funktion verweigert ``str``-Argumente, sobald auch nur EIN Zeichen
ausserhalb von ASCII liegt -- sie wirft dann ``TypeError``. Der Wurf passiert
MITTEN in der Schleife, also BEVOR ``headers[name] = APPROVAL_HEADER_REDACTED``
laeuft.

Gemessen (Auditor, Runde 4)::

    A) ASCII-Geheimnis        -> DURCH      | Header im Log: '<redacted-by-datenschleuse>'
    B) Geheimnis mit Umlaut   -> TypeError  | Header im Log: 'Schluessel-fuer-Buero-Muenchen-2026'
       GEHEIMNIS UNREDIGIERT IM LOG: True

Damit sind zwei bindende Regeln des Grundbuchs gebrochen:

1. "Das Geheimnis wird nach der Pruefung redigiert, AUCH BEI FALSCHEM WERT."
   ``_redact_logging_snapshot`` ersetzt nur ``psr["body"]``, nie
   ``psr["headers"]`` -- der einzige Ort, an dem der Header-Wert redigiert
   wird, ist die uebersprungene Zeile.
2. "Ein unkontrollierter Fehlerpfad ist kein fail-closed." Ein roher
   ``TypeError`` wird von litellm zu einem opaken 500, nicht zu einem
   Guardrail-Block.

Ausloesbar von ZWEI Seiten:

* Ein CLIENT schickt den Header mit einem Umlaut -- jeder Request stirbt am
  ``TypeError`` (Denial of Service auf den ganzen Proxy).
* Ein BETREIBER waehlt eine deutsche Passphrase -- der Freigabeweg ist
  dauerhaft kaputt, und sein echtes Geheimnis landet bei JEDEM Versuch
  unredigiert im Failure-Log.

Die Entscheidung
----------------
Drei Teile, analog zur Behandlung, die ``configure_reid_crypto()`` in dieser
Runde bekommen hat:

* Verglichen wird auf ``bytes`` (UTF-8). ``compare_digest`` ist auf Bytes
  definiert und bleibt dort konstantzeitig.
* Die Redaktion steht im ``finally``. Sie ist damit unabhaengig davon, ob der
  Vergleich getroffen, danebengelegen oder geworfen hat.
* Das Geheimnis wird BEIM START validiert, nicht beim ersten Request. Ein
  Betreiber, der etwas Unbrauchbares konfiguriert, erfaehrt es beim
  Hochfahren -- nicht als scheinbar zufaelliges Fehlschlagen im Betrieb.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest discover -s test \\
        -p "test_approval_header_secret.py" -v
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402
import sensitivity_classifier as sc  # noqa: E402


#: Derselbe Stufe-2-Text wie in test_approval_source.py -- er ist dort gegen
#: den echten Klassifizierer verifiziert. Ohne echte Stufe 2 wuerde diese
#: Datei nichts messen: das Freigabe-Gate wuerde gar nicht befragt.
_TIER2_NAME = "Max Mustermann"
_TIER2_TEXT = (
    "Streng vertraulich: Gehaltsliste und Kuendigungsplanung fuer "
    f"{_TIER2_NAME}, Personalakte."
)

#: Ein Betreiber-Geheimnis mit Umlaut. GENAU der Wert, an dem der Vergleich
#: heute wirft -- eine deutsche Passphrase ist fuer ein DACH-Projekt der
#: Normalfall, nicht der Sonderfall.
_UMLAUT_SECRET = "Schluessel-fuer-das-Buero-in-München-2026"
_ASCII_SECRET = "s3cr3t-vom-betreiber-lang-genug-fuer-die-grenze"


async def _fake_analyze(text):
    idx = text.find(_TIER2_NAME)
    if idx < 0:
        return []
    return [{
        "entity_type": "PERSON",
        "start": idx,
        "end": idx + len(_TIER2_NAME),
        "score": 0.99,
    }]


def _guard(**kwargs):
    kwargs.setdefault("presidio_analyzer_url", "http://presidio.invalid")
    kwargs.setdefault("language", "de")
    kwargs.setdefault("image_policy", "pass")
    guard = dg.DatenschleuseGuardrail(**kwargs)
    guard._analyze = _fake_analyze
    return guard


def _body_with_header(wert):
    return {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": _TIER2_TEXT}],
        "proxy_server_request": {
            "url": "http://proxy/v1/chat/completions",
            "method": "POST",
            "headers": {sc.APPROVAL_HEADER: wert},
        },
    }


class _Case(unittest.IsolatedAsyncioTestCase):
    async def run_hook(self, data, guard):
        return await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="acompletion"
        )

    def assert_redigiert(self, data):
        """Der Header-Wert darf nach dem Hook NIE mehr der Klartext sein --
        egal ob getroffen, danebengelegen oder geworfen. ``data`` ist dasselbe
        Objekt, das ``post_call_failure_hook`` und die Failure-Callbacks
        sehen."""
        kopf = data["proxy_server_request"]["headers"][sc.APPROVAL_HEADER]
        self.assertEqual(
            kopf,
            dg.DatenschleuseGuardrail.APPROVAL_HEADER_REDACTED,
            "Der Header-Wert steht unredigiert im Logging-Kanal.",
        )


class TestFixtureIstEchteStufe2(_Case):
    """Bauart-Absicherung: ohne echte Stufe 2 misst diese Datei nichts."""

    async def test_fixture_wird_als_stufe_2_klassifiziert(self):
        entities = await _fake_analyze(_TIER2_TEXT)
        klass = sc.SensitivityClassifier().classify(_TIER2_TEXT, entities=entities)
        self.assertIs(klass.tier, sc.Tier.TIER_2, klass.summary())


class TestNichtAsciiBrichtDenVergleichNicht(_Case):
    """DER Befund, Teil 1: ein Nicht-ASCII-Zeichen darf den Vergleich nicht
    zum Absturz bringen."""

    async def test_betreiber_geheimnis_mit_umlaut_gibt_frei(self):
        """Weg B des Auditors: der Betreiber waehlt eine deutsche Passphrase.
        Heute ist sein Freigabeweg dauerhaft kaputt."""
        data = _body_with_header(_UMLAUT_SECRET)
        guard = _guard(approval_header_secret=_UMLAUT_SECRET)
        await self.run_hook(data, guard)  # darf NICHT werfen
        self.assert_redigiert(data)

    async def test_client_header_mit_umlaut_toetet_den_request_nicht(self):
        """Weg A des Auditors: ein Client schickt irgendeinen Header mit
        Umlaut. Heute stirbt daran JEDER Request am rohen TypeError."""
        data = _body_with_header("völlig-geraten")
        guard = _guard(approval_header_secret=_ASCII_SECRET)
        # Erwartet wird ein sauberer Guardrail-Block (Stufe 2 ohne Freigabe),
        # NICHT ein TypeError -- ein unkontrollierter Fehlerpfad ist kein
        # fail-closed, sondern ein opaker 500.
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await self.run_hook(data, guard)
        self.assertIn("Stufe 2", str(ctx.exception))
        self.assert_redigiert(data)

    async def test_falsches_geheimnis_mit_umlaut_wird_redigiert(self):
        """Die Grundbuch-Regel woertlich: auch ein FALSCHES Geheimnis ist ein
        Geheimnisversuch und hat im Log nichts zu suchen."""
        data = _body_with_header(_UMLAUT_SECRET)
        guard = _guard(approval_header_secret=_ASCII_SECRET)
        with self.assertRaises(dg.DatenschleuseBlocked):
            await self.run_hook(data, guard)
        self.assert_redigiert(data)
        # Und zwar wirklich der WERT, nicht nur "irgendwas anderes".
        self.assertNotIn(
            _UMLAUT_SECRET,
            repr(data["proxy_server_request"]["headers"]),
        )


class TestRedaktionUeberlebtJedeAusnahme(_Case):
    """DER Befund, Teil 2: die Redaktion darf nicht am Erfolg des Vergleichs
    haengen. Sie gehoert ins ``finally`` -- sonst haelt sie nur so lange, wie
    niemand einen neuen Fehlerpfad hinzufuegt."""

    async def test_geheimnis_wird_auch_bei_geworfenem_vergleich_redigiert(self):
        data = _body_with_header(_ASCII_SECRET)
        guard = _guard(approval_header_secret=_ASCII_SECRET)

        def _kaputter_vergleich(a, b):
            raise RuntimeError("simulierter Fehlerpfad im Vergleich")

        original = dg.hmac.compare_digest
        dg.hmac.compare_digest = _kaputter_vergleich
        try:
            with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
                await self.run_hook(data, guard)
        finally:
            dg.hmac.compare_digest = original

        # Kontrollierter Fehlerpfad statt rohem RuntimeError ...
        self.assertIn("fail-closed", str(ctx.exception))
        # ... ohne den Fehlertext des Vergleichs weiterzureichen (Gesetz 5:
        # keine fremden Werte in der Meldung, nur unsere eigenen Konstanten
        # und der Typname).
        self.assertNotIn(_ASCII_SECRET, str(ctx.exception))
        # ... und die Redaktion hat trotzdem stattgefunden.
        self.assert_redigiert(data)


class TestGeheimnisWirdBeimStartValidiert(unittest.TestCase):
    """Der Schwesterschalter zu ``configure_reid_crypto()``. Dort bricht eine
    unbrauchbare Konfiguration den START ab; hier lief sie bis zum ersten
    Request durch -- und dann in einen uncontrollierten Fehler."""

    def test_nicht_string_bricht_den_start_ab(self):
        """``.strip()`` auf einer Zahl ist ein AttributeError aus dem
        Konstruktor -- eine Fehlermeldung, die dem Betreiber nichts sagt."""
        with self.assertRaises(dg.DatenschleuseConfigError) as ctx:
            _guard(approval_header_secret=12345)
        self.assertIn(dg.APPROVAL_SECRET_ENV, str(ctx.exception))

    def test_nur_leerzeichen_bricht_den_start_ab(self):
        """Ein Geheimnis aus Leerzeichen schaltet den Header-Weg still AB.
        Der Betreiber glaubt, er habe eine Freigabe konfiguriert -- genau die
        Klasse stiller Zustand, gegen die das Grundbuch steht."""
        with self.assertRaises(dg.DatenschleuseConfigError) as ctx:
            _guard(approval_header_secret="   ")
        self.assertIn(dg.APPROVAL_SECRET_ENV, str(ctx.exception))

    def test_nicht_utf8_darstellbares_geheimnis_bricht_den_start_ab(self):
        """``os.getenv`` liefert undekodierbare Bytes als Surrogate zurueck
        (surrogateescape). Die fliegen erst beim ``.encode('utf-8')`` im
        Request auf -- also wieder mitten im Vergleich."""
        with self.assertRaises(dg.DatenschleuseConfigError) as ctx:
            _guard(approval_header_secret="geheim-\udcff-kaputt")
        self.assertIn(dg.APPROVAL_SECRET_ENV, str(ctx.exception))

    def test_leerer_wert_bleibt_die_gueltige_abschaltung(self):
        """Gegenprobe: ein leerer/ungesetzter Wert heisst weiterhin
        "Header-Weg aus" und darf NICHT abbrechen. Sonst koennte niemand die
        Guardrail ohne Header-Freigabe betreiben."""
        guard = _guard(approval_header_secret="")
        self.assertEqual(guard.approval_header_secret, "")

    def test_gueltiges_geheimnis_mit_umlaut_startet(self):
        guard = _guard(approval_header_secret=_UMLAUT_SECRET)
        self.assertEqual(guard.approval_header_secret, _UMLAUT_SECRET)


class TestGeheimnisBrauchtMindestlaenge(unittest.TestCase):
    """Der Schalter, den dieses Geheimnis bedient, schaltet den
    Stufe-2-SCHUTZ AB. Ein Geheimnis, das man raten kann, ist auf diesem
    Schalter kein Geheimnis -- und schlimmer als gar keines, weil der
    Betreiber sich darauf verlaesst.

    Die Zahl ist eine SETZUNG (von Oliver entschieden, Runde 4), aber keine
    willkuerliche: siehe APPROVAL_SECRET_MIN_LEN.

    Kein Bestandsschutz noetig -- der Header-Weg ist NEU in diesem Branch
    (er entstand als Antwort auf F2 aus Runde 1). Es kann keine Installation
    geben, die ein kurzes Geheimnis nutzt.
    """

    def test_zu_kurzes_geheimnis_bricht_den_start_ab(self):
        with self.assertRaises(dg.DatenschleuseConfigError) as ctx:
            _guard(approval_header_secret="a" * (dg.APPROVAL_SECRET_MIN_LEN - 1))
        meldung = str(ctx.exception)
        self.assertIn(dg.APPROVAL_SECRET_ENV, meldung)
        self.assertIn(str(dg.APPROVAL_SECRET_MIN_LEN), meldung)

    def test_meldung_nennt_den_erzeugungsbefehl(self):
        """Eine Fehlermeldung, die nur verbietet, laesst den Betreiber
        raten -- und er raet dann etwas, das gerade so durchkommt."""
        with self.assertRaises(dg.DatenschleuseConfigError) as ctx:
            _guard(approval_header_secret="zu-kurz")
        self.assertIn("secrets.token_urlsafe", str(ctx.exception))

    def test_meldung_nennt_das_geheimnis_nicht(self):
        """Gesetz 5: auch ein untaugliches Geheimnis ist ein Geheimnis. Es
        darf nicht ueber die Startmeldung ins Log wandern."""
        geheim = "viel-zu-kurz-x"
        with self.assertRaises(dg.DatenschleuseConfigError) as ctx:
            _guard(approval_header_secret=geheim)
        self.assertNotIn(geheim, str(ctx.exception))

    def test_erzeugtes_geheimnis_kommt_durch(self):
        """Gegenprobe an der Untergrenze: der EMPFOHLENE Befehl muss
        bequem passen, sonst ist die Grenze falsch gewaehlt."""
        import secrets
        erzeugt = secrets.token_urlsafe(32)
        self.assertGreater(len(erzeugt), dg.APPROVAL_SECRET_MIN_LEN)
        guard = _guard(approval_header_secret=erzeugt)
        self.assertEqual(guard.approval_header_secret, erzeugt)

    def test_grenze_selbst_kommt_durch(self):
        """Genau die Mindestlaenge ist gueltig -- die Grenze blockt, was
        DARUNTER liegt, nicht was auf ihr liegt."""
        auf_der_grenze = "b" * dg.APPROVAL_SECRET_MIN_LEN
        guard = _guard(approval_header_secret=auf_der_grenze)
        self.assertEqual(guard.approval_header_secret, auf_der_grenze)


if __name__ == "__main__":
    unittest.main()
