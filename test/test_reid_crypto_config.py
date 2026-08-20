"""Verankerung des Re-Id-Schluessels im BETRIEB (DATENSCHLE-69, W2/W3).

Der F4-Fix hat zwei neue Umgebungsvariablen eingefuehrt --
``DATENSCHLEUSE_REID_KEY`` und ``DATENSCHLEUSE_REID_TTL`` -- und sie nirgends
verankert. Kein Startcheck, keine Doku, kein Compose-Guard. Damit lief jedes
reale Deployment auf dem prozesslokalen Schluessel, OHNE dass das je eine
Entscheidung war.

Das Vorbild steht im selben Repo: ``QiStateStore`` bricht im Konstruktor ab,
und ``docker-compose.yml`` erzwingt ``DATENSCHLEUSE_STATE_KEY`` per
``:?``-Guard.

Zwei Fehlerbilder, die diese Datei festnagelt:

* **Ungueltiger Schluessel wirkte erst beim ERSTEN REQUEST.** Der Konstruktor
  lief sauber durch, danach warf jeder Request. Ein Konfigurationsfehler
  gehoert an den Start, wo ihn der Betreiber sieht -- nicht in den Betrieb,
  wo er als Ausfall erscheint.
* **``TTL=-1`` legte jede Re-Identifikation STILL lahm.** Der Parser fiel bei
  Unsinn auf die Vorgabe zurueck, akzeptierte aber negative Werte -- und
  jedes Siegel galt sofort als abgelaufen. Jede Antwort behielt ihre
  Platzhalter, ohne eine einzige Meldung.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.
"""

import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, os.pardir, "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


def _gueltiger_key():
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


class _Basis(unittest.TestCase):
    def setUp(self):
        # Jeder Test hinterlaesst eine frische Krypto-Konfiguration, sonst
        # verfaelscht der prozessweite Cache die folgenden.
        self.addCleanup(dg.configure_reid_crypto)


class TestSchluesselWirdAmStartGeprueft(_Basis):
    """Ein Konfigurationsfehler gehoert an den Start."""

    def test_ungueltiger_schluessel_scheitert_beim_start(self):
        """DER Befund W3: vorher lief der Konstruktor durch."""
        with mock.patch.dict(os.environ, {dg.REID_KEY_ENV: "kein-fernet-key"}):
            with self.assertRaises(dg.DatenschleuseConfigError) as ctx:
                dg.DatenschleuseGuardrail()
        self.assertIn(dg.REID_KEY_ENV, str(ctx.exception))

    def test_gueltiger_schluessel_wird_benutzt(self):
        key = _gueltiger_key()
        with mock.patch.dict(os.environ, {dg.REID_KEY_ENV: key}):
            dg.DatenschleuseGuardrail()
            token = dg.seal_reid_map({"<PERSON_0>": "Hans Mueller"})
            self.assertEqual(
                dg.open_reid_map(token), {"<PERSON_0>": "Hans Mueller"}
            )
            # Gegenprobe: mit GENAU diesem Schluessel lesbar -- also wirklich
            # der konfigurierte und nicht ein erzeugter.
            from cryptography.fernet import Fernet

            roh = Fernet(key.encode()).decrypt(token.encode())
            self.assertIn(b"Hans Mueller", roh)

    def test_ohne_schluessel_laeuft_es_weiter(self):
        """Der prozesslokale Schluessel bleibt die bewusste Vorgabe.

        Kein fail-closed: das Mapping ist request-gebunden und muss keinen
        Neustart ueberleben. Es darf nur kein UNBEMERKTER Zustand sein.
        """
        umgebung = {k: v for k, v in os.environ.items() if k != dg.REID_KEY_ENV}
        with mock.patch.dict(os.environ, umgebung, clear=True):
            dg.DatenschleuseGuardrail()
            token = dg.seal_reid_map({"<PERSON_0>": "Hans"})
            self.assertEqual(dg.open_reid_map(token), {"<PERSON_0>": "Hans"})

    def test_ohne_schluessel_wird_der_betreiber_informiert(self):
        """Ein prozesslokaler Schluessel ist eine Betriebsentscheidung mit
        Folgen: ein Neustart entwertet offene Mappings, mehrere Worker teilen
        keinen Schluessel. Beides faellt sonst erst im Betrieb auf, als
        scheinbar zufaelliges Fehlschlagen der Re-Identifikation."""
        umgebung = {k: v for k, v in os.environ.items() if k != dg.REID_KEY_ENV}
        with mock.patch.dict(os.environ, umgebung, clear=True):
            with self.assertLogs(dg._LOG, level="WARNING") as protokoll:
                dg.configure_reid_crypto()
            self.assertTrue(
                any(dg.REID_KEY_ENV in z for z in protokoll.output),
                f"Warnung nennt die Variable nicht: {protokoll.output}",
            )


class TestTtlWirdGeprueft(_Basis):
    """``TTL=-1`` darf nicht still jede Re-Identifikation abschalten."""

    def test_negative_ttl_scheitert_beim_start(self):
        """DER zweite Befund: vorher lief es durch und lieferte immer {}."""
        with mock.patch.dict(os.environ, {dg.REID_TTL_ENV: "-1"}):
            with self.assertRaises(dg.DatenschleuseConfigError) as ctx:
                dg.DatenschleuseGuardrail()
        self.assertIn(dg.REID_TTL_ENV, str(ctx.exception))

    def test_ttl_null_scheitert_beim_start(self):
        """0 ist kein gueltiger Wert -- und wirkt bei Fernet ausserdem NICHT
        wie 'sofort abgelaufen' (der Vergleich ist ``zeitstempel + ttl <
        jetzt``). Wer 0 setzt, meint etwas anderes als das, was passiert.
        Also blocken statt raten."""
        with mock.patch.dict(os.environ, {dg.REID_TTL_ENV: "0"}):
            with self.assertRaises(dg.DatenschleuseConfigError):
                dg.DatenschleuseGuardrail()

    def test_unlesbare_ttl_scheitert_beim_start(self):
        """Frueher: stiller Rueckfall auf die Vorgabe. Ein Tippfehler in der
        Betreiber-Konfiguration darf nicht unbemerkt etwas anderes tun."""
        with mock.patch.dict(os.environ, {dg.REID_TTL_ENV: "eine Stunde"}):
            with self.assertRaises(dg.DatenschleuseConfigError):
                dg.DatenschleuseGuardrail()

    def test_gueltige_ttl_wird_uebernommen(self):
        with mock.patch.dict(os.environ, {dg.REID_TTL_ENV: "900"}):
            dg.DatenschleuseGuardrail()
            self.assertEqual(dg._reid_ttl_seconds(), 900)

    def test_vorgabe_ohne_gesetzte_variable(self):
        umgebung = {k: v for k, v in os.environ.items() if k != dg.REID_TTL_ENV}
        with mock.patch.dict(os.environ, umgebung, clear=True):
            dg.DatenschleuseGuardrail()
            self.assertEqual(dg._reid_ttl_seconds(), dg.DEFAULT_REID_TTL_SECONDS)


if __name__ == "__main__":
    unittest.main()
