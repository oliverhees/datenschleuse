"""``configure_reid_crypto()`` re-keyt bei jeder Instanziierung (F6).

Der Befund (Runde 4, F6, MEDIUM)
--------------------------------
``configure_reid_crypto()`` setzt ``_REID_FERNET`` BEDINGUNGSLOS -- auch im
``else``-Zweig, in dem ohne gesetzten ``DATENSCHLEUSE_REID_KEY`` ein
prozesslokaler Schluessel erzeugt wird. Die Funktion laeuft im KONSTRUKTOR.

Folge: jede weitere Instanziierung der Guardrail wirft den bisherigen
Schluessel weg. Gemessen: nach der zweiten Instanz oeffnet ein Siegel, das
die erste ausgestellt hat, nicht mehr -- und zwar OHNE jede Meldung.

Warum das im Betrieb weh tut: das Re-Id-Mapping reist versiegelt im Request
und wird im post_call wieder geoeffnet. Wird zwischen pre_call und post_call
eine zweite Guardrail gebaut (Reload der Config, ein zweiter Guardrail-
Eintrag, ein Health-Check-Pfad), schlaegt die Re-Identifikation fehl. Der
Nutzer bekommt Platzhalter statt Klartext -- und niemand sieht einen Fehler,
weil keiner geloggt wird.

Die Entscheidung
----------------
Idempotenz: ein einmal erzeugter Prozess-Schluessel bleibt. Nur ein
ausdrueckliches ``force=True`` erzeugt neu -- fuer Tests, die eine frische
Krypto-Umgebung brauchen. Ein gesetzter ``DATENSCHLEUSE_REID_KEY`` wird
weiterhin bei jedem Aufruf uebernommen: dort ist die Quelle der Wahrheit die
Umgebung, nicht der Prozesszustand, und ein geaenderter Key SOLL wirken.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest discover -s test \
        -p "test_reid_key_idempotenz.py" -v
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


def _guard(**kwargs):
    kwargs.setdefault("presidio_analyzer_url", "http://presidio.invalid")
    kwargs.setdefault("language", "de")
    kwargs.setdefault("image_policy", "pass")
    return dg.DatenschleuseGuardrail(**kwargs)


class _OhneReidKey:
    """Stellt sicher, dass der ENV-Schluessel NICHT gesetzt ist -- nur dann
    greift der prozesslokale Zweig, um den es hier geht."""

    def __enter__(self):
        self._alt = os.environ.pop(dg.REID_KEY_ENV, None)
        return self

    def __exit__(self, *exc):
        if self._alt is not None:
            os.environ[dg.REID_KEY_ENV] = self._alt


class TestProzessschluesselUeberlebtWeitereInstanzen(unittest.TestCase):
    """DER Befund."""

    def test_siegel_der_ersten_instanz_oeffnet_nach_der_zweiten_noch(self):
        with _OhneReidKey():
            dg.configure_reid_crypto(force=True)
            _guard()
            siegel = dg.seal_reid_map({"<PERSON_0>": "Max Mustermann"})

            # Die zweite Instanz darf den Schluessel NICHT wegwerfen.
            _guard()

            wieder = dg.open_reid_map(siegel)
            self.assertEqual(
                wieder, {"<PERSON_0>": "Max Mustermann"},
                "Die zweite Instanz hat re-keyt -- ein Siegel der ersten "
                "oeffnet nicht mehr. Im Betrieb: Platzhalter statt Klartext, "
                "ohne jede Fehlermeldung.",
            )

    def test_auch_ueber_mehrere_instanzen(self):
        with _OhneReidKey():
            dg.configure_reid_crypto(force=True)
            siegel = dg.seal_reid_map({"<IBAN_0>": "DE02120300000000202051"})
            for _ in range(5):
                _guard()
            self.assertEqual(
                dg.open_reid_map(siegel),
                {"<IBAN_0>": "DE02120300000000202051"},
            )


class TestForcePfad(unittest.TestCase):
    """Der ausdrueckliche Weg zu einer frischen Krypto-Umgebung -- fuer
    Tests. Ohne ihn koennte man den Prozess-Schluessel nie zuruecksetzen."""

    def test_force_erzeugt_einen_neuen_schluessel(self):
        with _OhneReidKey():
            dg.configure_reid_crypto(force=True)
            siegel = dg.seal_reid_map({"<PERSON_0>": "Erika Mustermann"})
            dg.configure_reid_crypto(force=True)
            # open_reid_map wirft NICHT -- es gibt im Zweifel ein leeres
            # Mapping zurueck (sichere Fehlerrichtung). Genau diese Stille
            # ist der Grund fuer die Warnung, die dieser Commit ergaenzt.
            self.assertEqual(dg.open_reid_map(siegel), {})

    def test_ohne_force_bleibt_es_beim_alten(self):
        with _OhneReidKey():
            dg.configure_reid_crypto(force=True)
            siegel = dg.seal_reid_map({"<PERSON_0>": "Erika Mustermann"})
            dg.configure_reid_crypto()
            dg.configure_reid_crypto()
            self.assertEqual(
                dg.open_reid_map(siegel),
                {"<PERSON_0>": "Erika Mustermann"},
            )


class TestGesetzterEnvKeyWirktWeiterhin(unittest.TestCase):
    """Gegenprobe -- die Idempotenz darf den konfigurierten Schluessel nicht
    aussperren. Dort ist die Umgebung die Quelle der Wahrheit, nicht der
    Prozesszustand: ein geaenderter Key SOLL wirken."""

    def test_env_key_wird_uebernommen(self):
        from cryptography.fernet import Fernet

        alt = os.environ.get(dg.REID_KEY_ENV)
        key = Fernet.generate_key().decode()
        os.environ[dg.REID_KEY_ENV] = key
        try:
            dg.configure_reid_crypto()
            siegel = dg.seal_reid_map({"<PERSON_0>": "Max Mustermann"})
            # Fremder Prozess, gleicher Schluessel -> muss oeffnen.
            dg.configure_reid_crypto()
            self.assertEqual(
                dg.open_reid_map(siegel),
                {"<PERSON_0>": "Max Mustermann"},
            )
        finally:
            if alt is None:
                os.environ.pop(dg.REID_KEY_ENV, None)
            else:
                os.environ[dg.REID_KEY_ENV] = alt
            dg.configure_reid_crypto(force=True)


if __name__ == "__main__":
    unittest.main()
