"""``MESSAGE_FIELDS_MASKED`` treibt die Schleifen wirklich (F9).

Der Befund (Runde 4, F9, LOW -- aber dritte Wiederholung derselben Bauart)
--------------------------------------------------------------------------
Das Register ``MESSAGE_FIELDS_MASKED`` sah aus wie die Quelle der Wahrheit,
war es aber nicht. Maskiert und validiert wurde gegen HANDGEPFLEGTE Tupel::

    for field in ("name", "refusal", "reasoning_content"):   # _mask_message_fields
    for field in ("name", "refusal", "reasoning_content"):   # _validate_message_shape

(und seit F3 ein drittes Mal im Aufruf-Zaehler.)

Wer kuenftig ein Feld ins Register eintraegt, OEFFNET es damit zum Passieren
-- ``ALLOWED_MESSAGE_FIELDS`` leitet sich vom Register ab, der Formpruefer
laesst es also durch -- ohne dass es je MASKIERT wird. Ein neues Feld
einzutragen macht die Guardrail an dieser Stelle also unsicherer, nicht
sicherer. Genau die Falle, die ein Register verhindern soll.

Dieselbe Bauart wie F1 (zweite Referenz), F3 (zweite Zaehlung) und die
Doku-Namen aus F8: zwei Beschreibungen derselben Sache, die auseinanderlaufen.

Die Entscheidung
----------------
Die Freitextfelder werden ABGELEITET, nicht aufgezaehlt. Wer etwas ins
Register eintraegt, bekommt Maskierung, Validierung und Kostenzaehlung
automatisch -- oder eine Import-Zeit-Zusicherung um die Ohren.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.
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


class TestFreitextfelderSindAbgeleitet(unittest.TestCase):
    """Die Konstante muss aus dem Register kommen, nicht daneben stehen."""

    def test_konstante_existiert(self):
        self.assertTrue(hasattr(dg, "MESSAGE_FIELDS_PLAIN_TEXT"))

    def test_jedes_freitextfeld_steht_im_register(self):
        for feld in dg.MESSAGE_FIELDS_PLAIN_TEXT:
            with self.subTest(feld=feld):
                self.assertIn(feld, dg.MESSAGE_FIELDS_MASKED)

    def test_register_minus_eigene_pfade_ist_genau_die_freitextliste(self):
        """DIE Kopplung. Kein Feld darf zwischen Register und Maskierung
        verloren gehen -- ein verlorenes Feld passiert ungemaskt."""
        erwartet = tuple(
            f for f in dg.MESSAGE_FIELDS_MASKED
            if f not in dg.MESSAGE_FIELDS_OWN_PATH
        )
        self.assertEqual(dg.MESSAGE_FIELDS_PLAIN_TEXT, erwartet)

    def test_eigene_pfade_stehen_ebenfalls_im_register(self):
        for feld in dg.MESSAGE_FIELDS_OWN_PATH:
            with self.subTest(feld=feld):
                self.assertIn(feld, dg.MESSAGE_FIELDS_MASKED)

    def test_jedes_registerfeld_ist_genau_einmal_zugeordnet(self):
        """Kein Feld darf in beiden Mengen stehen und keines in keiner --
        sonst ist wieder offen, wer es behandelt."""
        plain = set(dg.MESSAGE_FIELDS_PLAIN_TEXT)
        eigen = set(dg.MESSAGE_FIELDS_OWN_PATH)
        self.assertEqual(plain & eigen, set(), "Feld in beiden Mengen")
        self.assertEqual(
            plain | eigen, set(dg.MESSAGE_FIELDS_MASKED),
            "Ein Registerfeld ist keinem Pfad zugeordnet -- es wird nicht "
            "maskiert, passiert aber die Formpruefung.",
        )


class TestNeuesFeldWirdWirklichMaskiert(unittest.IsolatedAsyncioTestCase):
    """Der Beweis am lebenden Objekt: ein Feld ins Register eintragen muss
    reichen. Ohne diesen Test bliebe die Ableitung eine Behauptung."""

    async def test_zusaetzliches_registerfeld_laeuft_durch_den_masker(self):
        neu = "annotation_text"
        alt_masked = dg.MESSAGE_FIELDS_MASKED
        alt_plain = dg.MESSAGE_FIELDS_PLAIN_TEXT
        alt_allowed = dg.ALLOWED_MESSAGE_FIELDS
        try:
            dg.MESSAGE_FIELDS_MASKED = alt_masked + (neu,)
            dg.MESSAGE_FIELDS_PLAIN_TEXT = tuple(
                f for f in dg.MESSAGE_FIELDS_MASKED
                if f not in dg.MESSAGE_FIELDS_OWN_PATH
            )
            dg.ALLOWED_MESSAGE_FIELDS = frozenset(
                dg.MESSAGE_FIELDS_MASKED + dg.MESSAGE_FIELDS_VALIDATED
            )

            guard = _guard()
            gesehen = []

            async def _fake(text):
                gesehen.append(text)
                return []

            guard._analyze = _fake
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None,
                data={
                    "model": "gpt-4o",
                    "messages": [
                        {"role": "user", "content": "Hi", neu: "Max Mustermann"}
                    ],
                },
                call_type="acompletion",
            )
            self.assertIn(
                "Max Mustermann", gesehen,
                "Das neue Registerfeld wurde nie an den Analyzer gegeben -- "
                "es passiert die Formpruefung, wird aber nicht maskiert.",
            )
        finally:
            dg.MESSAGE_FIELDS_MASKED = alt_masked
            dg.MESSAGE_FIELDS_PLAIN_TEXT = alt_plain
            dg.ALLOWED_MESSAGE_FIELDS = alt_allowed


if __name__ == "__main__":
    unittest.main()
