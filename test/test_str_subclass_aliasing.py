"""Str-Subklassen duerfen sich nirgends als bekannter Schluessel tarnen.

Hintergrund (DATENSCHLE-65, dritte QA-Runde): ``x in frozenset`` prueft ueber
``__hash__``/``__eq__`` -- formatiert, geloggt bzw. weiterverarbeitet wird
aber die INSTANZ. Eine ``str``-Subklasse mit ueberschriebenem
``__hash__``/``__eq__`` tarnt sich damit als bekannter Schluessel und schleust
ihren eigenen Inhalt durch.

``ef29bf8`` hat das an zwei WERT-Stellen geschlossen (Part-Typ, Zitat-Typ).
Baugleich offen blieben:

  * die drei Stellen mit dict-SCHLUESSELN gegen die
    ``KNOWN_UNSUPPORTED_*``-Register -- dort landet die Nutzlast wortwoertlich
    in der Blockmeldung UND in ``_LOG.warning`` (die in derselben Zeile
    behauptet, keine Werte zu loggen),
  * saemtliche ALLOWLIST-Vergleiche: eine Tarnung als ERLAUBTER Wert
    passiert die Allowlist komplett unblockiert und wird als der getarnte
    Wert weiterverarbeitet -- fail-closed ist damit ausgehebelt.

Diese Datei prueft beide Klassen von Stellen systematisch und haelt
zusaetzlich die Verhaltens-Neutralitaet fuer echte ``str`` fest.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest discover -s test
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


# Die Nutzlast ist bewusst lang (~3700 Zeichen) und traegt mehrere eindeutige
# Marker: eine Meldung, die sie durchreicht, faellt in JEDER Assertion auf.
_PII_MARKER = "PII-LEAK"
_PII_IBAN = "DE02120300000000202051"
_PII = (
    f"{_PII_MARKER}:Maximilian Mustermann, IBAN {_PII_IBAN}, "
    f"Diagnose F32.1, " + "X" * 3700
)

_LOGGER = "datenschleuse"


def _alias(tarnung, nutzlast=_PII):
    """Eine ``str``-Subklasse, die sich als ``tarnung`` hasht und vergleicht,
    inhaltlich aber ``nutzlast`` ist -- exakt der PoC des Pruefers."""

    class _Alias(str):
        def __new__(cls, wert):
            return str.__new__(cls, wert)

        def __hash__(self):
            return hash(tarnung)

        def __eq__(self, other):
            return other == tarnung

    boese = _Alias(nutzlast)
    # Vorbedingung: die Tarnung greift wirklich. Ohne diese Zusicherung
    # koennte der Test gruen werden, weil die Aliasierung gar nicht wirkt.
    assert boese == tarnung
    assert hash(boese) == hash(tarnung)
    assert str.__str__(boese) == nutzlast
    return boese


def _guard():
    return dg.DatenschleuseGuardrail(image_policy="block")


class _AliasAssertions(unittest.TestCase):
    """Gemeinsame Zusicherungen fuer alle Tarn-Faelle."""

    def assertKeinLeck(self, text, wo):
        self.assertNotIn(_PII_MARKER, text, f"Nutzlast in {wo}")
        self.assertNotIn(_PII_IBAN, text, f"IBAN in {wo}")
        self.assertNotIn("Mustermann", text, f"Klarname in {wo}")
        self.assertNotIn("X" * 100, text, f"Fuellzeichen in {wo}")

    def assertBlocktOhneLeck(self, aufruf, wo):
        """Der Aufruf muss blocken, und weder Exception noch Log duerfen die
        Nutzlast tragen. Beides zusammen, weil das Log-Leck eigenstaendig ist:
        es besteht unabhaengig davon, was LiteLLM mit der Exception macht."""
        with self.assertLogs(_LOGGER, level="WARNING") as protokoll:
            with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
                aufruf()
            # Ohne mindestens einen Log-Satz waere ``assertLogs`` selbst der
            # Fehlschlag -- dieser Marker haelt den Kontext gueltig, falls die
            # gepruefte Stelle kuenftig gar nicht mehr loggt.
            dg._LOG.warning("datenschleuse-test-marker")
        # Das LOG zuerst: es ist der eigenstaendige Befund. Stuende die
        # Exception-Pruefung davor, wuerde sie bei einem Rueckfall zuerst
        # schlagen und das Log-Leck im Fehlerbericht verdecken -- gegen den
        # pre-Fix-Stand empirisch nachgestellt.
        for satz in protokoll.output:
            self.assertKeinLeck(satz, f"Log ({wo})")
            self.assertLess(len(satz), 800, f"Log-Satz aufgeblaeht ({wo})")
        meldung = str(ctx.exception)
        self.assertKeinLeck(meldung, f"Blockmeldung ({wo})")
        self.assertLess(len(meldung), 800, f"Meldung aufgeblaeht ({wo})")
        return meldung

    def assertBlockt(self, aufruf, wo):
        """Nur fail-closed, ohne Log-Zusicherung -- fuer Stellen, die nicht
        loggen. Die Nutzlast darf trotzdem nicht in der Meldung stehen."""
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            aufruf()
        meldung = str(ctx.exception)
        self.assertKeinLeck(meldung, f"Blockmeldung ({wo})")
        self.assertLess(len(meldung), 800, f"Meldung aufgeblaeht ({wo})")
        return meldung


# ===========================================================================
# 1) SCHLUESSEL gegen die KNOWN_UNSUPPORTED_*-Register (der benennende Zweig)
# ===========================================================================
class TestBenennenderZweigSchluessel(_AliasAssertions):
    """Die drei offenen Stellen aus dem Befund. Getarnter Schluessel ->
    generischer Block-Zweig, nicht benannt, nicht geloggt."""

    def test_message_field_key_alias(self):
        boese = _alias("provider_specific_fields")
        self.assertIn(boese, dg.KNOWN_UNSUPPORTED_MESSAGE_FIELDS)
        msg = {"role": "user", "content": "hallo"}
        msg[boese] = "irgendwas"
        meldung = self.assertBlocktOhneLeck(
            lambda: dg.DatenschleuseGuardrail._validate_message_shape(msg),
            "_validate_message_shape",
        )
        self.assertNotIn("bekannt, aber nicht im Register", meldung)
        self.assertIn("Fingerprint", meldung)

    def test_part_field_key_alias(self):
        boese = _alias("thinking")
        self.assertIn(boese, dg.KNOWN_UNSUPPORTED_PART_FIELDS)
        part = {"type": "text", "text": "hallo"}
        part[boese] = "irgendwas"
        meldung = self.assertBlocktOhneLeck(
            lambda: dg.DatenschleuseGuardrail._validate_part_shape(part),
            "_validate_part_shape (Felder)",
        )
        self.assertNotIn("bekannt, aber nicht im Register", meldung)
        self.assertIn("Fingerprint", meldung)

    def test_citation_field_key_alias(self):
        boese = _alias("file_id")
        self.assertIn(boese, dg.KNOWN_UNSUPPORTED_CITATION_FIELDS)
        zitat = {"type": "char_location", "cited_text": "hallo"}
        zitat[boese] = "irgendwas"
        meldung = self.assertBlocktOhneLeck(
            lambda: dg.DatenschleuseGuardrail._validate_citations([zitat]),
            "_validate_citations (Felder)",
        )
        self.assertNotIn("bekannt, aber nicht im Register", meldung)
        self.assertIn("Fingerprint", meldung)


# ===========================================================================
# 2) WERTE gegen Allowlists -- Tarnung als ERLAUBTER Wert
# ===========================================================================
class TestAllowlistWerte(_AliasAssertions):
    """Die fuenfte Variante (MEDIUM) und ihre Geschwister: wer sich als
    erlaubter Wert tarnt, passiert die Allowlist bisher voellig unblockiert."""

    def test_citation_type_alias_als_erlaubter_typ(self):
        boese = _alias("char_location")
        self.assertIn(boese, dg.ALLOWED_CITATION_TYPES)
        zitat = {"type": boese, "cited_text": "hallo"}
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_citations([zitat]),
            "citation_type in ALLOWED_CITATION_TYPES",
        )

    def test_part_type_alias_als_erlaubter_typ(self):
        boese = _alias("text")
        self.assertIn(boese, dg.ALLOWED_PART_TYPES)
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_part_shape(
                {"type": boese, "text": "hallo"}
            ),
            "part_type in ALLOWED_PART_TYPES",
        )

    def test_role_alias_als_erlaubte_rolle(self):
        boese = _alias("user")
        self.assertIn(boese, dg.ALLOWED_ROLES)
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_message_shape(
                {"role": boese, "content": "hallo"}
            ),
            "role in ALLOWED_ROLES",
        )

    def test_tool_call_type_alias_als_erlaubter_typ(self):
        boese = _alias("function")
        self.assertIn(boese, dg.ALLOWED_TOOL_CALL_TYPES)
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_tool_call(
                {"id": "call_1", "type": boese}
            ),
            "call_type in ALLOWED_TOOL_CALL_TYPES",
        )

    def test_image_url_detail_alias_als_erlaubter_wert(self):
        boese = _alias("auto")
        self.assertIn(boese, dg.IMAGE_URL_DETAILS)
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_image_url_container(
                {"url": "https://example.org/b.png", "detail": boese}
            ),
            "detail in IMAGE_URL_DETAILS",
        )

    def test_cache_control_type_alias_als_erlaubter_marker(self):
        boese = _alias("ephemeral")
        self.assertIn(boese, dg.CACHE_CONTROL_TYPES)
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_cache_control(
                {"type": boese}
            ),
            "marker in CACHE_CONTROL_TYPES",
        )

    def test_cache_control_ttl_alias_als_erlaubter_wert(self):
        boese = _alias("5m")
        self.assertIn(boese, dg.CACHE_CONTROL_TTLS)
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_cache_control(
                {"type": "ephemeral", "ttl": boese}
            ),
            "ttl in CACHE_CONTROL_TTLS",
        )


# ===========================================================================
# 3) SCHLUESSEL gegen Allowlists -- der getarnte Schluessel ginge sonst
#    ungeprueft mitsamt seinem Inhalt ans Zielmodell raus.
# ===========================================================================
class TestAllowlistSchluessel(_AliasAssertions):

    def test_message_key_alias_als_erlaubtes_feld(self):
        boese = _alias("content")
        self.assertIn(boese, dg.ALLOWED_MESSAGE_FIELDS)
        msg = {"role": "user"}
        msg[boese] = "hallo"
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_message_shape(msg),
            "msg-Key in ALLOWED_MESSAGE_FIELDS",
        )

    def test_part_key_alias_als_erlaubtes_feld(self):
        boese = _alias("citations")
        self.assertIn(boese, dg.ALLOWED_PART_FIELDS["text"])
        part = {"type": "text", "text": "hallo"}
        part[boese] = []
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_part_shape(part),
            "part-Key in ALLOWED_PART_FIELDS",
        )

    def test_citation_key_alias_als_erlaubtes_feld(self):
        boese = _alias("cited_text")
        self.assertIn(boese, dg.ALLOWED_CITATION_FIELDS["char_location"])
        zitat = {"type": "char_location"}
        zitat[boese] = "hallo"
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_citations([zitat]),
            "citation-Key in ALLOWED_CITATION_FIELDS",
        )

    def test_image_url_key_alias_als_erlaubtes_feld(self):
        boese = _alias("detail")
        self.assertIn(boese, dg.IMAGE_URL_ALLOWED_FIELDS)
        container = {"url": "https://example.org/b.png"}
        container[boese] = "auto"
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_image_url_container(
                container
            ),
            "image_url-Key in IMAGE_URL_ALLOWED_FIELDS",
        )

    def test_cache_control_key_alias_als_erlaubtes_feld(self):
        boese = _alias("ttl")
        self.assertIn(boese, dg.CACHE_CONTROL_ALLOWED_FIELDS)
        marker = {"type": "ephemeral"}
        marker[boese] = "5m"
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_cache_control(marker),
            "cache_control-Key in CACHE_CONTROL_ALLOWED_FIELDS",
        )

    def test_tool_call_key_alias_als_erlaubtes_feld(self):
        boese = _alias("index")
        self.assertIn(boese, dg.TOOL_CALL_ALLOWED_FIELDS)
        call = {"id": "call_1", "type": "function"}
        call[boese] = 0
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_tool_call(call),
            "tool_call-Key in TOOL_CALL_ALLOWED_FIELDS",
        )

    def test_function_key_alias_als_erlaubtes_feld(self):
        boese = _alias("arguments")
        self.assertIn(boese, dg.TOOL_CALL_FUNCTION_ALLOWED_FIELDS)
        function = {"name": "f"}
        function[boese] = "{}"
        self.assertBlockt(
            lambda: dg.DatenschleuseGuardrail._validate_function_payload(
                function, "tool_calls[].function"
            ),
            "function-Key in TOOL_CALL_FUNCTION_ALLOWED_FIELDS",
        )


# ===========================================================================
# 4) Erreichbarkeit ueber den echten Einstiegspunkt
# ===========================================================================
class TestUeberDenEinstiegspunkt(
    _AliasAssertions, unittest.IsolatedAsyncioTestCase
):
    """Nicht nur die Statics: derselbe Weg durch ``async_pre_call_hook``.
    Ueber HTTP liefert ``json.loads`` exakte ``str`` -- fuer In-Process-
    Aufrufer und normalisierende Zwischenschichten aber sehr wohl erreichbar."""

    async def test_pre_call_hook_blockt_getarnten_part_typ(self):
        boese = _alias("text")
        data = {
            "messages": [
                {"role": "user", "content": [{"type": boese, "text": "hallo"}]}
            ]
        }
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _guard().async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data,
                call_type="completion",
            )
        meldung = str(ctx.exception)
        self.assertKeinLeck(meldung, "async_pre_call_hook")
        # Der Block muss aus der FORMPRUEFUNG kommen, nicht aus einem
        # Folgefehler: ohne erreichbaren Presidio-Container blockt dieser
        # Aufruf sonst auch, und der Test waere aus dem falschen Grund gruen.
        self.assertIn("Content-Part", meldung)
        self.assertNotIn("Presidio", meldung)


# ===========================================================================
# 5) VERHALTENS-NEUTRALITAET: echte str verhalten sich exakt wie bisher
# ===========================================================================
class TestVerhaltensNeutralitaet(_AliasAssertions):
    """Ein Fix, der legitime Anfragen blockt, waere die naechste Regression.
    Deshalb festgehalten: echtes ``str`` -> unveraendertes Verhalten."""

    def test_bekanntes_message_feld_wird_weiterhin_benannt(self):
        msg = {"role": "user", "content": "hallo", "provider_specific_fields": {}}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            dg.DatenschleuseGuardrail._validate_message_shape(msg)
        self.assertIn("provider_specific_fields", str(ctx.exception))
        self.assertIn("bekannt, aber nicht im Register", str(ctx.exception))

    def test_bekanntes_part_feld_wird_weiterhin_benannt(self):
        part = {"type": "text", "text": "hallo", "thinking": "..."}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            dg.DatenschleuseGuardrail._validate_part_shape(part)
        self.assertIn("thinking", str(ctx.exception))
        self.assertIn("bekannt, aber nicht im Register", str(ctx.exception))

    def test_bekanntes_zitat_feld_wird_weiterhin_benannt(self):
        zitat = {"type": "char_location", "cited_text": "hallo", "file_id": "f"}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            dg.DatenschleuseGuardrail._validate_citations([zitat])
        self.assertIn("file_id", str(ctx.exception))
        self.assertIn("bekannt, aber nicht im Register", str(ctx.exception))

    def test_unbekanntes_feld_bleibt_generisch(self):
        msg = {"role": "user", "content": "hallo", "voellig_neu": 1}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            dg.DatenschleuseGuardrail._validate_message_shape(msg)
        self.assertNotIn("voellig_neu", str(ctx.exception))
        self.assertIn("Fingerprint", str(ctx.exception))

    def test_bekannter_part_typ_wird_weiterhin_benannt(self):
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            dg.DatenschleuseGuardrail._validate_part_shape(
                {"type": "server_tool_use"}
            )
        self.assertIn("server_tool_use", str(ctx.exception))

    def test_bekannter_zitat_typ_wird_weiterhin_benannt(self):
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            dg.DatenschleuseGuardrail._validate_citations(
                [{"type": "web_search_result_location"}]
            )
        self.assertIn("web_search_result_location", str(ctx.exception))

    def test_erlaubte_werte_bleiben_erlaubt(self):
        G = dg.DatenschleuseGuardrail
        for rolle in sorted(dg.ALLOWED_ROLES):
            G._validate_message_shape({"role": rolle, "content": "hallo"})
        self.assertEqual(
            G._validate_part_shape({"type": "text", "text": "hallo"}), "text"
        )
        self.assertEqual(
            G._validate_part_shape(
                {"type": "image_url",
                 "image_url": {"url": "https://example.org/b.png"}}
            ),
            "image_url",
        )
        for detail in sorted(dg.IMAGE_URL_DETAILS):
            G._validate_image_url_container(
                {"url": "https://example.org/b.png", "detail": detail}
            )
        G._validate_cache_control({"type": "ephemeral"})
        for ttl in sorted(dg.CACHE_CONTROL_TTLS):
            G._validate_cache_control({"type": "ephemeral", "ttl": ttl})
        G._validate_tool_call(
            {"id": "call_1", "type": "function", "index": 0,
             "function": {"name": "f", "arguments": "{}"}}
        )
        G._validate_function_payload(
            {"name": "f", "arguments": "{}"}, "tool_calls[].function"
        )
        G._validate_citations([
            {"type": "char_location", "cited_text": "x", "document_title": "t",
             "document_index": 0, "start_char_index": 0, "end_char_index": 1},
            {"type": "page_location", "cited_text": "x",
             "document_index": 0, "start_page_number": 1, "end_page_number": 2},
            {"type": "content_block_location", "cited_text": "x",
             "document_index": 0, "start_block_index": 0, "end_block_index": 1},
        ])

    def test_nicht_str_typen_blocken_unveraendert(self):
        """Der Helfer darf die bestehende Nicht-String-Abwehr nicht
        verschieben: int/None/dict blocken vorher wie nachher."""
        G = dg.DatenschleuseGuardrail
        for wert in (1, None, {}, [], True):
            with self.assertRaises(dg.DatenschleuseBlocked):
                G._validate_part_shape({"type": wert})
            with self.assertRaises(dg.DatenschleuseBlocked):
                G._validate_citations([{"type": wert}])
        for wert in (1, {}, []):
            with self.assertRaises(dg.DatenschleuseBlocked):
                G._validate_message_shape({"role": wert, "content": "hallo"})
            with self.assertRaises(dg.DatenschleuseBlocked):
                G._validate_cache_control({"type": wert})
            with self.assertRaises(dg.DatenschleuseBlocked):
                G._validate_image_url_container(
                    {"url": "https://example.org/b.png", "detail": wert}
                )
            with self.assertRaises(dg.DatenschleuseBlocked):
                G._validate_tool_call({"id": "call_1", "type": wert})
        # ``role``/``ttl``/``type`` duerfen weiterhin ganz fehlen bzw. None sein.
        G._validate_message_shape({"content": "hallo"})
        G._validate_cache_control(None)
        G._validate_cache_control({"type": "ephemeral", "ttl": None})
        G._validate_tool_call({"id": "call_1"})


# ===========================================================================
# 6) AEQUIVALENZBEWEIS: die Pruefhilfe ist fuer echte str deckungsgleich
#    mit dem alten ``x in register`` -- ueber ALLE Register des Moduls.
# ===========================================================================
class TestAequivalenzUeberAlleRegister(unittest.TestCase):
    """Die Verhaltens-Neutralitaet wird nicht behauptet, sondern erschoepfend
    nachgerechnet: fuer jedes exakte ``str`` und jedes Register des Moduls
    muss ``_ist_registriert(x, R)`` genau dasselbe liefern wie ``x in R``.

    Damit haengt die Neutralitaet nicht daran, dass jemand alle 19
    Aufrufstellen einzeln richtig umgestellt hat -- sie folgt aus der
    Eigenschaft der Hilfe selbst. Und ein kuenftiges Register faellt
    automatisch unter denselben Beweis, sobald es hier eingetragen wird.
    """

    def _register(self):
        reg = {
            "ALLOWED_MESSAGE_FIELDS": dg.ALLOWED_MESSAGE_FIELDS,
            "ALLOWED_ROLES": dg.ALLOWED_ROLES,
            "KNOWN_UNSUPPORTED_MESSAGE_FIELDS": dg.KNOWN_UNSUPPORTED_MESSAGE_FIELDS,
            "ALLOWED_PART_TYPES": dg.ALLOWED_PART_TYPES,
            "KNOWN_UNSUPPORTED_PART_TYPES": dg.KNOWN_UNSUPPORTED_PART_TYPES,
            "KNOWN_UNSUPPORTED_PART_FIELDS": dg.KNOWN_UNSUPPORTED_PART_FIELDS,
            "IMAGE_URL_ALLOWED_FIELDS": dg.IMAGE_URL_ALLOWED_FIELDS,
            "IMAGE_URL_DETAILS": dg.IMAGE_URL_DETAILS,
            "CACHE_CONTROL_ALLOWED_FIELDS": dg.CACHE_CONTROL_ALLOWED_FIELDS,
            "CACHE_CONTROL_TYPES": dg.CACHE_CONTROL_TYPES,
            "CACHE_CONTROL_TTLS": dg.CACHE_CONTROL_TTLS,
            "ALLOWED_CITATION_TYPES": dg.ALLOWED_CITATION_TYPES,
            "KNOWN_UNSUPPORTED_CITATION_TYPES": dg.KNOWN_UNSUPPORTED_CITATION_TYPES,
            "KNOWN_UNSUPPORTED_CITATION_FIELDS": dg.KNOWN_UNSUPPORTED_CITATION_FIELDS,
            "TOOL_CALL_ALLOWED_FIELDS": dg.TOOL_CALL_ALLOWED_FIELDS,
            "ALLOWED_TOOL_CALL_TYPES": dg.ALLOWED_TOOL_CALL_TYPES,
            "TOOL_CALL_FUNCTION_ALLOWED_FIELDS": dg.TOOL_CALL_FUNCTION_ALLOWED_FIELDS,
        }
        for typ, felder in dg.ALLOWED_PART_FIELDS.items():
            reg[f"ALLOWED_PART_FIELDS[{typ}]"] = felder
        for typ, felder in dg.ALLOWED_CITATION_FIELDS.items():
            reg[f"ALLOWED_CITATION_FIELDS[{typ}]"] = felder
        return reg

    def test_echte_str_verhalten_sich_deckungsgleich(self):
        reg = self._register()
        # Getestet wird jedes Wort gegen JEDES Register -- also auch jeder
        # Nicht-Treffer, nicht nur die Treffer.
        woerter = {"", "x", "voellig_neu", "TEXT", "text ", "5M", "Function"}
        for eintraege in reg.values():
            woerter |= set(eintraege)

        vergleiche = 0
        for name, eintraege in sorted(reg.items()):
            for wort in sorted(woerter):
                self.assertIs(type(wort), str)
                self.assertEqual(
                    wort in eintraege,
                    dg._ist_registriert(wort, eintraege),
                    f"{name}: {wort!r} verhaelt sich anders als vor dem Fix",
                )
                vergleiche += 1
        # Untergrenze statt exakter Zahl: waechst ein Register, waechst der
        # Beweis mit, ohne dass dieser Test bricht.
        self.assertGreater(vergleiche, 1000)

    def test_nicht_str_bleibt_ueberall_fail_closed(self):
        for name, eintraege in sorted(self._register().items()):
            for wert in (1, 0, None, True, False, (), frozenset(), 3.5, b"text"):
                self.assertFalse(
                    dg._ist_registriert(wert, eintraege),
                    f"{name}: {wert!r} gilt faelschlich als registriert",
                )

    def test_ist_echter_str_lehnt_subklassen_ab(self):
        self.assertTrue(dg._ist_echter_str("text"))
        self.assertFalse(dg._ist_echter_str(_alias("text")))
        # Auch eine voellig harmlose Subklasse ohne __eq__/__hash__ zaehlt
        # nicht -- die Regel ist Typidentitaet, nicht "boesartig aussehend".
        class Harmlos(str):
            pass
        self.assertFalse(dg._ist_echter_str(Harmlos("text")))


if __name__ == "__main__":
    unittest.main()
