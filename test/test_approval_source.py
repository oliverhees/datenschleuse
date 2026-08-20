"""Unit-Tests fuer die HERKUNFT der Stufe-2-Freigabe (DATENSCHLE-69,
Security-Finding F2).

Der Befund
----------
Das Freigabe-Gate fuer Schutzklasse 2 las ``sensitivity_approval`` aus
``data["metadata"]`` -- also aus dem Request-Body. In litellm 1.97.0 ueberlebt
ein client-gesetztes ``metadata`` den Weg bis in den Guardrail: gestrippt
werden ausschliesslich Keys mit Prefix ``user_api_key_`` und eine kleine
Kontroll-Liste (``_UNTRUSTED_METADATA_CONTROL_FIELDS``,
``proxy/litellm_pre_call_utils.py:215-227`` und ``:1655-1660``).
``sensitivity_approval`` steht in keiner der beiden Mengen.

Gemessen (PoC des Auditors): mit ``metadata: {"sensitivity_approval": true}``
im Body wird aus BLOCKED ein PASSED.

    [P4 approval=False] BLOCKED: Anfrage als Stufe 2 (vertraulich) ...
    [P4 approval=True]  PASSED

Damit konnte der Kontrollierte sein eigenes Kontroll-Gate abschalten.

Die Entscheidung
----------------
Freigeben darf AUSSCHLIESSLICH der Betreiber -- ueber die Key-Konfiguration
oder ueber einen Header mit betreiberseitig konfiguriertem Geheimnis. Niemals
aus dem Request-Body.

Begruendung (von Oliver entschieden, hier festgehalten): ein Gate, das der
Kontrollierte selbst abschalten kann, ist kein Gate. Fuer ein Werkzeug, dessen
Zweck es ist, auch bei FEHLERHAFTEN Clients zu schuetzen, ist Client-Vertrauen
an dieser Stelle nicht verteidigbar. litellm begruendet seinen eigenen
``user_api_key_``-Strip woertlich genauso: "a caller pre-populating any of
these keys would have their forged values surface in guardrails, spend
tracking, audit logs, and identity resolution".

Muster ist ``enforce_tier_3_block``: die Funktion nimmt bewusst NUR das
Classification-Objekt und hat keinen Bypass-Parameter.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_approval_source.py" -v
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


#: Ein Text, den der Klassifizierer sicher als Stufe 2 einstuft. Wird beim
#: Import einmal gegen den echten Klassifizierer verifiziert -- ein Testwert,
#: der die Stufe gar nicht ausloest, wuerde nichts messen (dieselbe Lehre wie
#: bei den Wertformen im Snapshot-Test).
_TIER2_NAME = "Max Mustermann"
_TIER2_TEXT = (
    "Streng vertraulich: Gehaltsliste und Kuendigungsplanung fuer "
    f"{_TIER2_NAME}, Personalakte."
)


async def _fake_analyze(text):
    """Findet den Testnamen als PERSON.

    Nicht kosmetisch: Stufe 2 verlangt ein Vertraulich-Signal UND eine
    Personen-Referenz. Ohne Entity klassifiziert derselbe Text als Stufe 1 --
    der Test wuerde dann gar kein Gate ausloesen und waere gruen, ohne etwas
    zu messen. Eine Messung ist nur so gut wie ihre Wertform.
    """
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


class _KeyAuth:
    """Minimaler Ersatz fuer litellms ``UserAPIKeyAuth``: ein Objekt mit
    ``metadata``/``team_metadata``, wie es der Proxy aus der Key-Konfiguration
    des BETREIBERS baut."""

    def __init__(self, metadata=None, team_metadata=None):
        self.metadata = metadata or {}
        self.team_metadata = team_metadata or {}


def _tier2_body(metadata=None):
    data = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": _TIER2_TEXT}],
    }
    if metadata is not None:
        data["metadata"] = metadata
    return data


class _Case(unittest.IsolatedAsyncioTestCase):
    async def run_hook(self, data, guard=None, key_auth=None, call_type="acompletion"):
        guard = guard or _guard()
        return await guard.async_pre_call_hook(
            user_api_key_dict=key_auth, cache=None, data=data, call_type=call_type
        )

    async def assert_blocked(self, data, guard=None, key_auth=None):
        """Der Hook wickelt Tier2ApprovalRequired in DatenschleuseBlocked --
        litellm erkennt nur diese als Guardrail-Block."""
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await self.run_hook(data, guard=guard, key_auth=key_auth)
        self.assertIn("Stufe 2", str(ctx.exception))
        return ctx.exception

    async def assert_passed(self, data, guard=None, key_auth=None):
        return await self.run_hook(data, guard=guard, key_auth=key_auth)


class TestTier2FixtureIsRealistic(_Case):
    """Bauart-Absicherung: der Testtext MUSS wirklich Stufe 2 sein, sonst
    misst die ganze Datei nichts."""

    async def test_fixture_wird_als_stufe_2_klassifiziert(self):
        entities = await _fake_analyze(_TIER2_TEXT)
        klass = sc.SensitivityClassifier().classify(_TIER2_TEXT, entities=entities)
        self.assertIs(klass.tier, sc.Tier.TIER_2, klass.summary())


class TestBodyApprovalIsIgnored(_Case):
    """DER Befund: die Freigabe aus dem Request-Body darf nicht wirken."""

    async def test_freigabe_aus_dem_body_wirkt_nicht(self):
        data = _tier2_body({sc.SENSITIVITY_APPROVAL_KEY: True})
        await self.assert_blocked(data)

    async def test_freigabe_als_string_aus_dem_body_wirkt_nicht(self):
        for wert in ("true", "1", "yes", "ja", "TRUE"):
            with self.subTest(wert=wert):
                data = _tier2_body({sc.SENSITIVITY_APPROVAL_KEY: wert})
                await self.assert_blocked(data)

    async def test_freigabe_aus_litellm_metadata_wirkt_nicht(self):
        """Zweiter Metadaten-Kanal, denselben Weg. litellm propagiert je nach
        Codepfad ``metadata`` ODER ``litellm_metadata`` -- ein Fix, der nur
        einen der beiden abdeckt, waere derselbe Alias-Fehler wie seinerzeit
        bei ``headers``/``extra_headers``."""
        data = _tier2_body()
        data["litellm_metadata"] = {sc.SENSITIVITY_APPROVAL_KEY: True}
        await self.assert_blocked(data)

    async def test_body_flag_wird_aus_den_metadaten_entfernt(self):
        """Ignorieren reicht nicht: das Flag darf auch nicht stehen bleiben.

        Sonst wandert es durch den Logging-Kanal weiter und sieht fuer jeden
        spaeteren Leser aus, als HAETTE eine Freigabe vorgelegen -- eine
        Falschaussage im Audit-Trail.
        """
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Harmloser Text."}],
            "metadata": {sc.SENSITIVITY_APPROVAL_KEY: True},
        }
        out = await self.run_hook(data)
        self.assertNotIn(sc.SENSITIVITY_APPROVAL_KEY, out["metadata"])

    async def test_blockmeldung_nennt_den_ignorierten_body_versuch(self):
        """Ein stiller No-op ist genau die Fehlerklasse, die dieses Projekt
        wiederholt gebissen hat. Wer die Freigabe in den Body schreibt, muss
        aus der Meldung erfahren, dass sie dort nicht wirkt."""
        data = _tier2_body({sc.SENSITIVITY_APPROVAL_KEY: True})
        meldung = str(await self.assert_blocked(data)).lower()
        # Die Meldung muss BEIDES sagen: dass der Body-Weg nicht wirkt, und
        # welcher Weg stattdessen gilt. Nur "blockiert" waere eine Sackgasse.
        self.assertIn("betreiber", meldung)
        self.assertIn(sc.SENSITIVITY_APPROVAL_KEY, meldung)
        self.assertIn("ignoriert", meldung)
        self.assertIn(sc.OPERATOR_APPROVAL_KEY, meldung)
        self.assertIn(sc.APPROVAL_HEADER, meldung)


class TestOperatorApprovalWorks(_Case):
    """Der Betreiber muss freigeben KOENNEN -- sonst ist Stufe 2 faktisch ein
    Hard-Block und der Betreiber schaltet die Guardrail ab."""

    async def test_freigabe_aus_der_key_konfiguration_wirkt(self):
        key = _KeyAuth(metadata={sc.OPERATOR_APPROVAL_KEY: True})
        await self.assert_passed(_tier2_body(), key_auth=key)

    async def test_freigabe_aus_der_team_konfiguration_wirkt(self):
        key = _KeyAuth(team_metadata={sc.OPERATOR_APPROVAL_KEY: True})
        await self.assert_passed(_tier2_body(), key_auth=key)

    async def test_key_konfiguration_als_dict_wirkt(self):
        """litellm liefert je nach Codepfad ein Objekt ODER ein dict."""
        key = {"metadata": {sc.OPERATOR_APPROVAL_KEY: True}}
        await self.assert_passed(_tier2_body(), key_auth=key)

    async def test_ohne_key_konfiguration_bleibt_es_beim_block(self):
        await self.assert_blocked(_tier2_body(), key_auth=_KeyAuth())

    async def test_kein_key_objekt_bleibt_beim_block(self):
        """SDK-/Testpfad ohne Auth: sicherer Default ist NICHT freigegeben."""
        await self.assert_blocked(_tier2_body(), key_auth=None)


class TestHeaderApprovalNeedsOperatorSecret(_Case):
    """Der Header-Weg ist nur betreiberkontrolliert, WEIL er ein Geheimnis
    braucht. Ein blosser Header waere wieder Client-Eingabe."""

    HEADER = sc.APPROVAL_HEADER
    # Mindestens APPROVAL_SECRET_MIN_LEN Zeichen (Runde 4, F2): ein
    # Geheimnis auf dem Stufe-2-Schalter wird erzeugt, nicht ausgedacht.
    # Ein zu kurzer Testwert wuerde ab jetzt schon beim Konstruieren
    # scheitern -- und damit die Freigabe-Wege gar nicht mehr messen.
    SECRET = "s3cr3t-vom-betreiber-lang-genug-fuer-die-grenze"

    def _guard_with_secret(self):
        return _guard(approval_header_secret=self.SECRET)

    def _body_with_header(self, wert):
        data = _tier2_body()
        data["proxy_server_request"] = {
            "url": "http://proxy/v1/chat/completions",
            "method": "POST",
            "headers": {self.HEADER: wert},
        }
        return data

    async def test_header_mit_korrektem_geheimnis_gibt_frei(self):
        await self.assert_passed(
            self._body_with_header(self.SECRET), guard=self._guard_with_secret()
        )

    async def test_header_mit_falschem_geheimnis_gibt_nicht_frei(self):
        await self.assert_blocked(
            self._body_with_header("geraten"), guard=self._guard_with_secret()
        )

    async def test_header_ohne_konfiguriertes_geheimnis_gibt_nicht_frei(self):
        """Ohne Betreiber-Konfiguration ist der Header-Weg komplett AUS --
        nicht "offen fuer alle"."""
        await self.assert_blocked(
            self._body_with_header("true"), guard=_guard()
        )

    async def test_header_geheimnis_wird_nach_der_pruefung_redigiert(self):
        """Gesetz 5: das Geheimnis darf nicht ueber den Logging-Kanal
        weiterwandern. ``proxy_server_request.headers`` geht in die
        Logging-Callbacks."""
        data = self._body_with_header(self.SECRET)
        guard = self._guard_with_secret()
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="acompletion"
        )
        kopf = out["proxy_server_request"]["headers"][self.HEADER]
        self.assertNotEqual(kopf, self.SECRET)


class TestTier3StaysUnreachable(_Case):
    """Der harte Block darf von KEINEM Freigabeweg beeinflussbar sein --
    auch nicht vom neuen Betreiber-Weg. Sonst haetten wir das Bypass-Argument
    wieder eingebaut, das enforce_tier_3_block ausdruecklich verbietet."""

    TIER3_TEXT = (
        "Patient leidet an einer HIV-Infektion, zusaetzlich Diagnose "
        "Leukaemie, Befund der Onkologie."
    )

    async def test_tier3_fixture_ist_wirklich_stufe_3(self):
        klass = sc.SensitivityClassifier().classify(self.TIER3_TEXT, entities=[])
        self.assertIs(klass.tier, sc.Tier.TIER_3, klass.summary())

    async def test_betreiber_freigabe_hebt_stufe_3_nicht_auf(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": self.TIER3_TEXT}],
        }
        key = _KeyAuth(metadata={sc.OPERATOR_APPROVAL_KEY: True})
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await self.run_hook(data, key_auth=key)
        self.assertIn("Stufe 3", str(ctx.exception))


class TestBeideFreigabeKeysWerdenGestrippt(_Case):
    """Security-F2b: gestrippt wurde der FALSCHE Key.

    ``_strip_body_approval`` entfernte nur ``SENSITIVITY_APPROVAL_KEY``
    ("sensitivity_approval"). Ein client-gesetztes
    ``metadata["datenschleuse_sensitivity_approval"]`` -- der BETREIBER-Key
    -- blieb stehen und wanderte in den Logging-Kanal.

    Kein Zugriffs-Bypass: ``_operator_approved`` liest ``data["metadata"]``
    nie, die Freigabe kommt ausschliesslich aus Key-Konfiguration oder
    Header-Geheimnis. Aber genau der Schaden, den der eigene Docstring
    verhindern will: der Eintrag "saehe fuer jeden spaeteren Leser aus, als
    HAETTE eine Freigabe vorgelegen" -- eine Falschaussage im Audit-Trail,
    und ausgerechnet unter dem Namen, den ein Leser fuer den echten
    Betreiber-Kanal haelt.
    """

    async def test_betreiber_key_aus_dem_body_wird_entfernt(self):
        """DER Befund F2b."""
        data = _tier2_body({sc.OPERATOR_APPROVAL_KEY: True})
        await self.assert_blocked(data)
        self.assertNotIn(
            sc.OPERATOR_APPROVAL_KEY,
            data.get("metadata", {}),
            "Der Betreiber-Freigabe-Key aus dem BODY bleibt stehen und "
            "taeuscht spaeteren Lesern eine Freigabe vor.",
        )

    async def test_beide_keys_gleichzeitig_werden_entfernt(self):
        """Ein Client, der beide Namen ausprobiert, hinterlaesst keinen."""
        data = _tier2_body(
            {sc.SENSITIVITY_APPROVAL_KEY: True, sc.OPERATOR_APPROVAL_KEY: True}
        )
        await self.assert_blocked(data)
        meta = data.get("metadata", {})
        self.assertNotIn(sc.SENSITIVITY_APPROVAL_KEY, meta)
        self.assertNotIn(sc.OPERATOR_APPROVAL_KEY, meta)

    async def test_betreiber_key_auch_in_litellm_metadata(self):
        """Beide Metadaten-Kanaele, wie beim anderen Key auch.

        litellm propagiert je nach Codepfad ``metadata`` ODER
        ``litellm_metadata``. Ein Fix, der nur einen kennt, ist derselbe
        Alias-Fehler wie seinerzeit ``headers``/``extra_headers``.
        """
        data = _tier2_body({})
        data["litellm_metadata"] = {sc.OPERATOR_APPROVAL_KEY: True}
        await self.assert_blocked(data)
        self.assertNotIn(
            sc.OPERATOR_APPROVAL_KEY, data.get("litellm_metadata", {})
        )

    async def test_betreiber_key_aus_dem_body_gibt_keine_freigabe(self):
        """Die Gegenprobe zum Strippen: er hat nie gewirkt und wirkt auch
        weiterhin nicht. F2b ist eine Audit-Trail-Frage, kein Bypass -- diese
        Zusicherung haelt fest, dass das so BLEIBT."""
        data = _tier2_body({sc.OPERATOR_APPROVAL_KEY: True})
        await self.assert_blocked(data)

    async def test_echte_betreiber_freigabe_bleibt_unangetastet(self):
        """Der Fix darf den GUELTIGEN Weg nicht beschaedigen: die Freigabe
        aus der Key-Konfiguration kommt nicht aus dem Body und wird deshalb
        auch nicht gestrippt."""
        data = _tier2_body({sc.OPERATOR_APPROVAL_KEY: True})
        key = _KeyAuth(metadata={sc.OPERATOR_APPROVAL_KEY: True})
        out = await self.assert_passed(data, key_auth=key)
        self.assertIsNotNone(out)
        # Und der Body-Eintrag ist trotzdem weg.
        self.assertNotIn(sc.OPERATOR_APPROVAL_KEY, data.get("metadata", {}))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
