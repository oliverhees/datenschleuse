"""Datenschleuse — eigene Custom-Guardrail-Klasse fuer LiteLLM.

Zweck
-----
Ersetzt den eingebauten ``guardrail: presidio`` von LiteLLM. Der eingebaute
Guardrail buffert bei Streaming-Responses den KOMPLETTEN Antworttext, bevor er
Platzhalter zurueck auf Klartext mapped -> Time-to-first-Token geht verloren,
Streaming fuehlt sich an wie non-streaming.

Diese Klasse haelt stattdessen nur einen kleinen **Sliding-Window-Tail-Puffer**,
sodass echtes Token-Streaming erhalten bleibt, waehrend ueber Chunk-Grenzen
gesplittete Platzhalter trotzdem korrekt erkannt und ersetzt werden.

Architektur-Entscheidungen (siehe ISA.md, Decision 2026-07-22 custom-guardrail)
-------------------------------------------------------------------------------
1. Selbststaendige Klasse. Wir verlassen uns NICHT auf LiteLLMs internes
   Presidio-Guardrail-Metadata-Schema (Key-Name dort nicht offiziell
   dokumentiert). Stattdessen rufen wir Presidio Analyzer SELBST per REST auf
   und verwalten unser EIGENES Platzhalter->Klartext-Mapping in einem eigenen
   Metadata-Key ``request_data["metadata"]["datenschleuse_reid_map"]``.

2. Wir bauen die Maskierung SELBST aus den Analyzer-Ergebnissen, statt den
   Presidio-**Anonymizer**-Service zu benutzen. Grund (verifiziert gegen die
   Presidio-Anonymizer-API): der Standard-``replace``-Operator liefert fuer
   jede Entitaet den generischen Platzhalter ``<PERSON>`` — bei zwei
   verschiedenen Personen also ZWEIMAL ``<PERSON>``. Damit ist eine eindeutige
   Rueck-Zuordnung Platzhalter->Klartext unmoeglich (Re-Identification wuerde
   den falschen Wert einsetzen oder scheitern). Presidio kann ueber die
   REST-API keine durchnummerierten, eindeutigen Platzhalter erzeugen (der
   ``custom``-Operator braucht ein Lambda, das nicht JSON-serialisierbar ist).
   Deshalb erzeugen wir eindeutige Platzhalter ``<ENTITY_TYPE_N>`` selbst.
   Das gibt uns zusaetzlich volle Kontrolle ueber das Platzhalter-Format —
   worauf die Sliding-Window-Logik direkt aufbaut. Der Analyzer (echte
   Presidio-Abhaengigkeit) wird weiterhin genutzt.

3. Fail-closed ueberall: schlaegt die PII-Erkennung fehl (Presidio nicht
   erreichbar / Fehlerantwort), wird der Request GEBLOCKT statt unmaskiert
   durchgelassen. Das ist bestehende Projekt-Konvention (CLAUDE.md).

Sicherheits-Rationale zu Streaming (Fail-closed vs. UX)
-------------------------------------------------------
- Fehler beim MASKIEREN (pre_call) -> Request blocken (sonst PII-Leck).
- Fehler beim RE-IDENTIFIZIEREN (post_call) -> Platzhalter stehen lassen. Das
  ist KEIN Leck (Platzhalter enthalten keine PII), nur eine degradierte UX.
  Deshalb wird post_call defensiv abgefangen und blockt NICHT.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import logging
import os
import re
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

# httpx ist im offiziellen LiteLLM-Image bereits vorhanden (LiteLLM-Dependency)
# und wird fuer die Presidio-REST-Calls genutzt.
import httpx

# Reine Quasi-Identifier-Logik (keine Fremd-Abhaengigkeit, immer importierbar).
# Der zustandsbehaftete, verschluesselte Store (qi_state) wird erst LAZY im
# Konstruktor importiert -- nur wenn das QI-Feature aktiv ist -- damit dieses
# Modul weiterhin ohne `cryptography` standalone importier-/testbar bleibt.
import qi_generalization as qig

# Schutzklassen-Modell (Community-Feedback, siehe ISA.md Decision 2026-07-23):
# 3-Stufen-Sensitivitaetsklassifizierung VOR jeder Maskierung. Stufe 3 ist eine
# HARTE Code-Garantie (nie Cloud, auch nicht anonymisiert), keine Konfigurations-
# option -- deshalb IMMER aktiv, anders als der optionale QI-Layer. Reine Logik,
# keine LiteLLM-/Presidio-Laufzeitabhaengigkeit (nur PyYAML zum Config-Laden).
import sensitivity_classifier as sc


# ---------------------------------------------------------------------------
# Basisklasse: in Produktion die echte LiteLLM-CustomGuardrail, im Test-/
# Standalone-Betrieb (litellm nicht installiert) ein leichter Shim, damit die
# reine Re-Identification-Logik ohne LiteLLM-Installation getestet werden kann.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - abhaengig von der Laufzeitumgebung
    from litellm.integrations.custom_guardrail import CustomGuardrail as _GuardrailBase
    _LITELLM_AVAILABLE = True
except Exception:  # pragma: no cover
    _LITELLM_AVAILABLE = False

    class _GuardrailBase:  # minimaler Shim nur fuer Tests / Standalone
        def __init__(self, **kwargs: Any) -> None:
            self.guardrail_name = kwargs.get("guardrail_name", "datenschleuse-reid")


# Key, unter dem wir unser eigenes Platzhalter->Klartext-Mapping ablegen.
REID_MAP_KEY = "datenschleuse_reid_map"

# Sicherheitsmarge (in Zeichen) auf die laengste bekannte Platzhalter-Laenge.
# Siehe ReidStreamProcessor fuer die Begruendung.
DEFAULT_PLACEHOLDER_MARGIN = 10

# Umgang mit Bild-Parts in multimodalen Nachrichten. Siehe Konstruktor.
IMAGE_POLICIES = ("redact", "block", "pass")


# ===========================================================================
# MESSAGE-FELD-REGISTER (DATENSCHLE-66)
# ===========================================================================
# Warum ein Register statt einzelner if-Zweige: der Guardrail hat dieselbe
# Luecke jetzt dreimal gehabt -- Part-Ebene (DATENSCHLE-57), content-Container
# (DATENSCHLE-64) und nun jedes Feld NEBEN content (DATENSCHLE-66, PII in
# ``tool_calls[].function.arguments`` lief unveraendert ans Modell). Ursache
# war jedes Mal dieselbe: gelesen wurde, was man kannte; alles Uebrige lief
# still durch. Deshalb wird ab hier nicht mehr Feld fuer Feld entdeckt,
# sondern EINMAL vollstaendig erfasst: jedes Feld einer Chat-Message steht in
# genau einer der drei Listen unten. Was in keiner steht, ist unbekannt und
# blockt fail-closed. Ein neues Feld der OpenAI-API zwingt damit zu einer
# bewussten Entscheidung (Eintrag ins Register), statt lautlos ein Leck zu
# oeffnen.
#
# 1) MASKIERT: freier Text, der ans Zielmodell geht -> durch Presidio +
#    Masker (dasselbe reid_map wie content, kein zweites Mapping).
MESSAGE_FIELDS_MASKED = (
    "content",
    "name",
    "refusal",
    "tool_calls",
    "function_call",
    # Reasoning-Modelle spielen ihren Gedankengang im naechsten Turn zurueck.
    # Das ist Freitext und enthaelt regelmaessig genau die Werte, um die es im
    # Gespraech geht -> maskieren wie jeden anderen Text.
    "reasoning_content",
)

# 2) VALIDIERT: Protokoll-Felder, die KEIN Freitext sind. Sie werden nicht
#    maskiert (ihr Wert muss byte-identisch erhalten bleiben, sonst bricht die
#    Zuordnung von tool_call zu Tool-Ergebnis), aber sie werden gegen ein
#    enges Format geprueft -- sonst waeren sie ein bequemer Schmuggelkanal.
MESSAGE_FIELDS_VALIDATED = (
    "role",
    "tool_call_id",
    # Caching-Marker (Anthropic-Stil, von LiteLLM/Hermes injiziert). Traegt
    # keinen Anwendertext, nur einen Schalter -> validieren statt maskieren.
    # Wichtig: Hermes setzt das Feld automatisch, sobald Provider-ID oder
    # Hostname den Token "litellm" enthaelt. Ein Selbsthoster mit der
    # Subdomain litellm.seine-domain.de wuerde ohne diesen Eintrag ab der
    # ersten Folge-Nachricht hart geblockt (QA-Audit).
    "cache_control",
)

ALLOWED_MESSAGE_FIELDS = frozenset(MESSAGE_FIELDS_MASKED + MESSAGE_FIELDS_VALIDATED)

# Protokoll-Rollen. Eine unbekannte Rolle ist entweder ein Client-Fehler oder
# ein Schmuggelversuch (Freitext im role-Feld) -> fail-closed.
ALLOWED_ROLES = frozenset(
    {"system", "user", "assistant", "tool", "function", "developer"}
)

# Opake Korrelations-IDs (tool_call_id, tool_calls[].id): vom Modell bzw. der
# API vergeben, nie Freitext. Bewusst eng: alles, was hier nicht passt, ist
# kein legitimer Identifier.
# ACHTUNG: wird mit ``fullmatch`` benutzt, NICHT mit ``match``. ``$`` matcht
# in Python auch VOR einem abschliessenden Newline -- mit ``^...$`` und
# ``match`` waere "call_1\n" ein gueltiger Identifier gewesen und der
# Zeilenumbruch ein kleiner, aber echter Schmuggelkanal (Security-Audit F6).
OPAQUE_ID_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")

# Maximale Verschachtelungstiefe in ``arguments``. Echte Tool-Argumente sind
# flach; alles darueber ist entweder kaputt oder ein Versuch, die Guardrail in
# einen RecursionError laufen zu lassen (unkontrollierter Fehlerpfad statt
# fail-closed, Security-Audit F7).
MAX_JSON_DEPTH = 64

# Fuellzeichen, das im Verifikationsdurchlauf an die Stelle bekannter
# Platzhalter tritt (siehe _verify_no_pii_left).
_PLACEHOLDER_PROBE_FILLER = " "

# Felder eines einzelnen tool_call-Eintrags (gleiche Logik eine Ebene tiefer).
TOOL_CALL_ALLOWED_FIELDS = frozenset({"id", "type", "index", "function"})
TOOL_CALL_FUNCTION_ALLOWED_FIELDS = frozenset({"name", "arguments"})
# ``type`` fehlt bei manchen Clients ganz (historisch impliziert "function").
ALLOWED_TOOL_CALL_TYPES = frozenset({"function"})

# Erlaubte Struktur von ``cache_control``. Bewusst eng: ein Marker hat genau
# diese zwei Felder und diese Werte -- alles andere ist kein Caching-Hinweis,
# sondern ein Kanal, den niemand geprueft hat.
CACHE_CONTROL_ALLOWED_FIELDS = frozenset({"type", "ttl"})
CACHE_CONTROL_TYPES = frozenset({"ephemeral"})
CACHE_CONTROL_TTLS = frozenset({"5m", "1h"})

# Felder, die es in der Praxis gibt, die wir aber (noch) NICHT behandeln.
# Sie blocken wie jedes unbekannte Feld -- werden in der Meldung aber beim
# Namen genannt, damit ein Betreiber weiss, woran er ist. Die Namen stammen
# aus dieser konstanten Liste, nie aus dem Request (Gesetz 5).
KNOWN_UNSUPPORTED_MESSAGE_FIELDS = frozenset({
    "audio",
    "annotations",
    "thinking_blocks",
    "reasoning",
    "redacted_thinking_blocks",
    "provider_specific_fields",
    "prefix",
    "partial",
})

# Freitext-Felder eines Streaming-Deltas NEBEN ``content``. Sie brauchen
# dieselbe Sliding-Window-Behandlung wie der Textkanal: ein Platzhalter kann
# auch hier mitten durch einen Chunk brechen. Als Liste statt einzeln
# behandelt, damit ein weiteres Feld eine Zeile ist und nicht wieder ein
# vergessener Pfad (``refusal`` war genau das, Security-Audit S1).
STREAM_TEXT_DELTA_FIELDS = ("reasoning_content", "refusal")

# Betreiber-Diagnose. Blockmeldungen gehen an den Client; hier landet
# zusaetzlich serverseitig, WAS geblockt hat -- Feldnamen bzw. Fingerprints,
# niemals Werte.
_LOG = logging.getLogger("datenschleuse")

# Erlaubte Felder in der Blockmeldung nennen wir NIE mit Client-Werten,
# sondern nur mit dieser konstanten, unveraenderlichen Liste (Gesetz 5).
_ALLOWED_FIELDS_HINT = ", ".join(sorted(ALLOWED_MESSAGE_FIELDS))


# ===========================================================================
# PART-FELD-REGISTER (DATENSCHLE-65)
# ===========================================================================
# Vierte Wiederholung derselben Bauart, jetzt eine Ebene unter dem
# Message-Register: DATENSCHLE-57 hat den Part-TYP auf eine Allowlist
# gestellt, die FELDER eines Parts blieben ungeprueft. Ein Text-Part durfte
# beliebige Zusatzschluessel tragen, und die gingen unveraendert ans Modell
# (verifizierter PoC: ``{"type":"text","text":"hi","zusatz":"<PII>"}``).
#
# Akut statt akademisch macht das ``cache_control``: DATENSCHLE-66
# legitimiert den Marker auf MESSAGE-Ebene, Anthropic-Clients haengen ihn
# aber an CONTENT-PARTS. "Part mit Zusatzfeld" ist damit kein exotischer
# Angriff, sondern Normalbetrieb -- der Marker MUSS durchgehen, waehrend
# alles Unbekannte blockt. Genau dafuer braucht es ein Register statt eines
# weiteren if-Zweiges.
#
# Aufbau bewusst identisch zum Message-Register (gleiche Namen, gleiche
# Zweiteilung), nur pro Part-Typ geschluesselt: jedes Feld eines Parts steht
# in genau einer der beiden Listen. Was in keiner steht, blockt fail-closed.

# 1) MASKIERT: freier Text, der ans Zielmodell geht -> Presidio + Masker.
PART_FIELDS_MASKED = {
    # ``citations`` steht bewusst HIER und nicht bei den validierten Feldern,
    # obwohl seine Struktur streng validiert wird: es TRAEGT Freitext
    # (``cited_text``, ``document_title``) und dieser Freitext geht durch
    # Presidio + Masker. Wer im Register nachschlaegt, ob ein Feld ein
    # Textkanal ans Modell ist, muss hier fuendig werden -- unter "erreicht
    # den Provider unveraendert" waere es schlicht falsch einsortiert.
    # Details siehe _validate_citations / _mask_citations.
    "text": ("text", "citations"),
    # Bild-Parts tragen keinen Text. Ihre Nutzlast laeuft ueber die
    # Bild-Policy (redact/block/pass), nicht ueber den Masker.
    "image_url": (),
}

# 2) VALIDIERT: kein Freitext, muss den Provider unveraendert erreichen --
#    und wird deshalb gegen ein enges Format geprueft, sonst waere es der
#    bequemste Schmuggelkanal des Parts.
PART_FIELDS_VALIDATED = {
    "text": ("type", "cache_control"),
    # ``cache_control`` auch hier: Anthropic erlaubt den Marker auf JEDEM
    # Content-Block, Bilder eingeschlossen. Er ist vollstaendig validiert
    # (Objekt mit hoechstens ``type``/``ttl`` aus geschlossenen Wertemengen),
    # traegt also keinerlei Freitext -- ihn nur auf Text-Parts zuzulassen
    # waere reine Client-Breakage ohne Sicherheitsgewinn.
    "image_url": ("type", "image_url", "cache_control"),
}

ALLOWED_PART_FIELDS = {
    part_type: frozenset(PART_FIELDS_MASKED[part_type] + PART_FIELDS_VALIDATED[part_type])
    for part_type in PART_FIELDS_MASKED
}

# Der Part-TYP-Allowlist aus DATENSCHLE-57 -- jetzt aus dem Register
# abgeleitet statt als zweite Wahrheit danebenstehend.
ALLOWED_PART_TYPES = frozenset(ALLOWED_PART_FIELDS)

# Felder des ``image_url``-Containers (eine Ebene unter dem Part). Auch der
# ist client-kontrolliert, und ``_handle_image_part`` ersetzt ausschliesslich
# ``url`` -- jedes weitere Feld ueberlebte die Bild-Policy unveraendert.
# ``detail`` ist der einzige weitere Schluessel, den die OpenAI-API kennt.
IMAGE_URL_ALLOWED_FIELDS = frozenset({"url", "detail"})
IMAGE_URL_DETAILS = frozenset({"auto", "low", "high"})

# ===========================================================================
# CITATIONS-REGISTER (DATENSCHLE-65)
# ===========================================================================
# Anthropic haengt an Assistant-Text-Bloecke ein ``citations``-Array. Schickt
# ein Client die History zurueck -- der Normalfall im Multi-Turn -- traegt die
# Assistant-Nachricht dieses Feld. Bis hierher blockte es als unbekanntes
# Part-Feld und riss damit die GANZE Folgeanfrage mit. Das war eine
# Regression aus genau diesem Work Item.
#
# Warum MASKIEREN und nicht durchreichen: ``cited_text`` ist wortwoertlicher
# Dokumentinhalt, ``document_title`` der vom Nutzer vergebene Dokumenttitel
# ("Arztbrief_Mustermann.pdf"). Beides ist Freitext und kann PII tragen --
# also derselbe Weg wie jeder andere Text: Presidio + Masker.
#
# Warum nicht BLOCKEN, sobald ``cited_text`` da ist: das Feld ist im
# Request-Schema PFLICHT (Anthropic Messages API, TextCitationParam) und
# wird beim Echo ausdruecklich zurueckerwartet -- die Doku haelt sogar fest,
# dass es dabei nicht auf die Input-Tokens zaehlt. Eine Allowlist, die es
# blockt, laesst die Regression fuer jeden realen Zitat-Nutzer bestehen und
# waere nur im kuenstlichen Testfall gruen.
#
# Warum trotzdem eine ENGE Struktur-Validierung obendrauf: alles, was nicht
# Freitext ist, sind Indizes -- und ein ungeprueftes Indexfeld waere der
# bequemste Schmuggelkanal des Zitats. Gleiche Bauart wie cache_control.

# 1) MASKIERT: Freitext im Zitat -> Presidio + Masker (siehe _mask_citations).
CITATION_FIELDS_MASKED = {
    "char_location": ("cited_text", "document_title"),
    "page_location": ("cited_text", "document_title"),
    "content_block_location": ("cited_text", "document_title"),
}

# 2) INDIZES: reine Zahlen, muessen den Provider unveraendert erreichen,
#    sonst zeigt das Zitat auf die falsche Stelle.
CITATION_INDEX_FIELDS = {
    "char_location": ("document_index", "start_char_index", "end_char_index"),
    "page_location": ("document_index", "start_page_number", "end_page_number"),
    "content_block_location": (
        "document_index", "start_block_index", "end_block_index",
    ),
}

ALLOWED_CITATION_FIELDS = {
    citation_type: frozenset(
        ("type",) + CITATION_FIELDS_MASKED[citation_type]
        + CITATION_INDEX_FIELDS[citation_type]
    )
    for citation_type in CITATION_FIELDS_MASKED
}
ALLOWED_CITATION_TYPES = frozenset(ALLOWED_CITATION_FIELDS)

# Die beiden uebrigen Zitat-Typen der Messages-API. Sie blocken bewusst:
#   search_result_location      -- traegt ``source``/``title`` als Freitext
#   web_search_result_location  -- traegt ``url``/``title`` als Freitext UND
#                                  ``encrypted_index``, das den Provider
#                                  byte-identisch erreichen muss
#
# KORREKTUR (QA-Audit zu 1e197f9): Hier stand, beide entstuenden
# "ausschliesslich aus Part-Typen, die die Datenschleuse ohnehin am Part-TYP
# blockt", ein Pfad hier waere deshalb toter Code. Fuer
# ``search_result_location`` stimmt das -- der Typ setzt einen
# ``search_result``-Part voraus, und der blockt. Fuer
# ``web_search_result_location`` stimmt es NICHT: Anthropics natives
# Web-Search-Tool wird ueber das TOP-LEVEL-Feld ``tools`` aktiviert
# ({"type": "web_search_20250305", "name": "web_search"}), braucht keinen
# Content-Part, und das Zitat haengt danach an einem normalen ``text``-Block.
# Der Typ ist also erreichbar. Die Begruendung war falsch.
#
# WARUM ER TROTZDEM BLOCKT -- neu begruendet statt stillschweigend behalten:
# Ihn allein zu oeffnen repariert den Kundenfall nicht. Anthropic verlangt
# fuer die Fortsetzung, dass der Client die Assistant-Bloecke unveraendert
# zurueckschickt, ``server_tool_use`` und ``web_search_tool_result``
# eingeschlossen -- die blocken am PART-Typ, eine Ebene hoeher. Die Anfrage
# scheitert dann eben dort. Bezahlt waere das mit ``encrypted_index``, fuer
# das Anthropic weder Zeichenmenge noch Laenge dokumentiert: ein opaker
# Provider-Token-Kanal ohne belegbare Obergrenze, der nicht maskiert werden
# darf. Realer Sicherheitspreis, kein funktionaler Gegenwert.
#
# FOLGE, ehrlich benannt: Multi-Turn mit Anthropics Web-Search funktioniert
# durch diese Datenschleuse nicht. Bekannte, akzeptierte Einschraenkung --
# siehe docs/foundation/security-baseline.md. Wer sie aufheben will, braucht
# ein Work Item, das BEIDE Ebenen zusammen behandelt.
#
# Der RUECKWEG ist davon unberuehrt: kommt ein Web-Search-Zitat in einer
# Antwort an, werden seine Platzhalter aufgeloest
# (CITATION_RESPONSE_TEXT_FIELDS deckt alle fuenf Typen ab).
KNOWN_UNSUPPORTED_CITATION_TYPES = frozenset({
    "search_result_location",
    "web_search_result_location",
})

# ``file_id`` gibt es NUR response-seitig; das Request-Schema kennt es nicht.
# Ein schema-konformer Client schickt es nie. Durchlassen hiesse, einen
# weiteren opaken String-Kanal zu oeffnen, ohne dass irgendetwas ihn braucht.
KNOWN_UNSUPPORTED_CITATION_FIELDS = frozenset({"file_id"})

# Jedes Zitat kostet bis zu zwei Analyzer-Durchlaeufe. Vor DATENSCHLE-65
# blockte ``citations`` und kostete null -- die Grenze gehoert deshalb mit
# der Oeffnung zusammen, sonst ist eine lange Liste ein Lastkanal (F7).
MAX_CITATIONS_PER_PART = 1000

# Indizes sind Positionen in einem Dokument. Eine Obergrenze macht das Feld
# als Zahlenkanal weitgehend unbrauchbar (Telefonnummern sind groesser),
# ohne realistische Dokumente einzuschraenken. Ehrlich bleibt: eine KURZE
# Zahl bleibt eine Zahl -- das schliesst der Deckel nicht.
MAX_CITATION_INDEX = 1_000_000_000

# Freitext-Felder eines Zitats auf dem RUECKWEG (QA-Audit F1).
#
# Bewusst BREITER als CITATION_FIELDS_MASKED: der Hinweg laesst nur die drei
# Dokument-Zitattypen durch, die ANTWORT kann jeden Typ tragen -- ein
# Web-Search-Zitat entsteht serverseitig ueber das Top-Level-Feld ``tools``
# und musste nie durch den Hinweg.
#
# Warum die Breite hier keine Sicherheitsfrage ist: der Rueckweg ist ein
# EINLOESE-Pfad, kein Pruef-Pfad. ``reidentify_full`` ersetzt ausschliesslich
# Platzhalter, die dieser Request selbst vergeben hat, und das Ergebnis geht
# an den KUNDEN, nicht an den Provider. Ein Feld zu viel kann hier nichts
# leaken; ein Feld zu wenig laesst einen Platzhalter beim Kunden stehen.
# Deshalb ist die Fehlerrichtung hier die umgekehrte als auf dem Hinweg:
# grosszuegig statt fail-closed.
#
# ``encrypted_index`` und ``file_id`` stehen bewusst NICHT hier: opake
# Provider-Token, die byte-identisch bleiben muessen.
CITATION_RESPONSE_TEXT_FIELDS = (
    "cited_text",       # alle fuenf Zitat-Typen
    "document_title",   # die drei Dokument-Typen
    "title",            # search_result_location, web_search_result_location
    "source",           # search_result_location
    "url",              # web_search_result_location
    # ``supported_text`` steht in KEINER Anthropic-Doku -- LiteLLM erfindet
    # das Feld beim Normalisieren und fuellt es mit ``content["text"]``, also
    # dem VOLLEN Text des Assistant-Blocks, den das Zitat stuetzt
    # (transformation.py, ## CITATIONS). Damit ist es derselbe Freitext wie
    # der Antworttext selbst und traegt dieselben Platzhalter. Wer nur die
    # Anthropic-Feldnamen kennt, laesst hier einen kompletten
    # Antworttext-Klon mit rohen Platzhaltern beim Kunden stehen.
    "supported_text",
)

_ALLOWED_CITATION_TYPES_HINT = ", ".join(sorted(ALLOWED_CITATION_TYPES))
_ALLOWED_CITATION_FIELDS_HINT = {
    citation_type: ", ".join(sorted(fields))
    for citation_type, fields in ALLOWED_CITATION_FIELDS.items()
}

# Part-Felder, die es bei realen Providern gibt, die die Datenschleuse aber
# (noch) NICHT behandelt. Sie blocken wie jedes unbekannte Feld -- werden in
# der Meldung aber beim Namen genannt, damit ein Betreiber nicht per
# Trial-and-Error gegen die Allowlist raten muss. Die Namen stammen aus
# dieser konstanten Liste, nie aus dem Request (Gesetz 5).
#
# Bewusst EINMAL vollstaendig erfasst statt Feld fuer Feld entdeckt:
#   OpenAI      -- input_audio, file, refusal (Assistant-Output-Part)
#   Anthropic   -- source, title, context, thinking, signature,
#                  data, id, name, input, content, is_error, tool_use_id
#                  (``citations`` stand hier ebenfalls und ist mit
#                  DATENSCHLE-65 ins Register gewandert -- siehe unten)
#   Google/Vertex (ueber LiteLLM) -- inline_data, file_data, function_call,
#                  function_response, thought, video_metadata
#   LiteLLM     -- provider_specific_fields, index, partial
# Sie alle sind entweder eigene Part-TYPEN (blocken bereits ueber den Typ)
# oder Nutzlast-Felder, fuer die es keinen geprueften Pfad gibt. Ein
# kuenftiges Feld hier einzutragen ist eine bewusste Entscheidung mit Work
# Item -- kein stillschweigendes Durchreichen.
KNOWN_UNSUPPORTED_PART_FIELDS = frozenset({
    "input_audio",
    "file",
    "refusal",
    "source",
    "title",
    "context",
    "thinking",
    "signature",
    "data",
    "id",
    "name",
    "input",
    "content",
    "is_error",
    "tool_use_id",
    "inline_data",
    "file_data",
    "function_call",
    "function_response",
    "thought",
    "video_metadata",
    "provider_specific_fields",
    "index",
    "partial",
})

# Part-TYPEN, die es in der Praxis gibt und die wir bewusst NICHT
# unterstuetzen. Sie blocken wie jeder unbekannte Typ -- werden in der
# Meldung aber beim Namen genannt, damit ein Betreiber eine BEKANNTE,
# akzeptierte Einschraenkung von einem echten Bug unterscheiden kann.
# Dieselbe Bauart wie KNOWN_UNSUPPORTED_CITATION_TYPES, eine Ebene hoeher.
#
# Anlass (QA-Audit zu 2165cf2): Anthropics natives Web-Search-Tool verlangt
# fuer die Fortsetzung, dass der Client die Assistant-Bloecke unveraendert
# zurueckschickt -- diese beiden eingeschlossen. Ein spec-konformer Client
# schickt sie also IMMER mit, und der Betreiber sah dafuer bisher exakt die
# Meldung, die auch ein Tippfehler im Part-Typ ausloest.
#
# Gesetz 5: die Namen stammen aus dieser konstanten Liste, nie aus dem
# Request. Genannt wird ein Typ nur, wenn der Client-Wert exakt einem
# Eintrag hier entspricht -- der ausgegebene String ist dann unsere
# Konstante, nicht die Eingabe.
KNOWN_UNSUPPORTED_PART_TYPES = frozenset({
    "server_tool_use",
    "web_search_tool_result",
})

# Konstanter Verweis auf die Stelle, an der die Einschraenkung begruendet
# steht. Ohne ihn hat ein Betreiber keinen Pfad zur Doku.
_WEB_SEARCH_LIMITATION_DOC = (
    "docs/foundation/security-baseline.md "
    "(\"Bekannte Einschraenkung: Anthropics natives Web-Search-Tool\")"
)

# Konstante Hinweistexte pro Part-Typ (nie Client-Werte, Gesetz 5).
_ALLOWED_PART_FIELDS_HINT = {
    part_type: ", ".join(sorted(fields))
    for part_type, fields in ALLOWED_PART_FIELDS.items()
}
_ALLOWED_PART_TYPES_HINT = ", ".join(sorted(ALLOWED_PART_TYPES))


def _image_part_url(part: Dict[str, Any]) -> str:
    """Liest die URL aus einem ``image_url``-Part. Das OpenAI-Format ist
    ``{"type": "image_url", "image_url": {"url": "..."}}``, manche Clients
    schicken den String direkt — beides akzeptieren, nichts erraten."""
    value = part.get("image_url")
    if isinstance(value, dict):
        url = value.get("url")
        return url if isinstance(url, str) else ""
    return value if isinstance(value, str) else ""


def _split_data_url(url: str) -> Tuple[str, Optional[bytes]]:
    """``data:image/png;base64,XXXX`` -> ``("image/png", b"...")``.

    Liefert ``(mime, None)``, wenn aus der URL keine Bilddaten gewonnen
    werden konnten -- der Aufrufer entscheidet dann fail-closed. ``mime``
    ist dabei das verlaessliche Signal FUER DEN AUFRUFER, WARUM es keine
    Bytes gab: leer, wenn ueberhaupt kein ``data:``-Header mit
    base64-Marker erkannt wurde (z.B. eine externe http-URL); gesetzt,
    wenn der Header erkannt wurde, das Payload danach aber fehlt oder
    nicht dekodierbar ist. WICHTIG: mime muss deshalb VOR der
    Payload-Pruefung berechnet werden -- sonst geht bei einem leeren
    Payload (``data:image/png;base64,``) das mime-Signal verloren und ein
    Aufrufer kann eine leere eingebettete data:-URL nicht mehr von einer
    echten externen URL unterscheiden (siehe QA-Finding zu Finding 5)."""
    if not isinstance(url, str) or not url.startswith("data:"):
        return "", None
    header, _, payload = url.partition(",")
    if "base64" not in header:
        return "", None
    mime = header[len("data:") :].split(";")[0].strip()
    if not payload:
        return mime, None
    try:
        return mime, base64.b64decode(payload, validate=True)
    except Exception:
        return mime, None


def _to_data_url(raw: bytes, mime: str) -> str:
    return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"

# Hinweis an das Ziel-Modell, dass Platzhalter wie <PERSON_1>/<ADDRESS_0>
# bewusste Anonymisierung sind, kein Fehler. Ohne diesen Hinweis neigen
# manche Modelle dazu, Platzhalter als vermeintlichen Tippfehler zu behandeln
# und nachzufragen oder den Text "korrigieren" zu wollen -- das zerstoert
# sowohl die UX als auch (im schlimmsten Fall) die Platzhalter selbst, wenn
# das Modell sie in seiner Antwort umformuliert statt wortwoertlich
# zurueckzugeben (worauf die Re-Identifikation angewiesen ist).
#
# Live-Deploy-Befund (2026-07-29, preview-api-Livetest gegen gpt-4o-mini via
# eurouter.ai): eine fruehere Fassung enthielt ein konkretes Beispiel
# ("<PERSON_1> statt \"Hans Müller\""), um das Prinzip zu illustrieren.
# Ergebnis: das Modell griff den Beispielnamen als vermeintlich "echten Wert"
# auf und antwortete mit "Hallo Hans Müller!" -- obwohl der reid_map ein
# GANZ ANDERER Name zugrunde lag. Kein PII-Leck (der erfundene Name ist
# harmlos), aber eine kaputte, fuer den Nutzer verwirrende Antwort. Reproduziert
# mit UND ohne zusaetzliche eigene System-Message. Deshalb bewusst OHNE
# konkretes Namensbeispiel formuliert -- das Prinzip laesst sich abstrakt
# erklaeren, ohne dem Modell einen Namen zum Nachplappern anzubieten.
ANONYMIZATION_NOTICE = (
    "Hinweis: Dieser Text wurde vor der Übermittlung automatisch pseudonymisiert. "
    "Platzhalter wie <PERSON_1>, <ADDRESS_0>, <EMAIL_ADDRESS_0>, <DE_AKTENZEICHEN_0> "
    "usw. stehen bewusst anstelle der jeweils echten Werte (z. B. steht <PERSON_1> "
    "für einen echten Personennamen, <ADDRESS_0> für eine vollständige Adresse). Das ist "
    "kein Tippfehler und keine fehlende Information — behandle jeden Platzhalter "
    "als den echten Wert, den er ersetzt, und gib ihn in deiner Antwort exakt so "
    "zurück, wie er dir übergeben wurde (nicht umformulieren, nicht durch einen "
    "Beispielwert ersetzen, nicht danach fragen)."
)


class DatenschleuseBlocked(Exception):
    """Wird geworfen, wenn fail-closed greift. LiteLLM behandelt eine im
    pre_call-Hook geworfene Exception als Guardrail-Block -> Request wird
    NICHT ans LLM weitergereicht (kein unmaskiertes PII verlaesst das System)."""


# ===========================================================================
# Reine, framework-freie Logik (keine LiteLLM-/Presidio-Abhaengigkeit).
# Genau dieser Teil ist unit-testbar ohne laufenden Container.
# ===========================================================================
def reidentify_full(text: str, mapping: Dict[str, str]) -> str:
    """Ersetzt in ``text`` alle bekannten Platzhalter durch ihre Klartextwerte.

    Fuer den Non-Streaming-Fall: es gibt kein Chunking-Problem, also einfach
    global ersetzen. Laengste Platzhalter zuerst, damit ``<PERSON_1>`` nicht
    faelschlich INNERHALB von ``<PERSON_10>`` matcht.
    """
    if not mapping or not text:
        return text
    for placeholder in sorted(mapping, key=len, reverse=True):
        if placeholder in text:
            text = text.replace(placeholder, mapping[placeholder])
    return text


def _field_fingerprint(name: Any) -> str:
    """Stabiler, wertfreier Kurz-Fingerprint eines Feldnamens.

    Warum nicht einfach den Namen ausgeben: ein FELDNAME ist Client-Inhalt.
    ``{"Max Mustermann": ...}`` oder eine IBAN als Schluessel sind trivial
    konstruierbar -- und die Blockmeldung wird geloggt und an den Client
    zurueckgegeben. Der Fingerprint gibt dem Betreiber trotzdem eine
    Handhabe: derselbe Feldname ergibt denselben Wert, damit laesst sich ein
    blockendes Feld eingrenzen, ohne dass sein Inhalt das System verlaesst.
    """
    return hashlib.sha256(repr(name).encode("utf-8")).hexdigest()[:8]


class _UnsafeJson(Exception):
    """JSON, das zwar parst, aber nicht eindeutig ist -- und deshalb nicht
    zuverlaessig geprueft werden kann. Bewusst KEIN ValueError-Subtyp, damit
    es nicht versehentlich im Parser-Fallback landet."""


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """object_pairs_hook: lehnt doppelte JSON-Schluessel ab.

    ``json.loads`` behaelt bei doppelten Keys still den LETZTEN Wert. Der
    erste wird nie geparst, nie analysiert -- und wenn der Rest der Struktur
    sauber ist, ging der unveraenderte Rohstring hinaus, PII inklusive
    (Security-Audit F2). Doppelte Keys sind in echten Tool-Argumenten
    bedeutungslos und als Umgehung trivial zu konstruieren: blocken.
    """
    seen = set()
    for key, _ in pairs:
        if key in seen:
            # Gesetz 5: der Schluessel selbst ist Client-Inhalt -> nie ausgeben.
            raise _UnsafeJson("doppelter Schluessel in arguments")
        seen.add(key)
    return dict(pairs)


def _reject_json_constant(name: str) -> Any:
    """parse_constant: ``NaN``/``Infinity``/``-Infinity`` sind kein striktes
    JSON. Python parst sie klaglos und emittiert sie wieder -- Empfaenger mit
    striktem Parser bekommen dann kaputte Argumente (Security-Audit F8)."""
    raise _UnsafeJson("nicht-standardkonforme JSON-Konstante in arguments")


def json_escaped_mapping(mapping: Dict[str, str]) -> Dict[str, str]:
    """Baut aus dem reid_map ein Mapping, dessen WERTE bereits so escaped
    sind, wie sie INNERHALB eines JSON-Strings stehen muessen.

    Warum: auf dem Rueckweg wird ein Platzhalter in
    ``tool_calls[].function.arguments`` durch den Klartext ersetzt. Steht in
    diesem Klartext ein Anfuehrungszeichen oder Backslash (``Max "Maxi"
    Mustermann``), macht ein naives ``str.replace`` aus gueltigem JSON
    kaputtes JSON -- der Tool-Aufruf ist beim Client unbrauchbar. Deshalb
    wird der Wert vorher JSON-escaped (``json.dumps`` liefert ihn mit
    Anfuehrungszeichen, die beiden aeusseren fallen weg).
    """
    return {k: json.dumps(v, ensure_ascii=False)[1:-1] for k, v in (mapping or {}).items()}


def _reidentify_json_node(node: Any, mapping: Dict[str, str]) -> Any:
    """Ersetzt Platzhalter in allen Strings eines geparsten JSON-Baums
    (Werte UND Schluessel -- maskiert wurden beide, siehe Masking-Pfad)."""
    if isinstance(node, str):
        return reidentify_full(node, mapping)
    if isinstance(node, list):
        return [_reidentify_json_node(v, mapping) for v in node]
    if isinstance(node, dict):
        return {
            _reidentify_json_node(k, mapping): _reidentify_json_node(v, mapping)
            for k, v in node.items()
        }
    return node


def reidentify_json_arguments(raw: Any, mapping: Dict[str, str]) -> Any:
    """Re-Identification fuer einen ``arguments``-JSON-String.

    Strukturerhaltend: geparst, in den Strings ersetzt, wieder serialisiert.
    Damit uebernimmt ``json.dumps`` das Escaping und das Ergebnis ist garantiert
    wieder gueltiges JSON. Nur wenn ``raw`` gar kein gueltiges JSON ist (Modelle
    liefern gelegentlich kaputte ``arguments``), wird auf einen Textersatz mit
    JSON-escapten Werten zurueckgefallen -- die beste verfuegbare Naeherung fuer
    einen String, der JSON sein wollte.
    """
    if not mapping or not isinstance(raw, str) or not raw:
        return raw
    if not any(placeholder in raw for placeholder in mapping):
        # Kein Platzhalter enthalten -> nichts zu ersetzen. Wichtig, damit
        # PII-freie Tool-Aufrufe den Client BYTE-IDENTISCH erreichen und
        # nicht durch eine ueberfluessige Re-Serialisierung laufen.
        return raw
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return reidentify_full(raw, json_escaped_mapping(mapping))
    return json.dumps(_reidentify_json_node(parsed, mapping), ensure_ascii=False)


class Masker:
    """Baut aus Presidio-Analyzer-Ergebnissen den maskierten Text UND das
    eindeutige Platzhalter->Klartext-Mapping.

    Wird ueber mehrere Nachrichten hinweg wiederverwendet, damit derselbe
    Klartextwert (z.B. ein Name in System- UND User-Message) denselben
    Platzhalter bekommt und Platzhalter request-weit eindeutig sind.
    """

    def __init__(self) -> None:
        # Klartext-(Typ,Wert) -> Platzhalter, damit Duplikate denselben
        # Platzhalter teilen.
        self._value_to_placeholder: Dict[Tuple[str, str], str] = {}
        # Zaehler pro Entitaetstyp fuer die Durchnummerierung.
        self._counters: Dict[str, int] = {}
        # Ergebnis-Mapping Platzhalter -> Klartext (das, was gestreamt
        # re-identifiziert wird).
        self.reid_map: Dict[str, str] = {}

    def mask(self, text: str, entities: List[Dict[str, Any]]) -> str:
        """Maskiert ``text`` anhand der Analyzer-Entities und aktualisiert das
        Mapping. Gibt den maskierten Text zurueck.

        ``entities``: Liste von Dicts mit mindestens ``entity_type``, ``start``,
        ``end`` (Presidio-``/analyze``-Response-Format).
        """
        if not text or not entities:
            return text

        kept = self._resolve_overlaps(entities, len(text))

        # 1) Platzhalter vergeben in aufsteigender Startposition -> stabile,
        #    deterministische Nummerierung (<TYPE_0>, <TYPE_1>, ...).
        for ent in sorted(kept, key=lambda e: e["start"]):
            original = text[ent["start"]:ent["end"]]
            self._placeholder_for(ent["entity_type"], original)

        # 2) Ersetzen in ABSTEIGENDER Startposition, damit die Indizes der noch
        #    nicht ersetzten Spans gueltig bleiben.
        for ent in sorted(kept, key=lambda e: e["start"], reverse=True):
            original = text[ent["start"]:ent["end"]]
            placeholder = self._placeholder_for(ent["entity_type"], original)
            text = text[:ent["start"]] + placeholder + text[ent["end"]:]

        return text

    def _placeholder_for(self, entity_type: str, original: str) -> str:
        key = (entity_type, original)
        placeholder = self._value_to_placeholder.get(key)
        if placeholder is None:
            n = self._counters.get(entity_type, 0)
            placeholder = f"<{entity_type}_{n}>"
            self._counters[entity_type] = n + 1
            self._value_to_placeholder[key] = placeholder
            self.reid_map[placeholder] = original
        return placeholder

    @staticmethod
    def _resolve_overlaps(entities: List[Dict[str, Any]], text_len: int) -> List[Dict[str, Any]]:
        """Presidio kann ueberlappende Treffer liefern (z.B. PERSON und
        LOCATION auf demselben Span). Wir behalten pro Position den Treffer mit
        dem hoechsten Score und lassen ueberlappende, schwaechere fallen.
        """
        valid = [
            e for e in entities
            if isinstance(e.get("start"), int)
            and isinstance(e.get("end"), int)
            and 0 <= e["start"] < e["end"] <= text_len
            and e.get("entity_type")
        ]
        # Hoher Score zuerst, dann laengerer Span, dann fruehere Position.
        valid.sort(key=lambda e: (-float(e.get("score", 0.0)), -(e["end"] - e["start"]), e["start"]))
        kept: List[Dict[str, Any]] = []
        for e in valid:
            if any(not (e["end"] <= k["start"] or e["start"] >= k["end"]) for k in kept):
                continue  # ueberlappt einen bereits behaltenen, staerkeren Treffer
            kept.append(e)
        return kept


class ReidStreamProcessor:
    """Sliding-Window-Re-Identification fuer Streaming-Chunks.

    Problem: ein Platzhalter wie ``<PERSON_1>`` kann ueber zwei SSE-Chunks
    gesplittet ankommen (z.B. ``<PERS`` | ``ON_1>``). Wir duerfen keinen Text
    emittieren, der der ANFANG eines noch nicht vollstaendig angekommenen
    Platzhalters sein koennte.

    Loesung: wir puffern nur einen kleinen Tail. Fensterlaenge ``window`` =
    laengster bekannter Platzhalter + Sicherheitsmarge. Wir emittieren pro
    Chunk alles AUSSER den letzten ``window - 1`` Zeichen.

    Warum ``window - 1``? Der laengste Platzhalter hat ``max_len`` Zeichen. Ein
    Platzhalter, der NICHT vollstaendig im Puffer steht, hat weniger als
    ``max_len`` Zeichen -> sein Anfang liegt zwangslaeufig innerhalb der letzten
    ``max_len - 1`` Zeichen. Halten wir diese zurueck, kann nie ein
    Platzhalter-Anfang faelschlich als normaler Text emittiert werden. Die
    Marge (+10) ist defensiver Puffer gegen Off-by-one und kuenftig laengere
    Platzhalter — mehr zurueckzuhalten ist immer sicher, kostet nur minimal
    Latenz.
    """

    def __init__(self, mapping: Dict[str, str], margin: int = DEFAULT_PLACEHOLDER_MARGIN) -> None:
        self.mapping = mapping or {}
        # Laengste Platzhalter zuerst ersetzen (<PERSON_1> vs. <PERSON_10>).
        self._keys = sorted(self.mapping, key=len, reverse=True)
        max_len = max((len(k) for k in self.mapping), default=0)
        self.window = (max_len + margin) if max_len else 0
        self.buffer = ""

    def feed(self, delta: str) -> str:
        """Nimmt ein Text-Delta an und gibt den JETZT sicher emittierbaren Text
        zurueck (kann leer sein)."""
        if not self.mapping:
            # Keine Platzhalter -> nichts zu re-identifizieren, unveraendert und
            # ungepuffert durchreichen (voller Streaming-Speed).
            return delta or ""
        if delta:
            self.buffer += delta
        self.buffer = self._replace_complete(self.buffer)

        hold = self.window - 1  # potenzieller Platzhalter-Anfang -> zurueckhalten
        if len(self.buffer) > hold:
            cut = len(self.buffer) - hold
            emit, self.buffer = self.buffer[:cut], self.buffer[cut:]
            return emit
        return ""

    def flush(self) -> str:
        """Am Stream-Ende: kompletten Rest-Puffer (final ersetzt) ausgeben,
        damit kein Text verloren geht — auch wenn er kuerzer als das Fenster
        ist."""
        rest = self._replace_complete(self.buffer)
        self.buffer = ""
        return rest

    def _replace_complete(self, s: str) -> str:
        for k in self._keys:
            if k in s:
                s = s.replace(k, self.mapping[k])
        return s


# ===========================================================================
# LiteLLM-Adapter: verbindet die reine Logik oben mit den LiteLLM-Hooks.
# ===========================================================================
class DatenschleuseGuardrail(_GuardrailBase):
    """Custom Guardrail: maskiert PII vor dem LLM (pre_call) und
    re-identifiziert die Antwort streaming-sicher (post_call)."""

    def __init__(
        self,
        presidio_analyzer_url: Optional[str] = None,
        language: str = "de",
        score_threshold: float = 0.0,
        placeholder_margin: int = DEFAULT_PLACEHOLDER_MARGIN,
        request_timeout: float = 10.0,
        image_redactor_url: Optional[str] = None,
        image_policy: Optional[str] = None,
        qi_risk_preset: Optional[str] = None,
        qi_state_key: Optional[str] = None,
        qi_state_db: Optional[str] = None,
        qi_state_ttl_seconds: Optional[int] = None,
        qi_store: Any = None,
        **kwargs: Any,
    ) -> None:
        # Analyzer-URL: Prioritaet Argument > ENV > Docker-Default.
        self.analyzer_url = (
            presidio_analyzer_url
            or os.getenv("PRESIDIO_ANALYZER_API_BASE")
            or "http://presidio-analyzer:3000"
        ).rstrip("/")
        # Manche Config-/ENV-Wege liefern die Werte via kwargs nach — defensiv.
        self.language = kwargs.pop("presidio_language", None) or language
        self.score_threshold = float(kwargs.pop("presidio_score_threshold", score_threshold) or 0.0)
        self.placeholder_margin = int(placeholder_margin)
        self.request_timeout = float(request_timeout)

        # --- Bild-Parts (multimodal) ----------------------------------------
        # Text war nie das ganze Problem: ein Screenshot mit derselben Adresse
        # drauf lief bis hierher unveraendert zum Modell, weil unten nur
        # ``type == "text"``-Parts maskiert werden. Presidio kann Bilder
        # schwaerzen (OCR + Boxen), das laeuft aber in einem EIGENEN Dienst
        # (microsoft/presidio-image-redactor, POST /redact).
        #
        # Policy statt stillem Default, weil beide Enden gefaehrlich sind: ohne
        # Redactor-Container waere "durchlassen" ein stilles Leck und "blocken"
        # ein hartes Verhaltensbruch. Deshalb explizit:
        #   redact = schwaerzen, Fehler => Block (empfohlen, braucht den Dienst)
        #   block  = Bilder grundsaetzlich ablehnen (sicher ohne Extra-Dienst)
        #   pass   = altes Verhalten, Bilder gehen UNGEPRUEFT raus (bewusste Luecke)
        self.image_redactor_url = (
            image_redactor_url
            or kwargs.pop("presidio_image_redactor_url", None)
            or os.getenv("PRESIDIO_IMAGE_REDACTOR_API_BASE")
            or ""
        ).rstrip("/")
        policy = (kwargs.pop("image_policy", None) or image_policy or os.getenv("DATENSCHLEUSE_IMAGE_POLICY") or "").strip().lower()
        if not policy:
            # Kein expliziter Wunsch: mit Dienst schwaerzen, ohne Dienst
            # ablehnen. Nie stillschweigend durchlassen — das war die Luecke.
            policy = "redact" if self.image_redactor_url else "block"
        if policy not in IMAGE_POLICIES:
            raise ValueError(
                f"image_policy={policy!r} unbekannt — erlaubt: {', '.join(sorted(IMAGE_POLICIES))}"
            )
        if policy == "redact" and not self.image_redactor_url:
            raise ValueError(
                "image_policy='redact' ohne image_redactor_url/"
                "PRESIDIO_IMAGE_REDACTOR_API_BASE — der Dienst muss erreichbar "
                "konfiguriert sein, sonst waere jedes Bild ein Blindflug."
            )
        self.image_policy = policy

        # --- Schutzklassen-Modell (IMMER aktiv, keine Konfigurationsoption) --
        # Laedt presidio/sensitivity-keywords.yml einmalig. Fail-closed beim
        # START: eine kaputte/fehlende Config wirft SensitivityConfigError und
        # verhindert, dass der Guardrail (und damit der ganze Proxy) ueberhaupt
        # hochkommt -- blind klassifizieren waere gefaehrlicher als nicht
        # starten. Siehe docs/SENSITIVITY-INTEGRATION.md.
        self.classifier = sc.SensitivityClassifier()

        # --- Quasi-Identifier-Layer (opt-in) --------------------------------
        # Aktiv, sobald ein Risiko-Preset gesetzt ist (Config: qi_risk_preset).
        # Ist es None/"off", bleibt der QI-Layer komplett aus -> Verhalten exakt
        # wie bisher (wichtig: bestehende Tests konstruieren die Guardrail ohne
        # Preset und brauchen daher KEINEN State-Key).
        self.qi_risk_preset = kwargs.pop("qi_risk_preset", None) or qi_risk_preset
        self.qi_enabled = bool(
            self.qi_risk_preset and str(self.qi_risk_preset).strip().lower() != "off"
        )
        self.qi_threshold = qig.threshold_for_preset(self.qi_risk_preset)
        self._qi_store = None
        if self.qi_enabled:
            if qi_store is not None:
                # Test-/DI-Pfad: fertigen Store injizieren.
                self._qi_store = qi_store
            else:
                # Produktionspfad: verschluesselten TTL-Store bauen. Fehlt der
                # Schluessel, wirft QiStateStore beim Konstruieren -> fail-closed
                # beim START (kein unverschluesselter Weiterbetrieb). qi_state
                # wird LAZY importiert, damit dieses Modul ohne cryptography
                # importierbar bleibt, solange der QI-Layer aus ist.
                import qi_state as qs

                ttl = (
                    int(qi_state_ttl_seconds)
                    if qi_state_ttl_seconds is not None
                    else int(os.getenv("DATENSCHLEUSE_STATE_TTL_SECONDS", qs.DEFAULT_TTL_SECONDS))
                )
                self._qi_store = qs.QiStateStore(
                    db_path=qi_state_db or os.getenv("DATENSCHLEUSE_STATE_DB"),
                    fernet_key=qi_state_key or os.getenv("DATENSCHLEUSE_STATE_KEY"),
                    ttl_seconds=ttl,
                )
        super().__init__(**kwargs)

    # ---- Presidio Analyzer (echte externe Abhaengigkeit) ------------------
    async def _analyze(self, text: str) -> List[Dict[str, Any]]:
        """Ruft Presidio Analyzer ``/analyze`` auf. Fail-closed: jeder Fehler
        (Netzwerk, HTTP >= 400, ungueltige Antwort) wird zu DatenschleuseBlocked
        eskaliert, damit KEIN unmaskierter Text durchgeht."""
        if not text or not text.strip():
            return []
        payload: Dict[str, Any] = {"text": text, "language": self.language}
        if self.score_threshold > 0:
            payload["score_threshold"] = self.score_threshold
        try:
            async with httpx.AsyncClient(timeout=self.request_timeout) as client:
                resp = await client.post(f"{self.analyzer_url}/analyze", json=payload)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, list):
                raise ValueError(f"unerwartete Analyzer-Antwort: {type(data)!r}")
            return data
        except DatenschleuseBlocked:
            raise
        except Exception as exc:  # fail-closed
            raise DatenschleuseBlocked(
                f"Presidio Analyzer nicht erreichbar/fehlerhaft ({exc}); "
                f"Request blockiert (fail-closed, kein unmaskiertes PII)."
            ) from exc

    # ---- Presidio Image Redactor (Bild-Parts) -----------------------------
    async def _redact_image(self, data_url: str) -> str:
        """Schickt ein ``data:``-Bild durch ``POST /redact`` und gibt die
        geschwaerzte Fassung als neue ``data:``-URL zurueck.

        Fail-closed wie ``_analyze``: jeder Fehler wird zu DatenschleuseBlocked,
        damit nie ein ungepruefres Bild durchrutscht.

        GRENZE, die man kennen muss: Der Image-Redactor bringt seine EIGENE
        Presidio-Instanz mit und kennt deshalb die deutschen Custom-Recognizer
        aus presidio/recognizers-config.yml NICHT. Im Bild werden also die
        eingebauten Typen erkannt (Namen, E-Mail, Telefon, IBAN, ...), aber
        z.B. ein deutsches Aktenzeichen nicht zwingend. Das ist der Grund,
        warum 'block' fuer sensible Setups die ehrlichere Wahl bleibt.
        """
        mime, raw = _split_data_url(data_url)
        if raw is None:
            # _split_data_url liefert (mime, None) in DREI unterschiedlichen
            # Faellen, die je eine zutreffende Meldung verdienen (kein
            # Bildinhalt/Base64-Fragment in der Meldung -- Gesetz 5). mime
            # allein reicht NICHT als Unterscheidungsmerkmal (nur binaer),
            # deshalb zusaetzlich pruefen, ob nach dem Komma ueberhaupt ein
            # Payload vorlag -- ohne dessen Inhalt in die Meldung zu uebernehmen:
            # - mime leer: es war ueberhaupt keine ``data:``-URL (z.B. eine
            #   externe http/https-URL), die das Modell serverseitig abrufen
            #   wuerde -- also am Proxy vorbei.
            # - mime gesetzt, kein Payload nach dem Komma: eine eingebettete
            #   data:-URL ohne jeden Bildinhalt (leeres Base64-Feld).
            # - mime gesetzt, Payload vorhanden: der data:-Header wurde
            #   erkannt, aber das Base64-Payload liess sich nicht dekodieren
            #   (kaputte/beschaedigte Daten).
            if not mime:
                raise DatenschleuseBlocked(
                    "Bild-Part verweist auf eine externe URL statt auf eingebettete "
                    "Daten; der Inhalt kann nicht geprueft werden (fail-closed)."
                )
            payload = data_url.partition(",")[2] if isinstance(data_url, str) else ""
            if not payload:
                raise DatenschleuseBlocked(
                    "Bild-Part ist eine eingebettete data:-URL ohne Payload "
                    "(leeres Base64-Feld); der Inhalt kann nicht geprueft "
                    "werden (fail-closed)."
                )
            raise DatenschleuseBlocked(
                "Bild-Part enthaelt eine data:-URL mit ungueltigem oder "
                "beschaedigtem Base64-Payload; der Inhalt kann nicht "
                "dekodiert werden (fail-closed)."
            )
        try:
            files = {"image": ("upload", raw, mime or "application/octet-stream")}
            async with httpx.AsyncClient(timeout=self.request_timeout) as client:
                resp = await client.post(
                    f"{self.image_redactor_url}/redact",
                    files=files,
                    data={"data": '{"color_fill": "0"}'},
                )
            resp.raise_for_status()
            redacted = resp.content
            if not redacted:
                raise ValueError("leere Antwort vom Image-Redactor")
        except DatenschleuseBlocked:
            raise
        except Exception as exc:  # fail-closed
            raise DatenschleuseBlocked(
                f"Presidio Image Redactor nicht erreichbar/fehlerhaft ({exc}); "
                f"Request blockiert (fail-closed, kein ungeprueftes Bild)."
            ) from exc
        return _to_data_url(redacted, mime or "image/png")

    async def _handle_image_part(self, part: Dict[str, Any]) -> None:
        """Wendet die konfigurierte Bild-Policy auf einen ``image_url``-Part an.
        Mutiert den Part in-place (wie der Text-Pfad auch)."""
        if self.image_policy == "pass":
            return
        if self.image_policy == "block":
            raise DatenschleuseBlocked(
                "Bild-Anhaenge sind blockiert (image_policy='block'). Die "
                "Datenschleuse maskiert Text; Bilder muessten geschwaerzt "
                "werden, wofuer der Image-Redactor-Dienst noetig ist."
            )
        url = _image_part_url(part)
        if not url:
            raise DatenschleuseBlocked(
                "Bild-Part ohne lesbare URL — Inhalt nicht pruefbar (fail-closed)."
            )
        redacted = await self._redact_image(url)
        target = part.get("image_url")
        if isinstance(target, dict):
            target["url"] = redacted
        else:
            part["image_url"] = redacted

    # ---- Pre-Call: PII maskieren ------------------------------------------
    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict:
        """Maskiert PII in allen Chat-Messages und legt das Re-Id-Mapping in
        den Metadaten ab. Nur fuer Chat-/Text-Completions relevant."""
        if call_type not in ("completion", "text_completion", "acompletion", None):
            return data

        messages = data.get("messages")
        masker = Masker()

        # --- Schutzklassen: Metadaten fuer explizite Stufe + Freigabe-Flag ---
        meta_in = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        requested_level = meta_in.get(sc.SENSITIVITY_LEVEL_KEY)
        approved = sc.is_release_approved(meta_in)

        # QI-Typen werden nur dann aus der direkten Maskierung herausgehalten,
        # wenn der QI-Layer aktiv ist. Sonst laufen sie wie jeder andere
        # erkannte Identifier durch den Masker (harmloser Platzhalter-Roundtrip).
        qi_types = qig.QI_ENTITY_TYPES if self.qi_enabled else frozenset()

        # Ueber ALLE Messages des Requests gesammelte QI-Instanzen dieses Turns
        # (Typ, Rohwert) + die Text-Slots, in denen sie ggf. generalisiert werden.
        turn_qi: List[Tuple[str, str]] = []
        text_slots: List[Tuple[Any, Any]] = []  # (container, key) auf maskierten Text

        # Der messages-Container selbst (DATENSCHLE-66): ist ``messages``
        # vorhanden, aber keine Liste, lief der Request bisher komplett
        # ungeprueft durch -- die Schleife wurde einfach nicht betreten.
        # Dieselbe Bauart wie die content-Container-Luecke (DATENSCHLE-64).
        # Fehlt der Key ganz (None), ist das kein Chat-Request -> unveraendert.
        if messages is not None and not isinstance(messages, list):
            raise DatenschleuseBlocked(
                f"messages vom Typ {type(messages).__name__!r} wird von der "
                "Datenschleuse nicht geprueft und ist deshalb blockiert "
                "(fail-closed). Erlaubt ist nur eine Liste von Nachrichten."
            )

        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    # Bisher: stillschweigend uebersprungen -- also ungeprueft
                    # ans Modell weitergereicht. Was nicht geprueft werden
                    # kann, passiert nicht (Gesetz: fail-closed).
                    raise DatenschleuseBlocked(
                        f"Nachricht vom Typ {type(msg).__name__!r} wird von der "
                        "Datenschleuse nicht geprueft und ist deshalb blockiert "
                        "(fail-closed). Erlaubt sind nur Nachrichten-Objekte."
                    )

                # Form-Pruefung VOR jeder Verarbeitung: unbekannte Felder,
                # fremde Rollen und Nicht-Identifier in ID-Feldern blocken,
                # bevor ueberhaupt ein Analyzer-Call passiert.
                self._validate_message_shape(msg)

                content = msg.get("content")
                if isinstance(content, str):
                    original = content
                    entities = await self._analyze(original)

                    # Schutzklassen: klassifizieren BEVOR irgendetwas maskiert
                    # oder Richtung Cloud aufbereitet wird. Stufe 3 blockt hart
                    # (kein Bypass), Stufe 2 ohne Freigabe blockt ebenfalls.
                    classification = self.classifier.classify(
                        original, entities=entities, requested_level=requested_level,
                    )
                    try:
                        sc.enforce_tier_3_block(classification)
                        sc.enforce_tier_2_gate(classification, approved)
                    except (sc.Tier3Blocked, sc.Tier2ApprovalRequired) as exc:
                        raise DatenschleuseBlocked(str(exc)) from exc

                    direct, qi = self._split_entities(entities, qi_types)
                    msg["content"] = masker.mask(original, direct)
                    # QI-Rohwerte aus dem ORIGINAL (vor Maskierung) ziehen.
                    turn_qi.extend(self._extract_qi_values(original, qi))
                    text_slots.append((msg, "content"))
                elif isinstance(content, list):
                    # Multimodal: Text-Parts maskieren, Bild-Parts nach Policy
                    # schwaerzen/blocken (frueher liefen sie hier unveraendert
                    # durch — genau das war die Luecke). ALLES ANDERE wird
                    # blockiert (Allowlist statt Denylist, DATENSCHLE-57):
                    # ``file``-Parts (hochgeladene PDFs/Dokumente),
                    # ``input_audio``, Parts ohne ``type``-Feld und jeder der
                    # Guardrail unbekannte/kuenftige Typ liefen bislang
                    # ungeprueft durch. Statt jeden bekannten unsicheren Typ
                    # einzeln aufzuzaehlen, gilt: nur was hier explizit als
                    # geprueft-und-sicher erkannt wird, passiert -- alles
                    # Uebrige blockt fail-closed, auch ein Part-Typ, den die
                    # OpenAI-API erst morgen einfuehrt.
                    for part in content:
                        # DATENSCHLE-65: Typ UND Felder in EINEM Schritt, im
                        # Validate-Pfad, fail-closed -- bevor irgendein Wert
                        # dieses Parts verarbeitet oder weitergereicht wird.
                        # Danach ist garantiert: Typ ist erlaubt, jedes Feld
                        # steht im Register, jedes Feld hat den richtigen Typ.
                        part_type = self._validate_part_shape(part)
                        if part_type == "image_url":
                            await self._handle_image_part(part)
                            continue
                        if part_type == "text":
                            # Nach _validate_part_shape garantiert ein String
                            # -- KEIN isinstance-Guard mehr an dieser Stelle,
                            # der waere wieder ein stiller Durchlass (F1).
                            original = part["text"]
                            entities = await self._analyze(original)

                            classification = self.classifier.classify(
                                original, entities=entities, requested_level=requested_level,
                            )
                            try:
                                sc.enforce_tier_3_block(classification)
                                sc.enforce_tier_2_gate(classification, approved)
                            except (sc.Tier3Blocked, sc.Tier2ApprovalRequired) as exc:
                                raise DatenschleuseBlocked(str(exc)) from exc

                            direct, qi = self._split_entities(entities, qi_types)
                            part["text"] = masker.mask(original, direct)
                            turn_qi.extend(self._extract_qi_values(original, qi))
                            text_slots.append((part, "text"))
                            # Zitate desselben Parts: Freitext maskieren,
                            # Indizes unangetastet lassen (DATENSCHLE-65).
                            # DERSELBE Masker wie der Textpfad -- ein
                            # zweites Mapping wuerde die Re-Identifikation
                            # auf dem Rueckweg ins Leere laufen lassen.
                            await self._mask_citations(
                                part, masker, requested_level, approved,
                            )
                            continue
                        # Unerreichbar, solange Register und Verarbeitung
                        # zusammenpassen: _validate_part_shape hat jeden
                        # anderen Typ bereits geblockt. Der Zweig bleibt als
                        # fail-closed-Netz fuer den Fall, dass jemand einen
                        # Typ ins Register eintraegt, ohne ihn hier zu
                        # behandeln -- dann blockt er, statt ungeprueft
                        # durchzulaufen. Genau diese Sorte Luecke ist die
                        # Geschichte dieses Guardrails (DATENSCHLE-57/64/65/66).
                        raise DatenschleuseBlocked(  # pragma: no cover
                            "Content-Part-Typ ist im Register erfasst, hat "
                            "aber keinen Verarbeitungspfad -- blockiert "
                            "(fail-closed)."
                        )
                elif content is not None:
                    # DATENSCHLE-64 (QA-Folgefund zu DATENSCHLE-57): dieselbe
                    # Luecke wie bei den Parts, nur eine Ebene hoeher. Ein
                    # einzelner Content-Part als dict OHNE umschliessende
                    # Liste -- z.B. {"type": "text", "text": "..."} statt
                    # [{"type": "text", "text": "..."}] -- ist weder
                    # isinstance(content, str) noch isinstance(content, list)
                    # und lief bislang komplett ungeprueft durch (kein
                    # Maskieren, kein Block). Ebenso jede andere Form (Zahl,
                    # bool, ...). Konsequente Allowlist wie bei den Parts: nur
                    # String und Liste sind als pruefbar erkannt, der Rest
                    # blockt fail-closed.
                    #
                    # AUSNAHME, nach erstem Security-Review korrigiert:
                    # content is None (bzw. ein fehlender content-Key, liefert
                    # ueber msg.get() ebenfalls None) ist KEIN Bypass, sondern
                    # spezifikationsgemaess legitim -- eine Assistant-Message
                    # mit ``tool_calls`` hat im OpenAI-Format kein content.
                    # Es gibt dort nichts zu maskieren oder zu leaken; ein
                    # Block wuerde Tool-Calling komplett brechen, ein
                    # normales, spezifiziertes Nutzungsmuster. Deshalb
                    # ``elif content is not None`` statt ``else`` -- None
                    # faellt durch und bleibt unveraendert.
                    #
                    # type(content).__name__ ist ein kurzer, konstant
                    # harmloser Typname -- nie der Wert selbst -- in der
                    # Meldung (Gesetz 5; siehe auch die Korrektur der
                    # Part-Fehlermeldung weiter oben, DATENSCHLE-64 zweites
                    # Finding).
                    raise DatenschleuseBlocked(
                        f"Nachricht mit content vom Typ "
                        f"{type(content).__name__!r} wird von der "
                        "Datenschleuse nicht geprueft und ist deshalb "
                        "blockiert (fail-closed). Erlaubt sind nur String- "
                        "oder Listen-content."
                    )

                # --- Alle uebrigen Textfelder der Message (DATENSCHLE-66) ---
                # content war nie das ganze Problem: fuer agentische Clients
                # ist ``tool_calls[].function.arguments`` der Normalbetrieb,
                # und genau dort stehen regelmaessig Kundendaten.
                await self._mask_message_fields(msg, masker, requested_level, approved)

        # Mapping im EIGENEN Metadata-Key ablegen (nicht LiteLLMs Interna).
        metadata = data.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
            data["metadata"] = metadata
        metadata[REID_MAP_KEY] = masker.reid_map

        # Anonymisierungs-Hinweis nur einfuegen, wenn tatsaechlich etwas
        # maskiert wurde (kein Overhead fuer PII-freie Requests) -- und nur
        # dann, wenn messages ueberhaupt eine Liste ist (defensiv, s.o.).
        if masker.reid_map and isinstance(messages, list):
            self._inject_anonymization_notice(messages)

        # --- QI-Layer: Akkumulation ueber die Session + Generalisierung -------
        # WICHTIG (fail-Semantik): ein Fehler im QI-Layer darf die bereits
        # erfolgte direkte-PII-Maskierung NICHT zunichte machen und den Request
        # NICHT blocken (anders als die Presidio-Erreichbarkeit, die hart
        # fail-closed ist). Deshalb defensiv abfangen + loggen.
        if self.qi_enabled and self._qi_store is not None and turn_qi:
            try:
                self._process_qi(data, user_api_key_dict, turn_qi, text_slots)
            except Exception as exc:  # pragma: no cover - defensiv
                print(
                    f"[datenschleuse] QI-Layer-Fehler ignoriert (direkte Maskierung "
                    f"bleibt aktiv, Request nicht geblockt): {exc}",
                    flush=True,
                )

        return data

    # ---- Message-Felder jenseits von content (DATENSCHLE-66) --------------
    @staticmethod
    def _validate_message_shape(msg: Dict[str, Any]) -> None:
        """Prueft die FORM einer Message gegen das Feld-Register.

        Konsequente Allowlist wie auf Part- und Container-Ebene: jedes Feld,
        das die Guardrail nicht kennt, ist ein Kanal, dessen Inhalt niemand
        geprueft hat -> fail-closed blocken. Damit erzwingt ein neues Feld der
        OpenAI-API eine bewusste Entscheidung im Register, statt still ein Leck
        zu oeffnen.

        Gesetz 5: in keiner Meldung stehen Client-Werte -- auch ein FELDNAME
        ist Client-Inhalt (eine IBAN als Feldname ist trivial konstruierbar).
        Ausgegeben werden nur Anzahl, Python-Typname und die konstante Liste
        der erlaubten Felder.
        """
        unknown = [key for key in msg if key not in ALLOWED_MESSAGE_FIELDS]
        if unknown:
            # QA-Audit: ein Betreiber sah bisher nur eine ANZAHL und hatte
            # keine Chance herauszufinden, was ihn blockiert -- ausser
            # Trial-and-Error gegen die Allowlist. Jetzt: bekannte
            # Provider-Felder beim Namen (konstantes Vokabular aus DIESER
            # Datei, nie aus dem Request), alles Uebrige als Fingerprint.
            benannt = sorted(
                key for key in unknown
                if isinstance(key, str) and key in KNOWN_UNSUPPORTED_MESSAGE_FIELDS
            )
            fremd = [key for key in unknown if key not in benannt]
            teile = []
            if benannt:
                teile.append(
                    "bekannt, aber nicht im Register: " + ", ".join(benannt)
                )
            if fremd:
                teile.append(
                    "unbekannt (Fingerprint): "
                    + ", ".join(sorted(_field_fingerprint(k) for k in fremd))
                )
            diagnose = "; ".join(teile)
            _LOG.warning(
                "Nachricht blockiert -- ungepruefte Felder [%s]. "
                "Werte werden bewusst nicht geloggt (Gesetz 5).", diagnose,
            )
            raise DatenschleuseBlocked(
                f"Nachricht enthaelt {len(unknown)} Feld(er), die die "
                f"Datenschleuse nicht prueft ({diagnose}) -- deshalb blockiert "
                f"(fail-closed). Geprueft werden ausschliesslich: "
                f"{_ALLOWED_FIELDS_HINT}."
            )

        role = msg.get("role")
        if role is not None and (not isinstance(role, str) or role not in ALLOWED_ROLES):
            raise DatenschleuseBlocked(
                f"Nachricht mit unbekannter Rolle (Typ {type(role).__name__!r}) "
                "wird von der Datenschleuse nicht geprueft und ist deshalb "
                f"blockiert (fail-closed). Erlaubt: {', '.join(sorted(ALLOWED_ROLES))}."
            )

        # F1 (Security-Audit): das Register blockte bisher unbekannte FELDER,
        # aber nicht den falschen TYP in einem bekannten Feld. Die Masker-Pfade
        # waren durchweg ``if isinstance(..., str)`` -- ein dict in ``name``
        # oder ``refusal`` fiel damit STILL durch und ging verbatim ans
        # Zielmodell. Genau das Muster, das dieses Register beenden soll.
        # Lehre: ein isinstance-Guard im Mask-Pfad ist immer ein stiller
        # Durchlass. Die Typpruefung gehoert hierher und muss blocken.
        for field in ("name", "refusal", "reasoning_content"):
            DatenschleuseGuardrail._validate_text_field(msg.get(field), field)

        DatenschleuseGuardrail._validate_cache_control(msg.get("cache_control"))

        DatenschleuseGuardrail._validate_opaque_id(msg.get("tool_call_id"), "tool_call_id")

        tool_calls = msg.get("tool_calls")
        if tool_calls is not None:
            if not isinstance(tool_calls, list):
                raise DatenschleuseBlocked(
                    f"tool_calls vom Typ {type(tool_calls).__name__!r} ist nicht "
                    "pruefbar und deshalb blockiert (fail-closed). Erlaubt ist "
                    "nur eine Liste."
                )
            for call in tool_calls:
                DatenschleuseGuardrail._validate_tool_call(call)

        function_call = msg.get("function_call")
        if function_call is not None:
            DatenschleuseGuardrail._validate_function_payload(function_call, "function_call")

    # ---- Content-Parts: Typ UND Felder (DATENSCHLE-65) --------------------
    @staticmethod
    def _validate_part_shape(part: Any) -> str:
        """Prueft die FORM eines Content-Parts gegen das Part-Feld-Register
        und liefert den geprueften Part-Typ zurueck.

        Bis DATENSCHLE-65 endete die Pruefung beim Part-TYP: ein Part mit
        erlaubtem Typ durfte beliebige Zusatzfelder tragen, und die gingen
        unveraendert ans Modell. Dieselbe Bauart wie auf Message-Ebene, eine
        Ebene tiefer -- deshalb hier dieselbe Konsequenz: Allowlist, alles
        Uebrige blockt fail-closed.

        Wichtig (Kriterium 4, Lehre aus Security-Audit F1 auf Message-Ebene):
        die Typpruefung der Felder gehoert HIERHER und muss blocken. Ein
        ``if isinstance(part.get("text"), str)`` im Verarbeitungspfad ist
        immer ein stiller Durchlass -- der Nicht-String faellt einfach durch.

        Gesetz 5: keine Meldung enthaelt Client-Werte -- auch ein FELDNAME
        ist Client-Inhalt (eine IBAN als Schluessel ist trivial). Ausgegeben
        werden nur Anzahl, Python-Typname, Fingerprint und konstante Listen.
        """
        if not isinstance(part, dict):
            raise DatenschleuseBlocked(
                f"Content-Part vom Typ {type(part).__name__!r} ist nicht "
                "pruefbar und deshalb blockiert (fail-closed). Erlaubt sind "
                "nur Part-Objekte."
            )

        part_type = part.get("type")
        if not isinstance(part_type, str) or part_type not in ALLOWED_PART_TYPES:
            if (
                isinstance(part_type, str)
                and part_type in KNOWN_UNSUPPORTED_PART_TYPES
            ):
                # Der ausgegebene Name ist unsere Konstante (der Vergleich
                # erzwingt Gleichheit), nicht der Request -- kein
                # Client-Wert, keine unbegrenzte Laenge.
                grund = (
                    f"Content-Part-Typ '{part_type}' gehoert zu Anthropics "
                    "nativem Web-Search-Tool und hat in der Datenschleuse "
                    "keinen geprueften Pfad"
                )
                hinweis = (
                    " Bekannte, akzeptierte Einschraenkung, kein Fehler "
                    "dieser Anfrage: Multi-Turn mit Anthropics Web-Search "
                    "funktioniert durch diese Datenschleuse nicht. "
                    f"Begruendung in {_WEB_SEARCH_LIMITATION_DOC}."
                )
            else:
                # part_type ist voll client-kontrolliert (beliebiger Inhalt,
                # beliebiger Typ, beliebige Laenge) und darf deshalb NIE roh
                # in die Meldung -- nur sein Python-Typname (DATENSCHLE-64,
                # zweites Security-Finding).
                grund = (
                    "Content-Part mit nicht erlaubtem Typ "
                    f"({type(part_type).__name__}) wird von der "
                    "Datenschleuse nicht geprueft"
                )
                hinweis = ""
            raise DatenschleuseBlocked(
                f"{grund} -- blockiert (fail-closed).{hinweis} "
                f"Erlaubt sind nur: {_ALLOWED_PART_TYPES_HINT}."
            )

        allowed = ALLOWED_PART_FIELDS[part_type]
        unknown = [key for key in part if key not in allowed]
        if unknown:
            benannt = sorted(
                key for key in unknown
                if isinstance(key, str) and key in KNOWN_UNSUPPORTED_PART_FIELDS
            )
            fremd = [key for key in unknown if key not in benannt]
            teile = []
            if benannt:
                teile.append("bekannt, aber nicht im Register: " + ", ".join(benannt))
            if fremd:
                teile.append(
                    "unbekannt (Fingerprint): "
                    + ", ".join(sorted(_field_fingerprint(k) for k in fremd))
                )
            diagnose = "; ".join(teile)
            _LOG.warning(
                "Content-Part blockiert -- ungepruefte Felder [%s]. "
                "Werte werden bewusst nicht geloggt (Gesetz 5).", diagnose,
            )
            raise DatenschleuseBlocked(
                f"Content-Part enthaelt {len(unknown)} Feld(er), die die "
                f"Datenschleuse nicht prueft ({diagnose}) -- deshalb blockiert "
                f"(fail-closed). Geprueft werden ausschliesslich: "
                f"{_ALLOWED_PART_FIELDS_HINT[part_type]}."
            )

        DatenschleuseGuardrail._validate_cache_control(part.get("cache_control"))

        if part_type == "text":
            text = part.get("text")
            # Kein ``_validate_text_field`` allein: das laesst None zu. Ein
            # Text-Part OHNE ``text`` hat keine pruefbare Nutzlast und ist
            # nicht spezifikationskonform -- fail-closed statt Leerlauf.
            DatenschleuseGuardrail._validate_text_field(text, "content-part.text")
            if text is None:
                raise DatenschleuseBlocked(
                    "Content-Part vom Typ 'text' ohne text-Feld hat keine "
                    "pruefbare Nutzlast und ist deshalb blockiert "
                    "(fail-closed)."
                )
            DatenschleuseGuardrail._validate_citations(part.get("citations"))
        else:
            DatenschleuseGuardrail._validate_image_url_container(part.get("image_url"))

        return part_type

    @staticmethod
    def _validate_image_url_container(value: Any) -> None:
        """Der ``image_url``-Container ist client-kontrolliert wie der Part
        selbst -- und ``_handle_image_part`` ersetzt ausschliesslich ``url``.
        Jedes weitere Feld ueberlebte die Bild-Policy bisher unveraendert
        (bei ``image_policy='pass'`` ohnehin). Deshalb dieselbe Allowlist
        eine Ebene tiefer.

        Die Bild-POLICY bleibt davon unberuehrt: was mit einem gueltigen Bild
        passiert (redact/block/pass), entscheidet weiterhin allein
        ``_handle_image_part``.
        """
        if value is None:
            # Ein Bild-Part ohne URL blockt weiter unten in _handle_image_part
            # mit der praeziseren Meldung -- hier nicht doppelt behandeln.
            return
        if isinstance(value, str):
            # Manche Clients schicken die URL direkt statt im Container.
            return
        if not isinstance(value, dict):
            raise DatenschleuseBlocked(
                f"image_url vom Typ {type(value).__name__!r} ist kein "
                "Bild-Verweis -- blockiert (fail-closed). Erlaubt ist ein "
                "String oder ein Objekt wie {'url': '...'}."
            )
        unknown = sum(1 for key in value if key not in IMAGE_URL_ALLOWED_FIELDS)
        if unknown:
            raise DatenschleuseBlocked(
                f"image_url enthaelt {unknown} ungepruefte(s) Feld(er) -- "
                "blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(IMAGE_URL_ALLOWED_FIELDS))}."
            )
        DatenschleuseGuardrail._validate_text_field(value.get("url"), "image_url.url")
        detail = value.get("detail")
        if detail is not None and (
            not isinstance(detail, str) or detail not in IMAGE_URL_DETAILS
        ):
            raise DatenschleuseBlocked(
                f"image_url.detail (Typ {type(detail).__name__!r}) ist kein "
                "bekannter Wert -- als Freitext-Kanal blockiert (fail-closed). "
                f"Erlaubt: {', '.join(sorted(IMAGE_URL_DETAILS))}."
            )

    @staticmethod
    def _validate_text_field(value: Any, field: str) -> None:
        """Ein Textfeld ist ein String oder gar nicht da. Alles andere ist
        nicht maskierbar -> blocken statt still durchreichen."""
        if value is None or isinstance(value, str):
            return
        raise DatenschleuseBlocked(
            f"{field} vom Typ {type(value).__name__!r} ist kein Text und damit "
            "nicht maskierbar -- blockiert (fail-closed). Erlaubt ist nur ein "
            "String (oder das Feld ganz weglassen)."
        )

    @staticmethod
    def _validate_cache_control(value: Any) -> None:
        """``cache_control`` ist ein Schalter, kein Freitext-Kanal.

        Deshalb validiert statt maskiert -- der Marker muss den Provider
        unveraendert erreichen, sonst greift das Prompt-Caching nicht. Und
        deshalb ENG validiert: waere hier ein ``isinstance``-Guard im
        Verarbeitungspfad statt einer Pruefung, die blockt, waere das exakt
        die Type-Confusion-Luecke (F1) an neuer Stelle."""
        if value is None:
            return
        if not isinstance(value, dict):
            raise DatenschleuseBlocked(
                f"cache_control vom Typ {type(value).__name__!r} ist kein "
                "Caching-Marker -- blockiert (fail-closed). Erlaubt ist nur "
                "ein Objekt wie {'type': 'ephemeral'}."
            )
        unknown = sum(1 for key in value if key not in CACHE_CONTROL_ALLOWED_FIELDS)
        if unknown:
            raise DatenschleuseBlocked(
                f"cache_control enthaelt {unknown} ungepruefte(s) Feld(er) -- "
                "blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(CACHE_CONTROL_ALLOWED_FIELDS))}."
            )
        marker = value.get("type")
        if not isinstance(marker, str) or marker not in CACHE_CONTROL_TYPES:
            raise DatenschleuseBlocked(
                f"cache_control.type (Typ {type(marker).__name__!r}) ist kein "
                "bekannter Caching-Marker -- blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(CACHE_CONTROL_TYPES))}."
            )
        ttl = value.get("ttl")
        if ttl is not None and (not isinstance(ttl, str) or ttl not in CACHE_CONTROL_TTLS):
            raise DatenschleuseBlocked(
                f"cache_control.ttl (Typ {type(ttl).__name__!r}) ist kein "
                "bekannter Wert -- blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(CACHE_CONTROL_TTLS))}."
            )

    @staticmethod
    def _validate_citation_index(value: Any, field: str) -> None:
        """Ein Zitat-Index ist eine nicht-negative Ganzzahl in plausibler
        Groessenordnung -- oder gar nicht da.

        ``bool`` wird ZUERST abgefangen: in Python ist ``True`` ein ``int``,
        ein blosses ``isinstance(value, int)`` liesse also ``True`` als Index
        durch. Genau die Sorte stiller Durchlass, die dieses Guardrail schon
        zweimal als Security-Befund gesehen hat."""
        if value is None:
            return
        if isinstance(value, bool) or not isinstance(value, int):
            raise DatenschleuseBlocked(
                f"{field} vom Typ {type(value).__name__!r} ist kein "
                "Zitat-Index -- als ungepruefter Kanal blockiert "
                "(fail-closed). Erlaubt ist nur eine Ganzzahl."
            )
        if value < 0 or value > MAX_CITATION_INDEX:
            raise DatenschleuseBlocked(
                f"{field} liegt ausserhalb des zulaessigen Bereichs "
                f"(0 bis {MAX_CITATION_INDEX}) und ist damit keine "
                "plausible Dokumentposition -- blockiert (fail-closed)."
            )

    @staticmethod
    def _validate_citations(value: Any) -> None:
        """``citations`` ist ein Zitat-Array, kein freier Container.

        Zweigeteilt wie das Part-Register eine Ebene hoeher: die Freitext-
        Felder (``cited_text``, ``document_title``) werden spaeter maskiert,
        die Indizes muessen unveraendert durch -- und werden deshalb HIER
        eng geprueft. Blocken statt still ueberspringen: nach dieser Methode
        ist garantiert, dass ``_mask_citations`` nur noch auf Listen von
        Dicts mit bekanntem Typ und Strings in den Textfeldern trifft. Ein
        ``isinstance``-Guard im Verarbeitungspfad waere wieder ein stiller
        Durchlass (Lehre aus F1).

        Gesetz 5: keine Meldung enthaelt Client-Werte. Ausgegeben werden nur
        Anzahl, Python-Typname, Fingerprint und konstante Listen. Ein Name
        aus einer unserer Konstanten ist kein Client-Wert -- er wird nur
        genannt, WEIL er gleich der Konstante ist.
        """
        if value is None:
            return
        if not isinstance(value, list):
            raise DatenschleuseBlocked(
                f"citations vom Typ {type(value).__name__!r} ist kein "
                "Zitat-Array -- blockiert (fail-closed). Erlaubt ist nur "
                "eine Liste von Zitat-Objekten."
            )
        if len(value) > MAX_CITATIONS_PER_PART:
            raise DatenschleuseBlocked(
                f"citations enthaelt {len(value)} Eintraege und "
                f"ueberschreitet die zulaessige Obergrenze "
                f"({MAX_CITATIONS_PER_PART}) -- blockiert (fail-closed)."
            )

        for citation in value:
            if not isinstance(citation, dict):
                raise DatenschleuseBlocked(
                    f"Zitat vom Typ {type(citation).__name__!r} ist nicht "
                    "pruefbar und deshalb blockiert (fail-closed). Erlaubt "
                    "sind nur Zitat-Objekte."
                )

            citation_type = citation.get("type")
            if (
                not isinstance(citation_type, str)
                or citation_type not in ALLOWED_CITATION_TYPES
            ):
                # citation_type ist voll client-kontrolliert und darf nie roh
                # in die Meldung. Genannt wird er NUR, wenn er exakt einem
                # Wert unserer Konstante entspricht -- dann ist der
                # ausgegebene String unsere Konstante, nicht der Request.
                if (
                    isinstance(citation_type, str)
                    and citation_type in KNOWN_UNSUPPORTED_CITATION_TYPES
                ):
                    grund = (
                        f"Zitat-Typ '{citation_type}' traegt Freitext- bzw. "
                        "Provider-Token-Felder, fuer die es keinen "
                        "geprueften Pfad gibt"
                    )
                else:
                    grund = (
                        "Zitat-Typ "
                        f"({type(citation_type).__name__}) ist der "
                        "Datenschleuse nicht bekannt"
                    )
                raise DatenschleuseBlocked(
                    f"{grund} -- blockiert (fail-closed). Geprueft werden "
                    f"ausschliesslich: {_ALLOWED_CITATION_TYPES_HINT}."
                )

            allowed = ALLOWED_CITATION_FIELDS[citation_type]
            unknown = [key for key in citation if key not in allowed]
            if unknown:
                benannt = sorted(
                    key for key in unknown
                    if isinstance(key, str)
                    and key in KNOWN_UNSUPPORTED_CITATION_FIELDS
                )
                fremd = [key for key in unknown if key not in benannt]
                teile = []
                if benannt:
                    teile.append(
                        "bekannt, aber nicht im Register: " + ", ".join(benannt)
                    )
                if fremd:
                    teile.append(
                        "unbekannt (Fingerprint): "
                        + ", ".join(sorted(_field_fingerprint(k) for k in fremd))
                    )
                diagnose = "; ".join(teile)
                _LOG.warning(
                    "Zitat blockiert -- ungepruefte Felder [%s]. Werte "
                    "werden bewusst nicht geloggt (Gesetz 5).", diagnose,
                )
                raise DatenschleuseBlocked(
                    f"Zitat enthaelt {len(unknown)} Feld(er), die die "
                    f"Datenschleuse nicht prueft ({diagnose}) -- deshalb "
                    "blockiert (fail-closed). Geprueft werden "
                    f"ausschliesslich: "
                    f"{_ALLOWED_CITATION_FIELDS_HINT[citation_type]}."
                )

            for field in CITATION_FIELDS_MASKED[citation_type]:
                DatenschleuseGuardrail._validate_text_field(
                    citation.get(field), f"citations[].{field}"
                )
            for field in CITATION_INDEX_FIELDS[citation_type]:
                DatenschleuseGuardrail._validate_citation_index(
                    citation.get(field), f"citations[].{field}"
                )

    @staticmethod
    def _validate_opaque_id(value: Any, field: str) -> None:
        """IDs (``tool_call_id``, ``tool_calls[].id``) sind opake Korrelations-
        Tokens, kein Freitext. Sie werden bewusst NICHT maskiert -- ihr Wert
        muss byte-identisch bleiben, sonst findet das Modell das Ergebnis
        eines Tool-Aufrufs nicht mehr zu seinem Aufruf. Genau deshalb muessen
        sie eng validiert werden, sonst waeren sie der bequemste
        Schmuggelkanal, den die Nachricht zu bieten hat."""
        if value is None:
            return
        if not isinstance(value, str) or not OPAQUE_ID_PATTERN.fullmatch(value):
            raise DatenschleuseBlocked(
                f"{field} ist kein zulaessiger Identifier (Typ "
                f"{type(value).__name__!r}) -- als Freitext-Kanal blockiert "
                "(fail-closed). Erlaubt: bis zu 128 Zeichen aus "
                "A-Z a-z 0-9 _ . : -"
            )

    @staticmethod
    def _validate_tool_call(call: Any) -> None:
        if not isinstance(call, dict):
            raise DatenschleuseBlocked(
                f"tool_call vom Typ {type(call).__name__!r} ist nicht pruefbar "
                "und deshalb blockiert (fail-closed)."
            )
        unknown = sum(1 for key in call if key not in TOOL_CALL_ALLOWED_FIELDS)
        if unknown:
            raise DatenschleuseBlocked(
                f"tool_call enthaelt {unknown} ungepruefte(s) Feld(er) -- "
                "blockiert (fail-closed). Erlaubt: "
                f"{', '.join(sorted(TOOL_CALL_ALLOWED_FIELDS))}."
            )
        DatenschleuseGuardrail._validate_opaque_id(call.get("id"), "tool_calls[].id")

        call_type = call.get("type")
        # ``type`` fehlt bei manchen Clients -- historisch impliziert das
        # "function". Ein ANDERER Typ ist dagegen ein uns unbekanntes Format
        # mit unbekannten Feldern -> blocken.
        if call_type is not None and (
            not isinstance(call_type, str) or call_type not in ALLOWED_TOOL_CALL_TYPES
        ):
            raise DatenschleuseBlocked(
                f"tool_call mit nicht erlaubtem Typ (Typ {type(call_type).__name__!r}) "
                "wird von der Datenschleuse nicht geprueft und ist deshalb "
                f"blockiert (fail-closed). Erlaubt: {', '.join(sorted(ALLOWED_TOOL_CALL_TYPES))}."
            )

        index = call.get("index")
        if index is not None and not isinstance(index, int):
            raise DatenschleuseBlocked(
                f"tool_calls[].index vom Typ {type(index).__name__!r} ist kein "
                "Index -- blockiert (fail-closed)."
            )

        function = call.get("function")
        if function is not None:
            DatenschleuseGuardrail._validate_function_payload(function, "tool_calls[].function")

    @staticmethod
    def _validate_function_payload(function: Any, field: str) -> None:
        if not isinstance(function, dict):
            raise DatenschleuseBlocked(
                f"{field} vom Typ {type(function).__name__!r} ist nicht pruefbar "
                "und deshalb blockiert (fail-closed)."
            )
        unknown = sum(1 for key in function if key not in TOOL_CALL_FUNCTION_ALLOWED_FIELDS)
        if unknown:
            raise DatenschleuseBlocked(
                f"{field} enthaelt {unknown} ungepruefte(s) Feld(er) -- blockiert "
                f"(fail-closed). Erlaubt: "
                f"{', '.join(sorted(TOOL_CALL_FUNCTION_ALLOWED_FIELDS))}."
            )
        # F1: ``arguments`` als dict/Liste statt als JSON-String lief bisher
        # ungeprueft durch -- verifizierter PoC des Security-Audits.
        for name in ("name", "arguments"):
            DatenschleuseGuardrail._validate_text_field(
                function.get(name), f"{field}.{name}"
            )

    def _enforce_sensitivity(
        self,
        text: str,
        entities: List[Dict[str, Any]],
        requested_level: Any,
        approved: bool,
    ) -> None:
        """Schutzklassen-Gate fuer die Felder neben content -- identisch zum
        content-Pfad: Stufe 3 blockt hart, Stufe 2 ohne Freigabe ebenfalls.
        Das Gate darf nicht am content-Feld enden, sonst waere eine Diagnose
        in ``arguments`` weniger geschuetzt als dieselbe Diagnose im Fliesstext."""
        classification = self.classifier.classify(
            text, entities=entities, requested_level=requested_level,
        )
        try:
            sc.enforce_tier_3_block(classification)
            sc.enforce_tier_2_gate(classification, approved)
        except (sc.Tier3Blocked, sc.Tier2ApprovalRequired) as exc:
            raise DatenschleuseBlocked(str(exc)) from exc

    async def _mask_text_value(
        self, text: Any, masker: Masker, requested_level: Any, approved: bool
    ) -> Any:
        """Maskiert einen einzelnen Textwert ueber DENSELBEN Masker wie der
        content-Pfad -- kein zweites Mapping, damit die Re-Identifikation auf
        dem Rueckweg unveraendert funktioniert.

        Anders als im content-Pfad wird hier NICHT nach QI-Typen aufgeteilt:
        QI-Werte werden direkt maskiert statt generalisiert. Das ist strenger
        (ein Platzhalter gibt weniger preis als ein generalisierter Wert),
        nie laxer -- und haelt den QI-Slot-Mechanismus aus Strukturen heraus,
        in denen es keinen zusammenhaengenden Textslot gibt."""
        if not isinstance(text, str) or not text.strip():
            return text
        entities = await self._analyze(text)
        self._enforce_sensitivity(text, entities, requested_level, approved)
        return masker.mask(text, entities)

    async def _mask_citations(
        self, part: Dict[str, Any], masker: Masker,
        requested_level: Any, approved: bool,
    ) -> None:
        """Maskiert die Freitext-Felder der Zitate eines Text-Parts und
        laesst die Indizes unveraendert.

        Voraussetzung ist ``_validate_citations``: danach ist ``citations``
        entweder None/leer oder eine Liste von Dicts mit bekanntem Typ,
        deren Textfelder Strings (oder None) sind. Deshalb steht hier KEINE
        ``isinstance``-Pruefung -- die gehoert in den Validierungspfad und
        blockt dort, statt hier still zu ueberspringen.

        ``document_title`` ist laut Schema ausdruecklich nullable; ein
        fehlendes oder None-Feld traegt keinen Text und wird uebersprungen.
        """
        citations = part.get("citations")
        if not citations:
            return
        for citation in citations:
            for field in CITATION_FIELDS_MASKED[citation["type"]]:
                value = citation.get(field)
                if value is None:
                    continue
                citation[field] = await self._mask_text_value(
                    value, masker, requested_level, approved,
                )

    async def _mask_json_node(
        self,
        node: Any,
        masker: Masker,
        collected: List[Dict[str, Any]],
        depth: int = 0,
    ) -> Any:
        """Maskiert rekursiv alle Textwerte eines geparsten JSON-Baums und
        laesst die STRUKTUR unangetastet (Akzeptanzkriterium: der Tool-Aufruf
        muss beim Zielmodell benutzbar bleiben).

        Auch SCHLUESSEL werden maskiert: ein JSON-Schluessel ist genauso ein
        Kanal ans Modell wie ein Wert. Maskieren statt Blocken haelt die
        Struktur gueltig.

        Zahlen/Bools: eine Zahl kann PII sein (Telefonnummer, Kundennummer als
        JSON-Zahl). Sie wird deshalb als Text geprueft -- aber nur DANN durch
        einen Platzhalter ersetzt, wenn tatsaechlich etwas erkannt wurde. Der
        damit einhergehende Typwechsel (Zahl -> String) ist bewusst in Kauf
        genommen: ein gebrochenes Tool-Schema ist sichtbar, ein Leck nicht."""
        if depth > MAX_JSON_DEPTH:
            # Ohne Grenze lief hier ein RecursionError aus dem Hook heraus --
            # ein unkontrollierter Fehlerpfad statt fail-closed (F7).
            raise DatenschleuseBlocked(
                f"arguments ueberschreitet die zulaessige Verschachtelungstiefe "
                f"({MAX_JSON_DEPTH}) und wird nicht geprueft -- blockiert "
                "(fail-closed)."
            )
        if isinstance(node, str):
            if not node.strip():
                return node
            entities = await self._analyze(node)
            collected.extend(entities)
            return masker.mask(node, entities)
        if isinstance(node, list):
            return [
                await self._mask_json_node(item, masker, collected, depth + 1)
                for item in node
            ]
        if isinstance(node, dict):
            masked: Dict[Any, Any] = {}
            for key, value in node.items():
                new_key = await self._mask_json_node(key, masker, collected, depth + 1)
                masked[new_key] = await self._mask_json_node(
                    value, masker, collected, depth + 1
                )
            return masked
        if node is None or isinstance(node, bool):
            # Tragen keinen Text -> nichts zu maskieren (bewusste Entscheidung).
            return node
        if isinstance(node, (int, float)):
            as_text = str(node)
            entities = await self._analyze(as_text)
            if not entities:
                return node
            collected.extend(entities)
            return masker.mask(as_text, entities)
        return node

    async def _verify_no_pii_left(self, text: Any, masker: Masker) -> None:
        """Verifikationsdurchlauf auf dem ERGEBNIS (Security-Audit F1).

        Alle Einzelpruefungen oben sind Pfad-gebunden: sie greifen nur, wenn
        ein Wert den Weg nimmt, den jemand vorhergesehen hat. Diese Pruefung
        ist die einzige, die unabhaengig davon greift -- der fertig maskierte
        String geht noch einmal durch den Analyzer. Findet der dort noch
        Entitaeten, ist irgendwo etwas durchgerutscht und der Request wird
        blockiert, statt die PII rauszulassen.

        Die bekannten Platzhalter werden vorher durch ein neutrales Zeichen
        ersetzt: sonst wuerde die Erkennung womoeglich den Platzhalter selbst
        (``<PERSON_0>``) als Namen lesen und jeden korrekt maskierten
        Tool-Aufruf blocken."""
        if not isinstance(text, str) or not text.strip():
            return
        probe = text
        for placeholder in sorted(masker.reid_map, key=len, reverse=True):
            probe = probe.replace(placeholder, _PLACEHOLDER_PROBE_FILLER)
        leftovers = await self._analyze(probe)
        if leftovers:
            types = sorted({str(e.get("entity_type")) for e in leftovers})
            # Nur die Entity-TYPEN nennen (Presidio-Vokabular, kein
            # Client-Inhalt) -- nie den Fundtext selbst (Gesetz 5).
            # Formulierung bewusst ehrlich (QA-Audit): ein Restbefund ist
            # NICHT zwingend ein Fehler im Maskierungspfad. Er entsteht auch
            # durch Grenzfaelle der Erkennung selbst -- derselbe Analyzer
            # findet an derselben Stelle im zweiten Durchlauf etwas, das er
            # im ersten uebersehen hat, weil sich der umgebende Kontext durch
            # die Ersetzung veraendert hat. Belegt am Beispiel
            # "Digitalisierung Rathaus Muenchen" + "Frau Schmidt". Eine
            # Meldung, die dem Betreiber einen Code-Fehler unterstellt, waere
            # in diesen Faellen schlicht falsch.
            raise DatenschleuseBlocked(
                "Nach der Maskierung wurden weiterhin personenbezogene Daten "
                f"erkannt ({', '.join(types)}) -- Request blockiert "
                "(fail-closed). Ursache ist entweder eine Luecke im "
                "Maskierungspfad oder ein Grenzfall der Erkennung, bei dem "
                "erst der zweite Durchlauf anschlaegt. In beiden Faellen "
                "gilt: im Zweifel nicht rauslassen."
            )

    async def _mask_arguments(
        self, raw: Any, masker: Masker, requested_level: Any, approved: bool
    ) -> Any:
        """Maskiert einen ``arguments``-JSON-String strukturerhaltend."""
        if not isinstance(raw, str) or not raw.strip():
            return raw
        try:
            parsed = json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except _UnsafeJson as exc:
            # Mehrdeutiges bzw. nicht standardkonformes JSON: nicht zuverlaessig
            # pruefbar -> blocken. Die Meldung traegt bewusst keinen Fundwert.
            raise DatenschleuseBlocked(
                f"arguments ist nicht eindeutig pruefbar ({exc}) -- blockiert "
                "(fail-closed)."
            ) from exc
        except RecursionError as exc:
            raise DatenschleuseBlocked(
                "arguments ist zu tief verschachtelt, um geprueft zu werden -- "
                "blockiert (fail-closed)."
            ) from exc
        except (ValueError, TypeError):
            # Modelle liefern gelegentlich kaputte ``arguments``. Nicht
            # parsebar heisst NICHT ungeprueft -- dann wird der Rohstring als
            # Freitext maskiert. (Maskieren ist nie ein Leck; ein Block waere
            # hier die haertere, aber unnoetige Reaktion.)
            result = await self._mask_text_value(
                raw, masker, requested_level, approved
            )
            await self._verify_no_pii_left(result, masker)
            return result

        collected: List[Dict[str, Any]] = []
        masked = await self._mask_json_node(parsed, masker, collected)

        # Schutzklassen auf dem GESAMTEN Rohstring: das Signalwort ("Diagnose")
        # und die Personen-Referenz stehen typischerweise in VERSCHIEDENEN
        # JSON-Feldern -- pro Feld einzeln klassifiziert wuerde die Kombination
        # nie erkannt. Uebergeben werden nur die Entity-TYPEN der gesammelten
        # Treffer: der Klassifizierer nutzt von den Entities ausschliesslich
        # den Typ (Personen-Referenz), und feld-lokale Offsets waeren auf den
        # Rohstring bezogen schlicht falsch.
        self._enforce_sensitivity(
            raw,
            [{"entity_type": e.get("entity_type")} for e in collected],
            requested_level,
            approved,
        )
        if masked == parsed:
            # Nichts erkannt -> Original unveraendert weiterreichen (keine
            # kosmetische Re-Serialisierung eines fremden JSON-Strings).
            # ACHTUNG: auch dieser Pfad muss durch die Verifikation -- genau
            # hier ging beim Duplicate-Key-Fund der Rohstring mit PII hinaus.
            result = raw
        else:
            try:
                result = json.dumps(masked, ensure_ascii=False, allow_nan=False)
            except ValueError as exc:
                raise DatenschleuseBlocked(
                    "arguments liess sich nicht als striktes JSON serialisieren "
                    "-- blockiert (fail-closed)."
                ) from exc
        await self._verify_no_pii_left(result, masker)
        return result

    async def _mask_function_payload(
        self, function: Any, masker: Masker, requested_level: Any, approved: bool
    ) -> None:
        """Maskiert ``name`` und ``arguments`` eines Function-/Tool-Calls."""
        if not isinstance(function, dict):
            return
        if isinstance(function.get("name"), str):
            function["name"] = await self._mask_text_value(
                function["name"], masker, requested_level, approved
            )
        if isinstance(function.get("arguments"), str):
            function["arguments"] = await self._mask_arguments(
                function["arguments"], masker, requested_level, approved
            )

    async def _mask_message_fields(
        self, msg: Dict[str, Any], masker: Masker, requested_level: Any, approved: bool
    ) -> None:
        """Maskiert alle Textfelder einer Message AUSSER ``content`` (das
        erledigt der bestehende Pfad im Hook). Reihenfolge der Felder ist
        stabil, damit die Platzhalter-Nummerierung deterministisch bleibt."""
        for field in ("name", "refusal", "reasoning_content"):
            value = msg.get(field)
            if isinstance(value, str):
                msg[field] = await self._mask_text_value(
                    value, masker, requested_level, approved
                )

        tool_calls = msg.get("tool_calls")
        if isinstance(tool_calls, list):
            for call in tool_calls:
                if isinstance(call, dict):
                    await self._mask_function_payload(
                        call.get("function"), masker, requested_level, approved
                    )

        # Legacy-Format (vor tool_calls): dieselbe Nutzlast, andere Stelle.
        await self._mask_function_payload(
            msg.get("function_call"), masker, requested_level, approved
        )

    # ---- Anonymisierungs-Hinweis -------------------------------------------
    @staticmethod
    def _inject_anonymization_notice(
        messages: List[Any], notice: str = ANONYMIZATION_NOTICE
    ) -> None:
        """Fuegt ``notice`` (Default: ANONYMIZATION_NOTICE) in die erste
        System-Message ein (haengt an, falls schon eine existiert) oder legt
        eine neue System-Message an Position 0 an, falls keine vorhanden ist.
        Mutiert ``messages`` in place (wie der Rest von async_pre_call_hook).

        ``notice`` ist optional parametrisierbar, damit Aufrufer (z. B. die
        Cockpit-preview-api) einen nutzerseitig ueberschriebenen Text
        einfuegen koennen, OHNE diese Platzierungs-/Formatierungslogik zu
        duplizieren (Drift-Vermeidung — siehe preview-api/app/masking.py::
        inject_anonymization_notice)."""
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "system":
                content = msg.get("content")
                if isinstance(content, str):
                    msg["content"] = f"{content}\n\n{notice}"
                    return
                if isinstance(content, list):
                    # Multimodale System-Message: als zusaetzlichen Text-Part anhaengen.
                    content.append({"type": "text", "text": notice})
                    return
                # Unbekannter/leerer content -> als String ueberschreiben statt
                # stillschweigend zu verwerfen.
                msg["content"] = notice
                return
        # Keine System-Message vorhanden -> neue an Position 0 einfuegen.
        messages.insert(0, {"role": "system", "content": notice})

    # ---- QI-Layer-Helfer ---------------------------------------------------
    @staticmethod
    def _split_entities(
        entities: List[Dict[str, Any]], qi_types: "frozenset"
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Teilt Analyzer-Entities in (direkte Identifier, Quasi-Identifier)."""
        if not qi_types:
            return list(entities), []
        direct: List[Dict[str, Any]] = []
        qi: List[Dict[str, Any]] = []
        for ent in entities:
            if ent.get("entity_type") in qi_types:
                qi.append(ent)
            else:
                direct.append(ent)
        return direct, qi

    @staticmethod
    def _extract_qi_values(
        original: str, qi_entities: List[Dict[str, Any]]
    ) -> List[Tuple[str, str]]:
        """(Typ, Rohwert)-Paare der QI-Entities aus dem ORIGINALTEXT (vor
        Maskierung; nur dort stimmen die Presidio-Offsets)."""
        out: List[Tuple[str, str]] = []
        for ent in qi_entities:
            etype = ent.get("entity_type")
            start, end = ent.get("start"), ent.get("end")
            if (
                etype
                and isinstance(start, int)
                and isinstance(end, int)
                and 0 <= start < end <= len(original)
            ):
                out.append((etype, original[start:end]))
        return out

    def _process_qi(
        self,
        data: dict,
        user_api_key_dict: Any,
        turn_qi: List[Tuple[str, str]],
        text_slots: List[Tuple[Any, Any]],
    ) -> None:
        """Kernstueck: Session-Key aufloesen, akkumulierte QI-Typen laden,
        Schwellwert pruefen, State aktualisieren und ggf. die QI-Rohwerte in
        den bereits maskierten Text-Slots durch ihre generalisierte Form
        ersetzen.

        Wird nur bei aktivem QI-Layer und vorhandenen QI-Instanzen aufgerufen.
        Session-Key: bevorzugt eine echte, client-gelieferte Session-ID; sonst
        (grob) der API-Key-Hash. Fehlt beides, ist keine Session-uebergreifende
        Akkumulation moeglich -- dann zaehlt nur der aktuelle Turn.
        """
        import qi_state as qs

        session_key, coarse = qs.resolve_session_key(data, user_api_key_dict)

        if session_key is None:
            # Keine Session-Zuordnung moeglich: nur den aktuellen Turn bewerten
            # (kein persistenter State). Das deckt den Single-Shot-Fall ab, in
            # dem z.B. unter `paranoid` schon eine einzelne QI generalisiert
            # werden soll, ohne dass wir etwas speichern koennten.
            seen_before: set = set()
            generalize_now, _ = qig.decide_generalization(
                seen_before, turn_qi, self.qi_threshold
            )
            if generalize_now:
                self._apply_qi_to_slots(text_slots, turn_qi)
            return

        store = self._qi_store
        seen_before = store.get_seen_types(session_key)
        generalize_now, _after = qig.decide_generalization(
            seen_before, turn_qi, self.qi_threshold
        )

        # State aktualisieren: pro QI-Typ nur die GENERALISIERTE Kategorie
        # (nie der Rohwert) verschluesselt ablegen.
        store.record_many(
            session_key,
            [(etype, qig.state_category(etype, value)) for etype, value in turn_qi],
        )

        if generalize_now:
            self._apply_qi_to_slots(text_slots, turn_qi)

    @staticmethod
    def _apply_qi_to_slots(
        text_slots: List[Tuple[Any, Any]], turn_qi: List[Tuple[str, str]]
    ) -> None:
        """Wendet die Generalisierung auf jeden Text-Slot an (wert-basiert;
        QI-Werte, die in einem Slot nicht vorkommen, sind schlicht No-ops)."""
        for container, key in text_slots:
            current = container.get(key) if isinstance(container, dict) else None
            if isinstance(current, str):
                container[key] = qig.apply_generalizations(current, turn_qi)

    # ---- Post-Call Streaming: streaming-sichere Re-Identification ---------
    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict,
    ) -> AsyncGenerator[Any, None]:
        """Ersetzt Platzhalter in Streaming-Chunks mit einem Sliding-Window,
        sodass echtes Token-Streaming erhalten bleibt."""
        reid_map = self._read_reid_map(request_data)
        processor = ReidStreamProcessor(reid_map, margin=self.placeholder_margin)
        # tool_call-Fragmente kommen in EIGENEN Feldern (delta.tool_calls[i].
        # function.arguments), nicht in delta.content -- und sie sind
        # genauso ueber Chunk-Grenzen zerlegt. Deshalb pro Tool-Call ein
        # eigener Sliding-Window-Prozessor. Fuer ``arguments`` mit
        # JSON-escapten Werten, weil das Fragment INNERHALB eines
        # JSON-Strings landet, den der Client wieder zusammensetzt.
        escaped_map = json_escaped_mapping(reid_map)
        tool_states: Dict[Any, Dict[str, Any]] = {}
        # Reasoning-Modelle streamen ihre Gedankenkette in einem EIGENEN
        # Delta-Feld, nicht in delta.content. Ohne eigenen Prozessor sah der
        # Nutzer dort rohe <PERSON_0>-Tokens: kein Leck, aber AK3 verlangt,
        # dass die Re-Identifikation "ebenso greift wie beim Textkanal" --
        # und Streaming-Reasoning ist ein beworbenes Client-Kernfeature.
        text_processors = {
            field: ReidStreamProcessor(reid_map, margin=self.placeholder_margin)
            for field in STREAM_TEXT_DELTA_FIELDS
        }
        text_templates: Dict[str, Any] = {}

        last_content_chunk = None
        try:
            async for chunk in response:
                self._stream_reidentify_tool_calls(
                    chunk, tool_states, escaped_map, reid_map
                )
                for field in self._stream_reidentify_text_deltas(
                    chunk, text_processors
                ):
                    text_templates[field] = chunk
                # Zitate: VOR der content-Pruefung, denn ein Chunk mit einem
                # ``citations_delta`` traegt typischerweise gar kein
                # Text-Delta und wuerde unten unveraendert durchgereicht.
                self._stream_reidentify_citations(chunk, reid_map)
                content = self._extract_delta(chunk)
                if content is None:
                    # Chunk ohne Text-Delta (role-only, finish_reason, usage) ->
                    # unveraendert durchreichen.
                    yield chunk
                    continue
                emit = processor.feed(content)
                # delta.content wird auf den sicher emittierbaren Teil gesetzt
                # (kann "" sein) — Chunk bleibt ein gueltiges ModelResponseStream.
                self._set_delta(chunk, emit)
                last_content_chunk = chunk
                yield chunk
        finally:
            # Rest-Puffer am Stream-Ende ausgeben, damit kein Text verloren geht.
            tail = processor.flush()
            if tail and last_content_chunk is not None:
                # Struktur eines echten Content-Chunks klonen (versionsagnostisch,
                # ohne LiteLLM-Typen konstruieren zu muessen) und Rest anhaengen.
                final_chunk = copy.deepcopy(last_content_chunk)
                # Security-Audit: ohne dieses Leeren wandert ein Reasoning-,
                # refusal- oder tool_call-Fragment, das DERSELBE Chunk trug,
                # unveraendert in den Klon -- und ist zu dem Zeitpunkt bereits
                # ausgeliefert. Folge: doppelter Text und, bei tool_calls,
                # deterministisch kaputtes JSON im zusammengesetzten
                # ``arguments``. Der Fix aus der Vorrunde traf nur zwei der
                # drei Tail-Pfade; dieser hier fehlte.
                self._blank_stream_fragments(final_chunk)
                self._set_delta(final_chunk, tail)
                self._clear_finish_reason(final_chunk)
                yield final_chunk
            # Dasselbe fuer die zurueckgehaltenen Enden der tool_call-Puffer:
            # ohne diesen Flush fehlt dem Client das Ende von ``arguments``
            # und das JSON des Tool-Aufrufs ist abgeschnitten.
            for key, state in tool_states.items():
                tails = {
                    field: state[field].flush() for field in ("arguments", "name")
                }
                if state["template"] is None or not any(tails.values()):
                    continue
                yield self._build_tool_tail_chunk(state["template"], key, tails)
            # Und der Rest des Reasoning-Puffers -- ohne diesen Flush fehlt
            # dem Nutzer das Ende der Gedankenkette.
            for field, processor in text_processors.items():
                text_tail = processor.flush()
                template = text_templates.get(field)
                if text_tail and template is not None:
                    yield self._build_text_tail_chunk(template, field, text_tail)

    # ---- Post-Call Non-Streaming: einfacher Voll-Ersatz -------------------
    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: Any,
        response: Any,
    ) -> Any:
        """Re-Identification fuer nicht-gestreamte Responses. Kein
        Sliding-Window noetig (kein Chunking). Fehler hier sind KEIN Leck
        (Platzhalter bleiben stehen) -> nicht fail-closed blocken."""
        reid_map = self._read_reid_map(data)
        if not reid_map:
            return response
        try:
            choices = getattr(response, "choices", None)
            if choices is None and isinstance(response, dict):
                choices = response.get("choices")
            for choice in choices or []:
                message = getattr(choice, "message", None)
                if message is None and isinstance(choice, dict):
                    message = choice.get("message")
                if message is None:
                    continue
                content = getattr(message, "content", None)
                if content is None and isinstance(message, dict):
                    content = message.get("content")
                if isinstance(content, str):
                    new_content = reidentify_full(content, reid_map)
                    if isinstance(message, dict):
                        message["content"] = new_content
                    else:
                        message.content = new_content
                elif isinstance(content, list):
                    # Die zweite reale Form (QA-Audit F1): Anthropic
                    # antwortet mit einer LISTE von Bloecken. Bisher gab es
                    # hier nur den String-Zweig, eine Liste fiel still durch
                    # -- der gesamte Antworttext blieb beim Platzhalter.
                    self._reidentify_content_blocks(content, reid_map)
                # Der Rueckweg muss dieselben Felder abdecken wie der Hinweg
                # (DATENSCHLE-66): gibt das Modell tool_calls zurueck, stehen
                # die Platzhalter in ``arguments`` -- ohne Ersetzung bekaeme
                # der Client <PERSON_0> statt des echten Werts und der
                # Tool-Aufruf liefe auf einem Platzhalter.
                self._reidentify_message_fields(message, reid_map)
        except Exception:
            # Bewusst still: Platzhalter im Output sind sicher (kein PII-Leck).
            return response
        return response

    # ---- Metadata-/Chunk-Helfer -------------------------------------------
    @staticmethod
    def _read_reid_map(request_data: Any) -> Dict[str, str]:
        """Liest das Re-Id-Mapping robust aus den Request-Metadaten.

        LiteLLM propagiert Metadaten je nach Version unter ``metadata`` oder
        ``litellm_metadata`` — beide werden geprueft. Genaue Propagation ist
        gegen die laufende LiteLLM-Version zu verifizieren.
        """
        if not isinstance(request_data, dict):
            return {}
        for meta_key in ("metadata", "litellm_metadata"):
            meta = request_data.get(meta_key)
            if isinstance(meta, dict) and isinstance(meta.get(REID_MAP_KEY), dict):
                return meta[REID_MAP_KEY]
        # Fallback: direkt im request_data (manche Codepfade flatten Metadaten).
        if isinstance(request_data.get(REID_MAP_KEY), dict):
            return request_data[REID_MAP_KEY]
        return {}

    @staticmethod
    def _field(obj: Any, name: str) -> Any:
        """Liest ein Feld robust aus dict ODER Objekt (LiteLLM liefert je nach
        Codepfad das eine oder das andere)."""
        if isinstance(obj, dict):
            return obj.get(name)
        return getattr(obj, name, None)

    @staticmethod
    def _set_field(obj: Any, name: str, value: Any) -> None:
        if isinstance(obj, dict):
            obj[name] = value
        else:
            setattr(obj, name, value)

    def _reidentify_function_payload(self, function: Any, reid_map: Dict[str, str]) -> None:
        if function is None:
            return
        name = self._field(function, "name")
        if isinstance(name, str):
            self._set_field(function, "name", reidentify_full(name, reid_map))
        arguments = self._field(function, "arguments")
        if isinstance(arguments, str):
            self._set_field(
                function, "arguments", reidentify_json_arguments(arguments, reid_map)
            )

    def _reidentify_message_fields(self, message: Any, reid_map: Dict[str, str]) -> None:
        """Re-Identification fuer alle Antwort-Felder neben ``content``."""
        for field in ("refusal", "reasoning_content"):
            value = self._field(message, field)
            if isinstance(value, str):
                self._set_field(message, field, reidentify_full(value, reid_map))

        tool_calls = self._field(message, "tool_calls")
        if isinstance(tool_calls, list):
            for call in tool_calls:
                self._reidentify_function_payload(self._field(call, "function"), reid_map)

        self._reidentify_function_payload(self._field(message, "function_call"), reid_map)

        # Zitate liegen bei LiteLLM NEBEN dem Text, nicht darin
        # (QA-Audit F1). Ohne diesen Aufruf kam der Haupttext im Klartext
        # an und dasselbe Zitat trug den rohen Platzhalter.
        self._reidentify_provider_specific_fields(message, reid_map)

    # ---- Rueckweg fuer Zitate (QA-Audit F1) -------------------------------
    def _reidentify_citation(self, citation: Any, reid_map: Dict[str, str]) -> None:
        """Loest die Platzhalter in den Freitext-Feldern EINES Zitats auf.

        In-place, wie der gesamte Rueckweg: der Aufrufer haelt eine Referenz
        auf das Objekt, das der Client bekommt. Ein Neu-Binden wuerde die
        Aenderung verlieren.
        """
        for field in CITATION_RESPONSE_TEXT_FIELDS:
            value = self._field(citation, field)
            if isinstance(value, str):
                self._set_field(citation, field, reidentify_full(value, reid_map))

    def _reidentify_citation_list(
        self, citations: Any, reid_map: Dict[str, str], depth: int = 0,
    ) -> None:
        """Eine Zitat-Liste. Eine Ebene Verschachtelung wird mitgenommen,
        weil LiteLLM die Zitate je nach Version pro Textblock gruppiert --
        dann steht dort eine Liste von Listen. Die Tiefe ist hart begrenzt:
        was hier ankommt, ist Provider-Ausgabe und keine gepruefte Struktur.
        """
        if not isinstance(citations, list) or depth > 1:
            return
        for citation in citations:
            if isinstance(citation, list):
                self._reidentify_citation_list(citation, reid_map, depth + 1)
                continue
            self._reidentify_citation(citation, reid_map)

    def _reidentify_provider_specific_fields(
        self, container: Any, reid_map: Dict[str, str],
    ) -> None:
        """Zitate aus ``provider_specific_fields`` -- der Ort, an dem LiteLLM
        sie ablegt, wenn es eine Anthropic-Antwort ins OpenAI-Format bringt.

        Zwei Schluessel, weil die beiden Pfade sie unterschiedlich benennen:
        non-streaming ``citations`` (Liste), streaming ``citation``
        (Einzelobjekt aus einem ``citations_delta``). Beide werden behandelt,
        damit eine LiteLLM-Version, die die Benennung angleicht, den Rueckweg
        nicht wieder stilllegt.
        """
        psf = self._field(container, "provider_specific_fields")
        if psf is None:
            return
        single = self._field(psf, "citation")
        if single is not None:
            self._reidentify_citation(single, reid_map)
        self._reidentify_citation_list(self._field(psf, "citations"), reid_map)

    def _reidentify_content_blocks(
        self, content: Any, reid_map: Dict[str, str],
    ) -> None:
        """``content`` als LISTE von Bloecken -- die Form, in der Anthropic
        antwortet. Der Hook verarbeitete ``content`` bisher nur unter
        ``isinstance(content, str)``; eine Liste fiel komplett durch, also
        blieb der GANZE Antworttext beim Platzhalter stehen.

        Jeder Block traegt seinen Text und ggf. seine eigenen Zitate.
        """
        if not isinstance(content, list):
            return
        for block in content:
            text = self._field(block, "text")
            if isinstance(text, str):
                self._set_field(block, "text", reidentify_full(text, reid_map))
            self._reidentify_citation_list(
                self._field(block, "citations"), reid_map
            )

    def _stream_reidentify_citations(
        self, chunk: Any, reid_map: Dict[str, str],
    ) -> None:
        """Zitate im Stream.

        Anders als Text und ``arguments`` kommt ein Zitat als VOLLSTAENDIGES
        Objekt pro Event -- Anthropics ``citations_delta`` traegt das ganze
        Zitat, nicht ein Fragment davon. Deshalb hier ein direkter
        Voll-Ersatz statt eines Sliding-Window-Puffers: der haette nichts zu
        puffern und wuerde nur das letzte Zitat zurueckhalten.
        """
        delta = self._chunk_delta(chunk)
        if delta is None:
            return
        self._reidentify_provider_specific_fields(delta, reid_map)

    @staticmethod
    def _chunk_delta(chunk: Any) -> Any:
        choices = getattr(chunk, "choices", None)
        if choices is None and isinstance(chunk, dict):
            choices = chunk.get("choices")
        if not choices:
            return None
        first = choices[0]
        delta = getattr(first, "delta", None)
        if delta is None and isinstance(first, dict):
            delta = first.get("delta")
        return delta

    def _iter_stream_functions(self, chunk: Any) -> List[Tuple[Any, Any]]:
        """Liefert (Schluessel, function-Payload) fuer jedes Tool-/Function-Call-
        Fragment eines Chunks. Der Schluessel identifiziert den Tool-Call ueber
        die Streams hinweg (``index``), damit die Fragmente eines Aufrufs im
        richtigen Puffer landen."""
        found: List[Tuple[Any, Any]] = []
        delta = self._chunk_delta(chunk)
        if delta is None:
            return found
        tool_calls = self._field(delta, "tool_calls")
        if isinstance(tool_calls, list):
            for position, call in enumerate(tool_calls):
                index = self._field(call, "index")
                key = ("tool_calls", index if isinstance(index, int) else position)
                found.append((key, self._field(call, "function")))
        function_call = self._field(delta, "function_call")
        if function_call is not None:
            found.append((("function_call", 0), function_call))
        return found

    def _stream_reidentify_tool_calls(
        self,
        chunk: Any,
        states: Dict[Any, Dict[str, Any]],
        escaped_map: Dict[str, str],
        reid_map: Dict[str, str],
    ) -> None:
        """Ersetzt Platzhalter in den tool_call-Fragmenten EINES Chunks
        (in-place) und puffert dabei wie im Text-Kanal nur einen kleinen Tail."""
        for key, function in self._iter_stream_functions(chunk):
            if function is None:
                continue
            state = states.get(key)
            if state is None:
                state = {
                    "arguments": ReidStreamProcessor(
                        escaped_map, margin=self.placeholder_margin
                    ),
                    "name": ReidStreamProcessor(
                        reid_map, margin=self.placeholder_margin
                    ),
                    "template": None,
                }
                states[key] = state
            for field in ("arguments", "name"):
                value = self._field(function, field)
                if isinstance(value, str):
                    self._set_field(function, field, state[field].feed(value))
            state["template"] = chunk

    def _stream_reidentify_text_deltas(
        self, chunk: Any, processors: Dict[str, ReidStreamProcessor]
    ) -> List[str]:
        """Ersetzt Platzhalter in den Freitext-Deltas neben ``content``
        (in-place) und liefert die Felder zurueck, die dieser Chunk trug --
        die taugen dann als Vorlage fuer den jeweiligen Abschluss-Chunk."""
        carried: List[str] = []
        delta = self._chunk_delta(chunk)
        if delta is None:
            return carried
        for field, processor in processors.items():
            value = self._field(delta, field)
            if not isinstance(value, str):
                continue
            self._set_field(delta, field, processor.feed(value))
            carried.append(field)
        return carried

    def _blank_stream_fragments(self, chunk: Any) -> None:
        """Leert in einem GEKLONTEN Chunk alle Fragmente, die der Client
        bereits bekommen hat. Ohne das wuerde ein Abschluss-Chunk den Inhalt
        seiner Vorlage ein zweites Mal ausliefern."""
        self._set_delta(chunk, "")
        delta = self._chunk_delta(chunk)
        if delta is not None:
            for field in STREAM_TEXT_DELTA_FIELDS:
                if isinstance(self._field(delta, field), str):
                    self._set_field(delta, field, "")
            # Zitate ebenso: trug die Vorlage ein ``citations_delta``, ist es
            # beim Client bereits angekommen. Ohne dieses Leeren liefert der
            # Abschluss-Chunk dasselbe Zitat ein zweites Mal aus -- derselbe
            # Defekt, den dieser Helfer fuer Reasoning, refusal und
            # tool_calls bereits behandelt.
            psf = self._field(delta, "provider_specific_fields")
            if psf is not None:
                for field in ("citation", "citations"):
                    if self._field(psf, field) is not None:
                        self._set_field(psf, field, None)
        for _key, function in self._iter_stream_functions(chunk):
            if function is None:
                continue
            for field in ("arguments", "name"):
                if isinstance(self._field(function, field), str):
                    self._set_field(function, field, "")

    def _build_tool_tail_chunk(
        self, template: Any, key: Any, tails: Dict[str, str]
    ) -> Any:
        """Baut den Abschluss-Chunk fuer die Rest-Puffer eines Tool-Calls.

        Wie beim Content-Tail wird ein echter Chunk GEKLONT statt ein
        LiteLLM-Typ konstruiert (versionsagnostisch). Alle bereits emittierten
        Fragmente im Klon werden geleert, damit nichts doppelt beim Client
        ankommt -- uebrig bleibt genau der Rest."""
        final_chunk = copy.deepcopy(template)
        self._blank_stream_fragments(final_chunk)
        for other_key, function in self._iter_stream_functions(final_chunk):
            if function is None or other_key != key:
                continue
            for field in ("arguments", "name"):
                if isinstance(self._field(function, field), str):
                    self._set_field(function, field, tails.get(field, ""))
        self._clear_finish_reason(final_chunk)
        return final_chunk

    def _build_text_tail_chunk(self, template: Any, field: str, tail: str) -> Any:
        """Abschluss-Chunk fuer den Restpuffer eines Freitext-Deltas --
        gleiche Mechanik wie beim Content- und Tool-Call-Tail."""
        final_chunk = copy.deepcopy(template)
        self._blank_stream_fragments(final_chunk)
        delta = self._chunk_delta(final_chunk)
        if delta is not None:
            self._set_field(delta, field, tail)
        self._clear_finish_reason(final_chunk)
        return final_chunk

    @staticmethod
    def _extract_delta(chunk: Any) -> Optional[str]:
        """Holt ``choices[0].delta.content`` aus einem Chunk. Gibt None zurueck,
        wenn kein Text-Delta vorhanden ist (dann Chunk unveraendert lassen)."""
        try:
            choices = getattr(chunk, "choices", None)
            if choices is None and isinstance(chunk, dict):
                choices = chunk.get("choices")
            if not choices:
                return None
            first = choices[0]
            delta = getattr(first, "delta", None)
            if delta is None and isinstance(first, dict):
                delta = first.get("delta")
            if delta is None:
                return None
            content = getattr(delta, "content", None)
            if content is None and isinstance(delta, dict):
                content = delta.get("content")
            return content if isinstance(content, str) else None
        except Exception:
            return None

    @staticmethod
    def _set_delta(chunk: Any, value: str) -> None:
        """Setzt ``choices[0].delta.content`` auf ``value``."""
        choices = getattr(chunk, "choices", None)
        if choices is None and isinstance(chunk, dict):
            choices = chunk.get("choices")
        if not choices:
            return
        first = choices[0]
        delta = getattr(first, "delta", None)
        if delta is None and isinstance(first, dict):
            delta = first.get("delta")
        if delta is None:
            return
        if isinstance(delta, dict):
            delta["content"] = value
        else:
            delta.content = value

    @staticmethod
    def _clear_finish_reason(chunk: Any) -> None:
        """Setzt finish_reason des geklonten Final-Chunks auf None (der Chunk,
        den wir klonen, war ein Mitten-im-Stream-Chunk und soll den Stream nicht
        vorzeitig beenden)."""
        choices = getattr(chunk, "choices", None)
        if choices is None and isinstance(chunk, dict):
            choices = chunk.get("choices")
        if not choices:
            return
        first = choices[0]
        if isinstance(first, dict):
            first["finish_reason"] = None
        elif hasattr(first, "finish_reason"):
            first.finish_reason = None
