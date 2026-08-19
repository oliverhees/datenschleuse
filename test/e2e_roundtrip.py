#!/usr/bin/env python3
"""End-to-end proof of the Datenschleuse round trip (DATENSCHLE-67).

Was hier bewiesen wird (nicht behauptet, bewiesen):

    Klartext -> Datenschleuse -> Platzhalter -> LLM -> Platzhalter
             -> Datenschleuse -> Klartext

Aufbau des Beweises
-------------------
Zwischen dem LiteLLM-Proxy und dem echten LLM (lokales Ollama, llama3.1:8b)
sitzt ein mitschneidender Tap (``test/e2e/tap.py``). Er protokolliert den
UPSTREAM-Payload -- also exakt das, was das LLM zu sehen bekommt -- und die
rohen Antwort-Chunks. Damit ist AK3 keine Vermutung ueber Code-Pfade, sondern
ein Mitschnitt.

Der Tap kann Antwort-Chunks zusaetzlich in Ein-Zeichen-SSE-Events zerlegen
(``mode="shred"``). Damit wird JEDER Platzhalter garantiert ueber
Chunk-Grenzen zerrissen -- der Streaming-Fall aus AK2 ist so deterministisch
statt vom Tokenizer-Zufall abhaengig.

Aufruf: ueber ``test/run-e2e-roundtrip.sh`` (bringt den Stack hoch, setzt die
noetigen ENV-Variablen und raeumt wieder ab).

Exit-Code 0 = alle Akzeptanzkriterien erfuellt.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# Konfiguration (alles ueberschreibbar, Defaults passen zu docker-compose.e2e)
# --------------------------------------------------------------------------
PROXY_URL = os.getenv("DS_E2E_PROXY_URL", "http://localhost:4001")
TAP_URL = os.getenv("DS_E2E_TAP_URL", "http://localhost:4600")
MASTER_KEY = os.getenv("DS_E2E_MASTER_KEY", "")
MODEL = os.getenv("DS_E2E_MODEL", "datenschleuse-e2e")
ARTIFACT_DIR = os.getenv("DS_E2E_ARTIFACTS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e", "artifacts"))

# --------------------------------------------------------------------------
# Echte deutsche Testdaten. Zulaessig, weil das Backend ein LOKALES Ollama ist
# -- diese Werte verlassen die Maschine nicht. Genau deshalb hat Oliver dieses
# Backend gewaehlt.
# --------------------------------------------------------------------------
PII = {
    "person": "Maria Meier",
    "strasse": "Bahnhofstraße 12",
    "iban": "DE89 3704 0044 0532 0130 00",
    "telefon": "089 12345678",
}
# Jedes Zeichen dieses Prompts ist gegen den echten Analyzer vermessen. Er ist
# so formuliert, dass GENAU die vier PII-Werte maskiert werden und sonst nichts.
# Zwei Fallen stecken darin, beide teuer bezahlt:
#
# 1. Umlaute ausschreiben, nicht umschreiben. Eine fruehere Fassung sagte
#    "Aendere keinen einzigen Wert." -- Presidio hielt "Aendere" fuer einen
#    PERSON (0.85) und maskierte es. Das Modell bekam dadurch einen
#    grammatisch zerstoerten Satz ("<PERSON_0> keinen einzigen Wert.") und
#    verweigerte die Antwort in zwei von drei Laeufen. Der Beweis wurde dadurch
#    unzuverlaessig -- und ein Gate, das grundlos rot wird, ist als Gate
#    wertlos. Mit echtem Umlaut ("Ändere") erkennt Presidio nichts.
#
# 2. Das Label "Strasse:" bleibt BEWUSST in ASCII. Schreibt man es "Straße:",
#    frisst der PERSON-Span den Zeilenumbruch mit und wird zu
#    'Maria Meier\nStraße' -- das Label verschwindet in der Maskierung. Ebenso
#    vermessen: Bulletstriche, Leerzeilen und kleingeschriebene Labels
#    erzeugen zusaetzlich ein LOCATION auf "DE89" (dem IBAN-Anfang).
#
# 3. Die Aufgabe ist als technischer Formatierungstest gerahmt, nicht als
#    Bitte um Personendaten. Mit der frueheren Formulierung ("Gib die
#    folgenden Angaben zurueck", Felder "Name/IBAN/Telefon") verweigerte
#    llama3.1:8b die Antwort -- "Ich kann keine Informationen zu bestimmten
#    Personen oder ihren Konten bereitstellen" -- und zwar auch bei
#    temperature 0 mal so, mal so. Das Modell sieht zwar nur Platzhalter,
#    liest die LABELS aber als Bitte um fremde Kontodaten. Der neue Rahmen
#    wurde gegen das Modell gemessen und liefert das Echo zuverlaessig.
#
# Anders gesagt: nicht "ASCII ist schlecht", sondern "gemessen statt geraten".
# Wer diesen Prompt anfasst, misst vorher gegen /analyze -- und PII_MASKED_RE
# unten faellt sofort auf, wenn doch etwas anderes maskiert wird.
PII_PROMPT = (
    "Das ist ein technischer Formatierungstest. Gib die folgenden vier Zeilen "
    "exakt und unverändert zurück, jede Zeile mit einem Bindestrich davor.\n"
    f"Name: {PII['person']}\n"
    f"Strasse: {PII['strasse']}\n"
    f"IBAN: {PII['iban']}\n"
    f"Telefon: {PII['telefon']}\n"
)

# Struktur, die im Upstream-Payload stehen MUSS. Sie prueft zweierlei zugleich:
# die vier Felder sind maskiert, UND der Anweisungssatz ist es NICHT. Damit
# wird aus dem Flake von oben ein lauter, sofort diagnostizierbarer Fehler --
# statt einer Verweigerung des Modells, die erst drei Schritte spaeter auffaellt.
PII_MASKED_RE = re.compile(
    r"Das ist ein technischer Formatierungstest\. Gib die folgenden vier Zeilen "
    r"exakt und unverändert zurück, jede Zeile mit einem Bindestrich davor\.\n"
    r"Name: (<PERSON_\d+>)\n"
    r"Strasse: (<DE_STRASSE_\d+>)\n"
    r"IBAN: (<IBAN_CODE_\d+>)\n"
    r"Telefon: (<PHONE_NUMBER_\d+>)\n"
)

# AK4: dieselbe Person zweimal, eine zweite Person einmal.
#
# Zur Wortwahl: der dritte Satz beginnt bewusst MIT dem Namen. Eine fruehere
# Fassung begann mit "Spaeter hat Maria Meier ..." -- Presidios deutsches
# NER-Modell hielt "Spaeter" am Satzanfang fuer einen Personennamen (0.85) und
# vergab dafuer einen dritten PERSON-Platzhalter. Bekanntes Muster, im Repo
# schon einmal notiert (ISA.md, "Fasse" am Satzanfang): deutsche
# Grossschreibung am Satzanfang produziert PERSON-False-Positives. Kein
# Privacy-Problem (Overmasking statt Leck), aber es haette diesen Test
# verrauscht statt die Zuordnungsstabilitaet zu pruefen.
STABILITY_SENTENCE = (
    "Maria Meier hat angerufen. Thomas Schneider war dabei. "
    "Maria Meier hat erneut angerufen."
)
STABILITY_PROMPT = f"Wiederhole diesen Text wortwörtlich:\n{STABILITY_SENTENCE}"

# Struktur, die im Upstream-Payload stehen MUSS: Position 1 und 3 derselbe
# Platzhalter (dieselbe Person), Position 2 ein anderer.
STABILITY_MASKED_RE = re.compile(
    r"(<PERSON_\d+>) hat angerufen\. (<PERSON_\d+>) war dabei\. "
    r"(<PERSON_\d+>) hat erneut angerufen\."
)

PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")


# --------------------------------------------------------------------------
# Kleine HTTP-Helfer (stdlib -- der Test soll ohne Extra-Deps laufen)
# --------------------------------------------------------------------------
def _req(url: str, *, data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None,
         timeout: float = 300.0) -> Tuple[int, bytes]:
    r = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _auth_headers() -> Dict[str, str]:
    return {"Content-Type": "application/json", "Authorization": f"Bearer {MASTER_KEY}"}


def chat(messages: List[Dict[str, Any]], *, stream: bool = False) -> Tuple[int, bytes]:
    body = {
        "model": MODEL,
        "messages": messages,
        "stream": stream,
        # Determinismus: das Modell soll nicht kreativ werden, sondern
        # zurueckgeben, was es bekommen hat.
        "temperature": 0.0,
        "max_tokens": 400,
    }
    return _req(f"{PROXY_URL}/v1/chat/completions", data=json.dumps(body).encode(),
                headers=_auth_headers())


def tap_reset(mode: str = "passthrough") -> None:
    status, raw = _req(f"{TAP_URL}/__tap/reset", data=json.dumps({"mode": mode}).encode(),
                       headers={"Content-Type": "application/json"})
    if status != 200:
        raise RuntimeError(f"Tap-Reset fehlgeschlagen: HTTP {status} {raw[:200]!r}")


def tap_records() -> List[Dict[str, Any]]:
    status, raw = _req(f"{TAP_URL}/__tap/records")
    if status != 200:
        raise RuntimeError(f"Tap-Records nicht lesbar: HTTP {status} {raw[:200]!r}")
    return json.loads(raw.decode())


# --------------------------------------------------------------------------
# Auswertung
# --------------------------------------------------------------------------
class Result:
    def __init__(self) -> None:
        self.failures: List[str] = []
        self.notes: List[str] = []

    def check(self, ok: bool, label: str, detail: str = "") -> bool:
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {label}"
        if detail:
            line += f"\n         {detail}"
        print(line, flush=True)
        if not ok:
            self.failures.append(label)
        return ok

    def note(self, text: str) -> None:
        print(f"  [INFO] {text}", flush=True)
        self.notes.append(text)


def upstream_prompt_text(record: Dict[str, Any], roles: Optional[Tuple[str, ...]] = None) -> str:
    """Der Text, den das LLM zu sehen bekam.

    ``roles`` grenzt auf bestimmte Message-Rollen ein. Wichtig fuer AK4: die
    Datenschleuse haengt einen Anonymisierungs-Hinweis als System-Message an,
    der das Platzhalter-SCHEMA erklaert. Fuer die Frage "bekommt derselbe Wert
    denselben Platzhalter?" zaehlen nur die Nutzdaten, nicht die Erklaerung --
    sonst misst man den Hinweistext mit."""
    body = record.get("request_json") or {}
    out = []
    for msg in body.get("messages", []) or []:
        if roles is not None and msg.get("role") not in roles:
            continue
        content = msg.get("content")
        if isinstance(content, str):
            out.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    out.append(part["text"])
    return "\n".join(out)


def assemble_upstream_answer(record: Dict[str, Any]) -> str:
    """Rekonstruiert die Antwort, wie sie das LLM geliefert hat (VOR
    Re-Identifikation) -- non-streaming wie streaming."""
    if not record.get("stream"):
        body = record.get("response_json") or {}
        try:
            return body["choices"][0]["message"]["content"] or ""
        except Exception:
            return ""
    text = []
    for line in record.get("upstream_chunks", []):
        payload = _sse_payload(line)
        if payload is None:
            continue
        try:
            text.append(payload["choices"][0]["delta"].get("content") or "")
        except Exception:
            continue
    return "".join(text)


def _sse_payload(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line.startswith("data:"):
        return None
    data = line[len("data:"):].strip()
    if not data or data == "[DONE]":
        return None
    try:
        return json.loads(data)
    except Exception:
        return None


def assemble_client_stream(raw_sse: str) -> Tuple[str, List[str]]:
    """(zusammengesetzter Text, Liste der einzelnen Deltas) aus der SSE-Antwort,
    die der CLIENT gelesen hat."""
    parts: List[str] = []
    for line in raw_sse.splitlines():
        payload = _sse_payload(line)
        if payload is None:
            continue
        try:
            delta = payload["choices"][0]["delta"].get("content")
        except Exception:
            continue
        if isinstance(delta, str) and delta:
            parts.append(delta)
    return "".join(parts), parts


def normalized_variants(value: str) -> List[str]:
    """Ein IBAN-Leak bleibt ein Leak, auch ohne Leerzeichen."""
    v = value.strip()
    out = {v, v.replace(" ", ""), v.lower(), v.replace(" ", "").lower()}
    return [x for x in out if x]


def roundtrip_ok(upstream_answer: str, client_answer: str, reid_pairs: Dict[str, str],
                 res: Result, label: str) -> bool:
    """Kernpruefung: fuer JEDEN Platzhalter, den das LLM zurueckgegeben hat,
    muss beim Client der Klartext stehen -- und der Platzhalter darf weg sein."""
    placeholders = PLACEHOLDER_RE.findall(upstream_answer)
    unique = sorted(set(placeholders))
    ok = res.check(
        len(unique) >= 3,
        f"{label}: LLM hat genug Platzhalter zurueckgegeben (>=3)",
        f"zurueckgegeben: {unique}",
    )
    all_ok = ok
    for ph in unique:
        clear = reid_pairs.get(ph)
        if clear is None:
            res.note(f"{label}: Platzhalter {ph} nicht in der erwarteten PII-Liste "
                     f"-- wird nur auf 'nicht mehr vorhanden' geprueft")
        else:
            all_ok &= res.check(
                clear in client_answer,
                f"{label}: Klartext fuer {ph} kommt beim Client an",
                f"erwartet: {clear!r}",
            )
        all_ok &= res.check(
            ph not in client_answer,
            f"{label}: Platzhalter {ph} ist beim Client verschwunden",
        )
    return all_ok


def check_masking_precondition(res: Result, label: str, upstream_user_text: str) -> bool:
    """Vorbedingung JEDES Laufs: es wurde genau das maskiert, was maskiert
    gehoert -- die vier PII-Felder -- und der Anweisungssatz blieb unangetastet.

    Warum das eine eigene Pruefung ist: maskiert Presidio versehentlich ein
    Wort der Anweisung mit, bekommt das Modell einen kaputten Satz und
    verweigert womoeglich die Antwort. Der Lauf faellt dann weiter unten mit
    'LLM hat keine Platzhalter zurueckgegeben' um -- eine Meldung, die auf die
    falsche Faehrte fuehrt und wie ein sporadischer Fehler des Round-Trips
    aussieht, obwohl der Round-Trip nie an die Reihe kam. Diese Pruefung nennt
    die wahre Ursache sofort."""
    m = PII_MASKED_RE.search(upstream_user_text)
    if not res.check(
        bool(m),
        f"{label}: Vorbedingung -- genau die vier PII-Felder maskiert, Anweisung unberuehrt",
        f"vorgefunden: {upstream_user_text!r}",
    ):
        return False
    fremd = [p for p in PLACEHOLDER_RE.findall(upstream_user_text) if p not in m.groups()]
    return res.check(
        not fremd,
        f"{label}: Vorbedingung -- kein zusaetzlicher, unerwarteter Platzhalter",
        f"unerwartet maskiert: {fremd}" if fremd else "",
    )


def build_reid_expectation(upstream_prompt: str) -> Dict[str, str]:
    """Ordnet jeden Platzhalter aus dem UPSTREAM-Prompt dem Klartext zu, der an
    derselben Stelle im ORIGINAL-Prompt stand. Rein positionell -- wir raten
    nicht, wir lesen ab."""
    mapping: Dict[str, str] = {}
    # Zeilenweise vergleichen: "Name: <PERSON_0>" vs "Name: Maria Meier"
    orig_lines = {l.split(":", 1)[0].strip(): l.split(":", 1)[1].strip()
                  for l in PII_PROMPT.splitlines() if ":" in l}
    for line in upstream_prompt.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key not in orig_lines:
            continue
        phs = PLACEHOLDER_RE.findall(value)
        if len(phs) == 1 and value == phs[0]:
            mapping[phs[0]] = orig_lines[key]
    return mapping


# --------------------------------------------------------------------------
# Artefakte
# --------------------------------------------------------------------------
def write_artifact(name: str, content: str) -> str:
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    path = os.path.join(ARTIFACT_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def banner(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}", flush=True)


# --------------------------------------------------------------------------
# Die einzelnen Akzeptanzkriterien
# --------------------------------------------------------------------------
def ak1_non_streaming(res: Result) -> Optional[Dict[str, Any]]:
    banner("AK1 -- Non-Streaming-Roundtrip mit echter deutscher PII")
    tap_reset("passthrough")
    status, raw = chat([{"role": "user", "content": PII_PROMPT}], stream=False)
    body = raw.decode("utf-8", "replace")
    write_artifact("ak1-client-response.json", body)
    if not res.check(status == 200, "AK1: Proxy antwortet mit HTTP 200", f"HTTP {status}: {body[:400]}"):
        return None

    client_answer = ""
    try:
        client_answer = json.loads(body)["choices"][0]["message"]["content"] or ""
    except Exception as exc:
        res.check(False, "AK1: Antwort ist parsebar", str(exc))
        return None

    records = tap_records()
    if not res.check(len(records) == 1, "AK1: genau ein Upstream-Call mitgeschnitten",
                     f"{len(records)} Records"):
        return None
    rec = records[0]
    write_artifact("ak1-upstream-record.json", json.dumps(rec, ensure_ascii=False, indent=2))

    prompt_seen_by_llm = upstream_prompt_text(rec)
    upstream_answer = assemble_upstream_answer(rec)
    reid = build_reid_expectation(prompt_seen_by_llm)
    check_masking_precondition(res, "AK1", upstream_prompt_text(rec, roles=("user",)))

    print("\n--- Was das LLM gesehen hat (Upstream-Prompt) ---")
    print(prompt_seen_by_llm)
    print("\n--- Was das LLM geantwortet hat (vor Re-Identifikation) ---")
    print(upstream_answer)
    print("\n--- Was der Client gelesen hat (nach Re-Identifikation) ---")
    print(client_answer)
    print()

    roundtrip_ok(upstream_answer, client_answer, reid, res, "AK1")
    return rec


def ak3_llm_never_saw_cleartext(res: Result, records: List[Dict[str, Any]]) -> None:
    banner("AK3 -- Beweis: das LLM hat den Klartext nie gesehen")
    combined = "\n\n".join(json.dumps(r.get("request_json"), ensure_ascii=False) for r in records)
    write_artifact("ak3-upstream-payloads.json",
                   json.dumps([r.get("request_json") for r in records], ensure_ascii=False, indent=2))
    haystack = combined.lower()
    for label, value in PII.items():
        leaked = [v for v in normalized_variants(value) if v.lower() in haystack]
        res.check(not leaked, f"AK3: {label} ({value!r}) steht NICHT im Upstream-Payload",
                  f"gefundene Varianten: {leaked}" if leaked else "")
    all_ph = set()
    for r in records:
        all_ph |= set(PLACEHOLDER_RE.findall(upstream_prompt_text(r)))
    res.check(any(p.startswith("<PERSON_") for p in all_ph),
              "AK3: stattdessen steht ein <PERSON_N>-Platzhalter im Upstream-Payload",
              f"Platzhalter im Upstream: {sorted(all_ph)}")


def ak2_streaming(res: Result, mode: str) -> Optional[Dict[str, Any]]:
    banner(f"AK2 -- Streaming-Roundtrip (Tap-Modus: {mode})")
    tap_reset(mode)
    body = {
        "model": MODEL,
        "messages": [{"role": "user", "content": PII_PROMPT}],
        "stream": True,
        "temperature": 0.0,
        "max_tokens": 400,
    }
    status, raw = _req(f"{PROXY_URL}/v1/chat/completions", data=json.dumps(body).encode(),
                       headers=_auth_headers())
    sse = raw.decode("utf-8", "replace")
    write_artifact(f"ak2-{mode}-client-stream.sse", sse)
    if not res.check(status == 200, f"AK2/{mode}: Proxy antwortet mit HTTP 200",
                     f"HTTP {status}: {sse[:400]}"):
        return None

    client_answer, deltas = assemble_client_stream(sse)
    records = tap_records()
    if not res.check(len(records) == 1, f"AK2/{mode}: genau ein Upstream-Call mitgeschnitten",
                     f"{len(records)} Records"):
        return None
    rec = records[0]
    write_artifact(f"ak2-{mode}-upstream-record.json", json.dumps(rec, ensure_ascii=False, indent=2))

    upstream_answer = assemble_upstream_answer(rec)
    reid = build_reid_expectation(upstream_prompt_text(rec))
    check_masking_precondition(res, f"AK2/{mode}", upstream_prompt_text(rec, roles=("user",)))

    # Wurde ein Platzhalter tatsaechlich ueber eine Chunk-Grenze zerrissen?
    forwarded_deltas = []
    for line in rec.get("forwarded_chunks", []):
        payload = _sse_payload(line)
        if payload is None:
            continue
        try:
            d = payload["choices"][0]["delta"].get("content")
        except Exception:
            continue
        if isinstance(d, str) and d:
            forwarded_deltas.append(d)
    split_ph = _placeholders_split_across_chunks(forwarded_deltas)

    print(f"\n--- Roh-Stream an den Client ({len(deltas)} Content-Chunks), erste 40 ---")
    print(json.dumps(deltas[:40], ensure_ascii=False))
    print(f"\n--- Chunks, die LiteLLM vom Upstream bekam ({len(forwarded_deltas)}), erste 40 ---")
    print(json.dumps(forwarded_deltas[:40], ensure_ascii=False))
    print("\n--- Zusammengesetztes Ergebnis beim Client ---")
    print(client_answer)
    print()

    res.check(bool(split_ph),
              f"AK2/{mode}: mindestens ein Platzhalter wurde ueber Chunk-Grenzen zerrissen",
              f"zerrissen: {sorted(split_ph)}")
    roundtrip_ok(upstream_answer, client_answer, reid, res, f"AK2/{mode}")
    return rec


def _placeholders_split_across_chunks(deltas: List[str]) -> List[str]:
    """Welche Platzhalter lagen NICHT vollstaendig in einem einzelnen Chunk?"""
    joined = "".join(deltas)
    out = []
    for ph in set(PLACEHOLDER_RE.findall(joined)):
        if not any(ph in d for d in deltas):
            out.append(ph)
    return out


def ak4_stable_mapping(res: Result) -> Optional[Dict[str, Any]]:
    banner("AK4 -- Stabile Zuordnung (gleicher Wert = gleicher Platzhalter)")
    tap_reset("passthrough")
    status, raw = chat([{"role": "user", "content": STABILITY_PROMPT}], stream=False)
    body = raw.decode("utf-8", "replace")
    write_artifact("ak4-client-response.json", body)
    if not res.check(status == 200, "AK4: Proxy antwortet mit HTTP 200", f"HTTP {status}: {body[:400]}"):
        return None
    records = tap_records()
    if not records:
        res.check(False, "AK4: Upstream-Call mitgeschnitten")
        return None
    rec = records[0]
    write_artifact("ak4-upstream-record.json", json.dumps(rec, ensure_ascii=False, indent=2))
    # Nur die Nutzdaten-Message, nicht der Hinweistext (siehe upstream_prompt_text).
    payload_seen = upstream_prompt_text(rec, roles=("user",))
    full_seen = upstream_prompt_text(rec)
    print("\n--- Was das LLM als Nutzdaten gesehen hat ---")
    print(payload_seen)
    print()

    m = STABILITY_MASKED_RE.search(payload_seen)
    if not res.check(bool(m),
                     "AK4: maskierter Satz hat die erwartete Struktur",
                     f"vorgefunden: {payload_seen!r}"):
        return rec
    first, second, third = m.group(1), m.group(2), m.group(3)
    res.check(first == third,
              "AK4: dieselbe Person bekommt beide Male DENSELBEN Platzhalter",
              f"1. Nennung: {first} / 3. Nennung: {third}")
    res.check(first != second,
              "AK4: die zweite, andere Person bekommt einen ANDEREN Platzhalter",
              f"Maria: {first} / Thomas: {second}")
    res.check("Maria Meier" not in full_seen and "Thomas Schneider" not in full_seen,
              "AK4: kein Personenname im gesamten Upstream-Payload")
    return rec


# --------------------------------------------------------------------------
def main() -> int:
    if not MASTER_KEY:
        print("DS_E2E_MASTER_KEY ist nicht gesetzt -- bitte ueber "
              "test/run-e2e-roundtrip.sh starten.", file=sys.stderr)
        return 2

    banner("Datenschleuse Round-Trip E2E (DATENSCHLE-67)")
    print(f"Proxy : {PROXY_URL}\nTap   : {TAP_URL}\nModell: {MODEL}\nArtefakte: {ARTIFACT_DIR}")

    res = Result()
    upstream_records: List[Dict[str, Any]] = []

    rec = ak1_non_streaming(res)
    if rec:
        upstream_records.append(rec)

    for mode in ("passthrough", "shred"):
        rec = ak2_streaming(res, mode)
        if rec:
            upstream_records.append(rec)

    rec = ak4_stable_mapping(res)
    if rec:
        upstream_records.append(rec)

    if upstream_records:
        # AK3 wertet ALLE mitgeschnittenen Upstream-Payloads gemeinsam aus.
        ak3_llm_never_saw_cleartext(res, upstream_records)
    else:
        res.check(False, "AK3: es gab ueberhaupt Upstream-Payloads zum Pruefen")

    banner("ERGEBNIS")
    if res.failures:
        print(f"{len(res.failures)} Pruefung(en) fehlgeschlagen:")
        for f in res.failures:
            print(f"  - {f}")
        return 1
    print("Alle Akzeptanzkriterien erfuellt. Artefakte liegen in:")
    print(f"  {ARTIFACT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
