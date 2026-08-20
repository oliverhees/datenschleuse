"""PoC-Nachstellung der drei High-Findings aus dem Security-Gate zu
DATENSCHLE-69 (zweite Runde). Kein Unit-Test, sondern der Beleg in genau der
Form, in der der Pruefer die Lecks gemeldet hat -- damit "behoben" nicht
geglaubt, sondern gesehen wird (Methode #10).

Ausfuehren (aus dem Repo-Root):
    python3 test/poc_datenschle_69_toplevel.py
"""

import asyncio
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "litellm")))

import datenschleuse_guardrail as dg  # noqa: E402
import qi_state as qs  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

IBAN = "DE02120300000000202051"
NAME = "Max Mustermann"
NEEDLES = ((NAME, "PERSON"), (IBAN, "IBAN_CODE"))
QI_TEXT = "Patientin, PLZ 81675, Jahrgang 1978, Lehrerin"
QI_MAP = {"81675": "DE_PLZ", "1978": "DE_GEBURTSJAHR", "Lehrerin": "DE_BERUF"}


def analyzer(mapping):
    async def fake(text):
        out = []
        for value, etype in mapping:
            start = 0
            while (idx := text.find(value, start)) >= 0:
                out.append({"entity_type": etype, "start": idx,
                            "end": idx + len(value), "score": 0.99})
                start = idx + len(value)
        return out
    return fake


def outgoing(payload):
    """Was den Provider erreicht -- ohne das reid_map, das bewusst lokal
    bleibt und litellms all_litellm_params-Filter nie passiert."""
    clone = dict(payload)
    if isinstance(clone.get("metadata"), dict):
        clone["metadata"] = {k: v for k, v in clone["metadata"].items()
                             if k != dg.REID_MAP_KEY}
    return json.dumps(clone, ensure_ascii=False, default=str)


async def call(data, call_type, guard=None):
    guard = guard or dg.DatenschleuseGuardrail()
    if not hasattr(guard._analyze, "_patched"):
        guard._analyze = analyzer(NEEDLES)
    return await guard.async_pre_call_hook(
        user_api_key_dict=None, cache=None, data=data, call_type=call_type
    )


def verdict(label, leaked, detail=""):
    mark = "LEAK  " if leaked else "DICHT "
    print(f"[{mark}] {label}{(' -- ' + detail) if detail else ''}")
    return leaked


async def main():
    leaks = 0

    # --- F1: Geschwisterfelder des prompt ---------------------------------
    for label, extra in (
        ("atext_completion, prompt(clean) + suffix(PII)",
         {"suffix": f" Kunde {NAME}, IBAN {IBAN}"}),
        ("atext_completion, prompt + stop(PII)", {"stop": [f"Ende {NAME}"]}),
    ):
        data = {"model": "m", "prompt": "Schreibe die Rechnung fertig:", **extra}
        try:
            out = await call(data, "atext_completion")
            flat = outgoing(out)
            leaks += verdict(label, IBAN in flat or NAME in flat, "durchgelaufen")
        except dg.DatenschleuseBlocked:
            verdict(label, False, "geblockt")

    # --- F3: Chat-Route ohne Payload-Formpruefung -------------------------
    for label, data in (
        ("acompletion, messages(clean) + top-level prompt(PII)",
         {"model": "m", "messages": [{"role": "user", "content": "hi"}],
          "prompt": f"IBAN {IBAN}"}),
        ("acompletion, NO messages, prompt(PII)",
         {"model": "m", "prompt": f"IBAN {IBAN}"}),
        ("acompletion, messages(clean) + tools[].function.description(PII)",
         {"model": "m", "messages": [{"role": "user", "content": "hi"}],
          "tools": [{"type": "function", "function": {
              "name": "kontostand",
              "description": f"Kontostand von {NAME}, IBAN {IBAN}"}}]}),
    ):
        try:
            out = await call(data, "acompletion")
            flat = outgoing(out)
            leaks += verdict(label, IBAN in flat or NAME in flat, "durchgelaufen")
        except dg.DatenschleuseBlocked:
            verdict(label, False, "geblockt")

    # --- F2: QI-Generalisierung bei Listen-prompt -------------------------
    print()
    print(f"INPUT :          {QI_TEXT}")
    ergebnisse = {}
    for label, data, ct in (
        ("CHAT         ", {"model": "m",
                           "messages": [{"role": "user", "content": QI_TEXT}],
                           "metadata": {"session_id": "a"}}, "acompletion"),
        ("prompt=STRING", {"model": "m", "prompt": QI_TEXT,
                           "metadata": {"session_id": "b"}}, "atext_completion"),
        ("prompt=LIST  ", {"model": "m", "prompt": [QI_TEXT],
                           "metadata": {"session_id": "c"}}, "atext_completion"),
    ):
        store = qs.QiStateStore(db_path=":memory:", fernet_key=Fernet.generate_key())
        guard = dg.DatenschleuseGuardrail(qi_risk_preset="paranoid", qi_store=store)
        guard._analyze = analyzer(tuple(QI_MAP.items()))
        guard._analyze._patched = True
        out = await call(data, ct, guard=guard)
        text = (next(m for m in out["messages"] if m.get("role") == "user")["content"]
                if ct == "acompletion" else
                (out["prompt"][0] if isinstance(out["prompt"], list) else out["prompt"]))
        ergebnisse[label] = text
        print(f"{label} -> {text}")
    roh = [lbl for lbl, txt in ergebnisse.items() if "81675" in txt or "1978" in txt]
    leaks += verdict("QI ueber alle drei Wege identisch",
                     bool(roh) or len(set(ergebnisse.values())) != 1,
                     f"roh in: {roh}" if roh else "")

    # --- Transport-Umschlag (Security-Gate 2) -----------------------------
    # Diese Keys stehen alle in litellms all_litellm_params -- sie erfuellen
    # also das ALTE, zu enge Kriterium ("nicht im Body") -- und gehen trotzdem
    # hinaus, als HTTP-Header auf der Leitung. Gemessen mit einem
    # mitschneidenden Provider-Server gegen echtes litellm 1.97.0.
    print()
    for label, extra in (
        ("acompletion, headers(PII)",
         {"headers": {"x-notiz": f"Patient {NAME}, IBAN {IBAN}"}}),
        ("acompletion, provider_specific_header(PII)",
         {"provider_specific_header": {"custom_llm_provider": "openai",
                                       "extra_headers": {"x-notiz": IBAN}}}),
        ("acompletion, model_list[].extra_headers(PII)",
         {"model_list": [{"model_name": "gpt-4o", "litellm_params": {
             "model": "openai/gpt-4o",
             "extra_headers": {"x-notiz": IBAN}}}]}),
    ):
        data = {"model": "m", "messages": [{"role": "user", "content": "hi"}],
                **extra}
        try:
            out = await call(data, "acompletion")
            flat = outgoing(out)
            leaks += verdict(label, IBAN in flat or NAME in flat, "durchgelaufen")
        except dg.DatenschleuseBlocked:
            verdict(label, False, "geblockt")

    print()
    print("ERGEBNIS:", "ALLE PoCs DICHT" if leaks == 0 else f"{leaks} LECK(S) OFFEN")
    return 1 if leaks else 0


sys.exit(asyncio.run(main()))
