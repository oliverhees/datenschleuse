#!/usr/bin/env python3
"""Mitschneidender Upstream-Tap fuer den Round-Trip-Beweis (DATENSCHLE-67).

Sitzt zwischen dem LiteLLM-Proxy (Datenschleuse) und dem echten LLM:

    Client -> LiteLLM (Datenschleuse) -> [ TAP ] -> Ollama

Warum es diesen Tap gibt
------------------------
AK3 verlangt den Nachweis, dass das LLM den Klartext nie zu sehen bekommt.
Ein Nachweis aus dem Guardrail-Code selbst waere zirkulaer -- er wuerde das
Verhalten aus derselben Quelle belegen, die geprueft werden soll. Der Tap
protokolliert deshalb den Payload GENAU DA, wo er das Vertrauensgebiet
verlaesst: auf der Leitung zum Modell.

Zweite Aufgabe: ``mode="shred"``
--------------------------------
Ob ein Platzhalter ueber eine SSE-Chunk-Grenze zerrissen wird, entscheidet
sonst der Tokenizer des Modells -- also Zufall. Im Shred-Modus zerlegt der Tap
jeden Content-Delta in Ein-Zeichen-Events. Damit steht garantiert JEDER
Platzhalter zerrissen im Stream, und AK2 wird deterministisch statt hoffnungs-
voll (Methode #12).

Nur Standardbibliothek -- laeuft in einem nackten python:3.12-slim ohne pip.
"""

from __future__ import annotations

import http.client
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

UPSTREAM = os.getenv("TAP_UPSTREAM", "http://lokyy-brain-ollama-1:11434")
PORT = int(os.getenv("TAP_PORT", "8080"))
UPSTREAM_TIMEOUT = float(os.getenv("TAP_UPSTREAM_TIMEOUT", "600"))

_LOCK = threading.Lock()
_RECORDS: List[Dict[str, Any]] = []
_MODE = "passthrough"  # "passthrough" | "shred"


def _record(entry: Dict[str, Any]) -> None:
    with _LOCK:
        _RECORDS.append(entry)


def _sse_lines(raw: bytes) -> List[str]:
    return [l for l in raw.decode("utf-8", "replace").splitlines() if l.strip()]


def _shred_sse_line(line: str) -> List[str]:
    """Zerlegt eine ``data:``-Zeile mit Mehrzeichen-Delta in mehrere Zeilen mit
    je EINEM Zeichen. Alles andere (``[DONE]``, Chunks ohne Content, kaputte
    Zeilen) bleibt unveraendert -- der Tap erfindet nichts."""
    stripped = line.strip()
    if not stripped.startswith("data:"):
        return [line]
    payload = stripped[len("data:"):].strip()
    if not payload or payload == "[DONE]":
        return [line]
    try:
        obj = json.loads(payload)
        choices = obj["choices"]
        delta = choices[0]["delta"]
        content = delta.get("content")
    except Exception:
        return [line]
    if not isinstance(content, str) or len(content) <= 1:
        return [line]

    out: List[str] = []
    for i, ch in enumerate(content):
        clone = json.loads(payload)  # frische Kopie, keine geteilten Referenzen
        clone["choices"][0]["delta"]["content"] = ch
        if i < len(content) - 1:
            # finish_reason gehoert nur an das letzte Teilstueck, sonst wuerde
            # der Stream fuer den Empfaenger vorzeitig enden.
            clone["choices"][0]["finish_reason"] = None
        out.append("data: " + json.dumps(clone, ensure_ascii=False))
    return out


class TapHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DatenschleuseTap/1.0"

    # ---- Logging: eigenes Format, ohne Payload (Gesetz 5) -----------------
    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[tap] {self.address_string()} {fmt % args}", flush=True)

    # ---- Kontroll-API -----------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/__tap/records":
            with _LOCK:
                body = json.dumps(_RECORDS, ensure_ascii=False).encode()
            self._respond(200, body, "application/json")
            return
        if self.path == "/__tap/health":
            self._respond(200, b'{"ok":true}', "application/json")
            return
        self._respond(404, b'{"error":"unknown tap route"}', "application/json")

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/__tap/reset":
            global _MODE
            raw = self._read_body()
            mode = "passthrough"
            try:
                mode = (json.loads(raw or b"{}") or {}).get("mode") or "passthrough"
            except Exception:
                pass
            if mode not in ("passthrough", "shred"):
                self._respond(400, b'{"error":"mode must be passthrough|shred"}',
                              "application/json")
                return
            with _LOCK:
                _RECORDS.clear()
                _MODE = mode
            self._respond(200, json.dumps({"ok": True, "mode": mode}).encode(),
                          "application/json")
            return
        self._proxy()

    # ---- Proxy ------------------------------------------------------------
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _proxy(self) -> None:
        body = self._read_body()
        try:
            request_json: Optional[Dict[str, Any]] = json.loads(body or b"{}")
        except Exception:
            request_json = None
        is_stream = bool(isinstance(request_json, dict) and request_json.get("stream"))

        with _LOCK:
            mode = _MODE

        entry: Dict[str, Any] = {
            "path": self.path,
            "stream": is_stream,
            "mode": mode,
            "request_raw": body.decode("utf-8", "replace"),
            "request_json": request_json,
            "upstream_chunks": [],
            "forwarded_chunks": [],
            "response_json": None,
        }

        up = urlparse(UPSTREAM)
        conn = http.client.HTTPConnection(up.hostname, up.port or 80, timeout=UPSTREAM_TIMEOUT)
        headers = {"Content-Type": "application/json",
                   "Authorization": self.headers.get("Authorization", "Bearer tap"),
                   "Accept": self.headers.get("Accept", "*/*")}
        try:
            conn.request("POST", (up.path.rstrip("/") + self.path) or self.path, body=body,
                         headers=headers)
            resp = conn.getresponse()
        except Exception as exc:
            _record(entry)
            self._respond(502, json.dumps({"error": f"tap upstream failed: {exc}"}).encode(),
                          "application/json")
            return

        if not is_stream:
            raw = resp.read()
            entry["upstream_chunks"] = [raw.decode("utf-8", "replace")]
            entry["forwarded_chunks"] = list(entry["upstream_chunks"])
            try:
                entry["response_json"] = json.loads(raw)
            except Exception:
                entry["response_json"] = None
            _record(entry)
            conn.close()
            self._respond(resp.status, raw,
                          resp.getheader("Content-Type") or "application/json")
            return

        # --- Streaming: Zeile fuer Zeile weiterreichen (chunked) -----------
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.getheader("Content-Type") or "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        try:
            while True:
                line = resp.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip("\r\n")
                if not text.strip():
                    self._write_chunk(b"\n")
                    continue
                entry["upstream_chunks"].append(text)
                for out_line in (_shred_sse_line(text) if mode == "shred" else [text]):
                    entry["forwarded_chunks"].append(out_line)
                    self._write_chunk((out_line + "\n\n").encode("utf-8"))
        except Exception as exc:  # pragma: no cover - Netzwerkabbruch
            print(f"[tap] Streamfehler: {exc}", flush=True)
        finally:
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except Exception:
                pass
            conn.close()
            _record(entry)

    def _write_chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n")
        self.wfile.flush()

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()


def main() -> None:
    print(f"[tap] listening on :{PORT}, upstream={UPSTREAM}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), TapHandler).serve_forever()


if __name__ == "__main__":
    main()
