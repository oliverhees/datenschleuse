"""Datenschleuse — verschluesselter, TTL-begrenzter Session-State fuer Quasi-Identifier.

Zweck
-----
Presidio ist zustandslos. Um Quasi-Identifier (QI) ueber mehrere Requests einer
Konversation hinweg zu AKKUMULIEREN (und ab einem Schwellwert zu generalisieren),
brauchen wir einen kleinen persistenten Zustand pro Session. Dieses Modul liefert
ihn -- bewusst mit denselben Sicherheits-Leitplanken wie das bestehende
Re-Identification-Mapping (CLAUDE.md): **verschluesselt + lokal + TTL-begrenzt**.

Sicherheits-Design
------------------
1. **Kein Rohwert wird je persistiert.** Gespeichert wird pro Session nur:
   QI-Typ (z.B. ``DE_PLZ``) + bereits GENERALISIERTE Kategorie (z.B.
   ``Region Bayern (Süd)/...``) -- niemals ``84028``. Die Generalisierung
   passiert VOR dem Schreiben (siehe qi_generalization.state_category).
2. **Verschluesselung at rest.** Die generalisierte Kategorie wird zusaetzlich
   mit Fernet (symmetrisch, ``cryptography``) verschluesselt. Der Session-Key
   selbst (kann ein API-Key-Hash sein) wird per SHA-256 gehasht abgelegt, nie
   im Klartext.
3. **Fail-closed beim Schluessel.** Fehlt ``DATENSCHLEUSE_STATE_KEY`` (oder ist
   er kein gueltiger Fernet-Key), wird der Store beim KONSTRUIEREN hart mit
   ``QiStateError`` abgebrochen -- es wird NIE unverschluesselt weitergelaufen.
   docker-compose erzwingt die Var zusaetzlich per ``:?``-Guard (wie UI_PASSWORD).
4. **TTL.** Eintraege aelter als ``ttl_seconds`` (Default 24 h) werden bei jedem
   Zugriff (get/record) weggeraeumt -- kein Cron noetig fuer v1.

Lokale SQLite-Datei (Python-Stdlib), keine neue Infrastruktur-Abhaengigkeit.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from typing import Callable, Iterable, List, Optional, Set, Tuple

# cryptography ist eine harte Laufzeit-Abhaengigkeit dieses Moduls (Fernet).
# Der Import steht bewusst oben: wer den QI-State nutzt, MUSS verschluesseln
# koennen -- ein fehlendes Paket ist ein Fehlkonfigurations-Fehler, kein
# "dann eben unverschluesselt".
from cryptography.fernet import Fernet


STATE_KEY_ENV = "DATENSCHLEUSE_STATE_KEY"
STATE_DB_ENV = "DATENSCHLEUSE_STATE_DB"
DEFAULT_DB_PATH = "/app/state/qi_state.db"
DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24 h


class QiStateError(Exception):
    """Harte Fehlkonfiguration des QI-State-Stores (z.B. Schluessel fehlt).

    Wird beim Konstruieren geworfen -> fail-closed beim Start, nie
    unverschluesselter Weiterbetrieb."""


class QiStateStore:
    """Verschluesselter, TTL-begrenzter SQLite-Store fuer akkumulierte QI-Typen.

    Tabelle ``qi_session_state``:
      * ``session_hash``  -- SHA-256 des Session-Keys (nie Klartext)
      * ``qi_type``       -- z.B. ``DE_PLZ`` (Kategoriename, kein PII)
      * ``category_enc``  -- Fernet-verschluesselte, bereits generalisierte
                             Kategorie (nie der Rohwert)
      * ``created_at``    -- Unix-Zeitstempel (float) fuer TTL

    Primaerschluessel (session_hash, qi_type): pro Session zaehlt jeder QI-TYP
    genau einmal (Akkumulation = Anzahl distinkter Typen). Ein erneutes Auftreten
    desselben Typs aktualisiert nur den Zeitstempel (haelt die Session frisch).
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        fernet_key: Optional[bytes] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        raw_key = fernet_key if fernet_key is not None else os.getenv(STATE_KEY_ENV)
        if not raw_key:
            raise QiStateError(
                f"{STATE_KEY_ENV} ist nicht gesetzt. Der QI-State-Store darf nur "
                "verschluesselt laufen (fail-closed). Setze einen Fernet-Key "
                "(z.B. `python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\"`) in der .env."
            )
        if isinstance(raw_key, str):
            raw_key = raw_key.encode()
        try:
            self._fernet = Fernet(raw_key)
        except Exception as exc:  # ungueltiges Key-Format
            raise QiStateError(
                f"{STATE_KEY_ENV} ist kein gueltiger Fernet-Key (erwartet 32 "
                f"url-safe base64 Bytes): {exc}"
            ) from exc

        self.ttl_seconds = int(ttl_seconds)
        self._clock = clock
        self.db_path = db_path or os.getenv(STATE_DB_ENV) or DEFAULT_DB_PATH
        self._lock = threading.Lock()

        if self.db_path != ":memory:":
            parent = os.path.dirname(self.db_path)
            if parent:
                os.makedirs(parent, exist_ok=True)

        # check_same_thread=False + eigener Lock: LiteLLM laeuft async in einem
        # Prozess; die kurzen, gelockten Zugriffe sind unkritisch.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_schema()

    # ---- interne Helfer ---------------------------------------------------
    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qi_session_state (
                    session_hash TEXT NOT NULL,
                    qi_type      TEXT NOT NULL,
                    category_enc BLOB NOT NULL,
                    created_at   REAL NOT NULL,
                    PRIMARY KEY (session_hash, qi_type)
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_qi_created_at "
                "ON qi_session_state (created_at)"
            )
            self._conn.commit()

    @staticmethod
    def _hash_key(session_key: str) -> str:
        return hashlib.sha256(session_key.encode("utf-8")).hexdigest()

    def _now(self) -> float:
        return float(self._clock())

    def _cutoff(self) -> float:
        return self._now() - self.ttl_seconds

    # ---- oeffentliche API -------------------------------------------------
    def cleanup(self) -> int:
        """Loescht alle Eintraege aelter als die TTL. Gibt die Anzahl geloeschter
        Zeilen zurueck. Wird bei jedem get/record automatisch aufgerufen."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM qi_session_state WHERE created_at < ?", (self._cutoff(),)
            )
            self._conn.commit()
            return cur.rowcount if cur.rowcount is not None else 0

    def get_seen_types(self, session_key: str) -> Set[str]:
        """Menge der bereits (innerhalb der TTL) fuer diese Session gesehenen
        QI-Typen. Raeumt vorher abgelaufene Eintraege weg."""
        if not session_key:
            return set()
        self.cleanup()
        session_hash = self._hash_key(session_key)
        with self._lock:
            rows = self._conn.execute(
                "SELECT qi_type FROM qi_session_state "
                "WHERE session_hash = ? AND created_at >= ?",
                (session_hash, self._cutoff()),
            ).fetchall()
        return {r[0] for r in rows}

    def record(self, session_key: str, qi_type: str, generalized_category: str) -> None:
        """Merkt sich, dass ``qi_type`` in dieser Session auftrat -- mit der
        bereits GENERALISIERTEN (nie rohen) Kategorie, Fernet-verschluesselt.

        Erneutes Auftreten desselben Typs aktualisiert nur den Zeitstempel
        (haelt die Session frisch), erhoeht aber nicht die Typ-Zahl."""
        if not session_key or not qi_type:
            return
        self.record_many(session_key, [(qi_type, generalized_category)])

    def record_many(
        self, session_key: str, items: Iterable[Tuple[str, str]]
    ) -> None:
        """Batch-Variante von :meth:`record` fuer mehrere QI-Typen eines Turns."""
        if not session_key:
            return
        session_hash = self._hash_key(session_key)
        now = self._now()
        rows: List[Tuple[str, str, bytes, float]] = []
        for qi_type, category in items:
            if not qi_type:
                continue
            token = self._fernet.encrypt((category or "").encode("utf-8"))
            rows.append((session_hash, qi_type, token, now))
        if not rows:
            return
        with self._lock:
            # abgelaufene Eintraege wegraeumen (Cleanup bei jedem Zugriff)
            self._conn.execute(
                "DELETE FROM qi_session_state WHERE created_at < ?", (self._cutoff(),)
            )
            self._conn.executemany(
                """
                INSERT INTO qi_session_state (session_hash, qi_type, category_enc, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(session_hash, qi_type)
                DO UPDATE SET category_enc = excluded.category_enc,
                              created_at   = excluded.created_at
                """,
                rows,
            )
            self._conn.commit()

    def get_categories(self, session_key: str) -> List[Tuple[str, str]]:
        """Entschluesselte (QI-Typ, generalisierte Kategorie)-Paare der Session.

        Nur fuer Debugging/Audit gedacht -- die eigentliche Schwellwert-Logik
        braucht nur die TYPEN (get_seen_types), nicht die Kategorien."""
        if not session_key:
            return []
        self.cleanup()
        session_hash = self._hash_key(session_key)
        with self._lock:
            rows = self._conn.execute(
                "SELECT qi_type, category_enc FROM qi_session_state "
                "WHERE session_hash = ? AND created_at >= ?",
                (session_hash, self._cutoff()),
            ).fetchall()
        out: List[Tuple[str, str]] = []
        for qi_type, token in rows:
            try:
                category = self._fernet.decrypt(bytes(token)).decode("utf-8")
            except Exception:
                category = "[nicht entschluesselbar]"
            out.append((qi_type, category))
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Session-Key-Aufloesung (gegen LiteLLM v1.95.0 verifiziert)
# ---------------------------------------------------------------------------
#
# Befund (Quelle: installiertes Package + Recherche, siehe Report):
#   LiteLLM erzeugt KEINE stabile cross-request Session-ID serverseitig. Die
#   Spalte LiteLLM_SpendLogs.session_id wird von
#   _get_standard_logging_payload_trace_id() aufgeloest in der Reihenfolge
#     litellm_session_id -> litellm_trace_id -> metadata.session_id
#     -> metadata.trace_id -> per-Request-UUID (litellm_trace_id)
#   Ohne Client-Mitwirkung ist der letzte Fallback pro Request eindeutig ->
#   keine Akkumulation moeglich. Der Client MUSS also eine Session-ID mitschicken
#   (Body-Feld litellm_session_id / metadata.session_id ODER Header
#   x-litellm-session-id / x-litellm-trace-id, die der Proxy in die Metadaten
#   normalisiert).
#
#   Die kanonische Extraktion lebt in
#   litellm.integrations.custom_guardrail.get_session_id_from_request_data();
#   die Funktion unten ist eine treue Nachbildung (damit der Standalone-/Test-
#   Betrieb ohne installiertes litellm funktioniert) plus ein trace_id-Fallback.
#
#   Fehlt eine echte Session-ID komplett, weichen wir auf den API-Key-Hash aus
#   (metadata.user_api_key_hash bzw. UserAPIKeyAuth.api_key = der gehashte
#   Token). Das ist ein GROBER Notnagel: er buendelt pro API-Key statt pro
#   Konversation -- parallele Chats desselben Keys kollabieren ineinander, ein
#   geteilter Team-Key mischt QIs verschiedener Personen. Deshalb wird er klar
#   als "coarse" markiert zurueckgegeben, nicht als vollwertige Session.


def resolve_session_id_from_data(data: dict) -> Optional[str]:
    """Praezise, client-gelieferte Session-ID aus den Request-Daten (oder None).

    Treue Nachbildung von LiteLLMs get_session_id_from_request_data() plus
    trace_id- und Header-Fallback."""
    if not isinstance(data, dict):
        return None

    sid = data.get("litellm_session_id")
    if sid:
        return str(sid)

    for meta_key in ("metadata", "litellm_metadata"):
        meta = data.get(meta_key)
        if isinstance(meta, dict):
            for field in ("session_id", "trace_id"):
                val = meta.get(field)
                if val:
                    return str(val)
            # Header-Fallback (falls der Proxy sie nicht in Felder normalisiert hat)
            headers = meta.get("headers")
            if isinstance(headers, dict):
                for hkey in ("x-litellm-session-id", "x-litellm-trace-id"):
                    val = headers.get(hkey)
                    if val:
                        return str(val)

    # trace_id direkt am Top-Level (manche Codepfade)
    tid = data.get("litellm_trace_id")
    if tid:
        return str(tid)
    return None


def resolve_api_key_hash(data: dict, user_api_key_dict: object = None) -> Optional[str]:
    """Grober Fallback-Session-Key: der API-Key-Hash (gehashter Token).

    Quelle 1: UserAPIKeyAuth.api_key (im Proxy = bereits der gehashte Token).
    Quelle 2: metadata.user_api_key_hash / user_api_key (dorthin legt der Proxy
    denselben Hash)."""
    api_key = getattr(user_api_key_dict, "api_key", None)
    if api_key:
        return str(api_key)
    if isinstance(data, dict):
        for meta_key in ("metadata", "litellm_metadata"):
            meta = data.get(meta_key)
            if isinstance(meta, dict):
                for field in ("user_api_key_hash", "user_api_key"):
                    val = meta.get(field)
                    if val:
                        return str(val)
    return None


def resolve_session_key(
    data: dict, user_api_key_dict: object = None
) -> Tuple[Optional[str], bool]:
    """Aufloesung des Session-Keys fuer die QI-Akkumulation.

    Returns ``(session_key, coarse)``:
      * praezise, client-gelieferte Session-ID -> (id, False)
      * sonst API-Key-Hash als grober Proxy     -> ("apikey:<hash>", True)
      * gar nichts auffindbar                    -> (None, False)

    ``coarse=True`` signalisiert dem Aufrufer, dass die Session-Zuordnung
    ungenau ist (pro API-Key statt pro Konversation)."""
    sid = resolve_session_id_from_data(data)
    if sid:
        return (f"sid:{sid}", False)
    api_hash = resolve_api_key_hash(data, user_api_key_dict)
    if api_hash:
        # Namespace-Praefix, damit ein API-Key-Hash nie zufaellig mit einer
        # echten Session-ID kollidiert.
        return (f"apikey:{api_hash}", True)
    return (None, False)
