# Headroom-Integration — Bewertung und Entscheidung

**Status:** ABGELEHNT für den aktuellen Use-Case (Stand 2026-07-29)
**Entscheidung:** Nicht integrieren. Kein Config-Flag, kein Service, keine Abhängigkeit.
**Revidieren wenn:** die unten genannten Bedingungen eintreten (§6).

Dieses Dokument hält fest, *warum* wir eine naheliegende Integration NICHT gebaut
haben. Ohne diese Notiz wird die Frage in sechs Monaten erneut gestellt und erneut
recherchiert.

---

## 1. Was Headroom ist (verifiziert, nicht aus dem Gedächtnis)

[Headroom](https://github.com/headroomlabs-ai/headroom) (auch unter
`chopratejas/headroom`) ist eine lokale Context-Compression-Layer für LLM-Traffic
von Tejas Chopra (Netflix). Stand Juni 2026: ~29.5K GitHub-Stars, 155 Releases,
zuletzt v0.25.0. Deployment als Library, Proxy oder MCP-Server.

Verifizierte Fakten aus README, Doku-Site und DeepWiki:

| Aspekt | Befund |
|---|---|
| Proxy-Endpunkte | `POST /v1/chat/completions` (OpenAI-kompatibel) + `/v1/messages` (Anthropic). Start: `headroom proxy --port 8787` |
| Upstream-Konfiguration | `OPENAI_TARGET_API_URL` / `ANTHROPIC_TARGET_API_URL`, alternativ CLI-Flags `--openai-api-url` / `--anthropic-api-url` |
| Was komprimiert wird | ContentRouter dispatcht nach Inhaltstyp: **SmartCrusher** (JSON-Arrays, ab `min_tokens_to_crush=200`), **CodeCompressor** (AST/tree-sitter), **LogCompressor** (Fehler bleiben erhalten), **Kompress-base** (Prosa) |
| Prosa-Verhalten | **Prosa wird per Default NICHT komprimiert** — explizit begründet mit "prioritizing meaning preservation" |
| Geltungsbereich | Wirkt auf die *jüngste* User-Message und das *jüngste* Tool-Result; System-Prompts, Tool-Definitionen und ältere Turns bleiben unangetastet |
| Streaming | SSE wird unterstützt; Byte-Buffer-Splitting für Multi-Byte-Zeichen, Usage-Frames werden online geparst. Für nicht-optimierte Teile gilt laut DeepWiki eine "byte-faithful"-Invariante (Chunks fließen unverändert durch, kein Voll-Buffering) |
| Reversibilität | CCR (Compressed Context Retrieval) legt Originale lokal ab und injiziert ein `headroom_retrieve`-Tool, damit das Modell bei Bedarf nachladen kann |
| Abschaltung | `--no-optimize` (Passthrough), `--no-cache`, `--no-ccr` |

**Nicht auffindbar in der Doku:** ein Mechanismus, der *literale Zeichenketten* vor
Veränderung schützt (Whitelist/Preserve-Pattern für beliebige Tokens). `SmartCrusher`
kennt `preserve_fields=['error','warning','failure']`, das gilt aber für JSON-Keys,
nicht für freien Text. `CacheAligner` erkennt volatilen Inhalt, *rewritet aber laut
Doku ausdrücklich keine Prompts*.

---

## 2. Die entscheidende Frage: Bringt das hier überhaupt etwas?

Headrooms Stärke ist strukturelle Redundanz — die 2.000-mal wiederholten
`"type": "file"`-Felder in Tool-Outputs, Logs, RAG-Chunks. Genau daher kommen die
60–95 %. Für Coding-Agents nennt das Projekt selbst nur noch ~20 %.

Der Traffic der Datenschleuse sieht so aus:

- kurze deutsche **Prosa**-Chat-Nachrichten,
- überwiegend Single-Turn,
- **kein** Tool-Use, **keine** RAG-Chunks, **keine** Logs, **kein** Code,
- typische Nachrichtenlänge weit unter `min_tokens_to_crush=200`.

Damit ist die Schnittmenge aus "was Headroom komprimiert" und "was die Datenschleuse
transportiert" **praktisch leer**:

- SmartCrusher (JSON) — feuert nicht, kein JSON im Payload.
- CodeCompressor — feuert nicht, kein Code.
- LogCompressor — feuert nicht, keine Logs.
- Kompress-base (Prosa) — **per Default aus**.

Das ist kein Tuning-Problem, sondern ein Architektur-Mismatch. Headroom ist ein
gutes Werkzeug für ein Problem, das wir nicht haben.

> **Ehrlich gesagt:** Wir hätten hier einen Service in den kritischen Datenpfad
> gestellt, der im Normalbetrieb messbar 0 % einspart. Der einzige Weg zu einer
> spürbaren Ersparnis wäre, Prosa-Kompression *aktiv einzuschalten* — also genau
> den Modus, den Headroom selbst aus gutem Grund deaktiviert lässt, und genau den,
> der unsere Platzhalter gefährdet (§4).

---

## 3. Bewertete Optionen

### Option A — Headroom als vorgeschalteter Proxy-Hop

`api_base` in `litellm/config.yaml` zeigt auf Headroom statt auf `api.eurouter.ai`,
Headroom leitet komprimiert weiter. Zusätzlicher Service in `docker-compose.yml`.

Reihenfolge: Guardrail maskiert (`pre_call`) → LiteLLM sendet maskierten Request →
Headroom komprimiert → eurouter.ai.

- **Datenschutz:** unkritisch. Headroom sieht ausschließlich **bereits
  pseudonymisierten** Text; auch der lokale CCR-Speicher enthält damit kein
  Klartext-PII. Das ist die *einzige* akzeptable Reihenfolge — Headroom vor der
  Maskierung wäre ein direkter Verstoß gegen das Projektprinzip.
- **Streaming:** unkritisch. Headroom puffert den Stream nicht voll, sondern reicht
  Chunks byte-treu durch. Selbst wenn Headroom die Chunk-Grenzen neu schneidet, ist
  der `ReidStreamProcessor` genau dafür gebaut (Sliding-Window über beliebige
  Chunk-Grenzen). Der zentrale Differenzierer des Projekts bleibt intakt.
- **Kosten:** ein weiterer Container, ein weiterer Netzwerk-Hop Latenz, eine
  weitere Fehlerquelle im Pfad — für 0 % Ersparnis.

### Option B — Headroom als Library im Guardrail

Aufruf direkt in `async_pre_call_hook` nach der Maskierung, vor dem Outbound-Call.

- **Vorteil:** feingranulare Kontrolle, wir könnten gezielt prüfen, welche Messages
  überhaupt angefasst werden.
- **Killer:** die Prosa-Kompression basiert auf einem *trainierten Modell*
  (`Kompress-v2-base`). Das zieht ML-Abhängigkeiten in das LiteLLM-Image, das heute
  bewusst schlank ist (`requirements-guardrail.txt`: `httpx`, `PyYAML`,
  `cryptography`). Für ein Tool, dessen Deploy-Versprechen `docker compose up`
  lautet, ist das ein erheblicher Rückschritt — hunderte MB und eine ML-Runtime im
  Compliance-kritischen Pfad, damit im Regelfall nichts komprimiert wird.

**Beide Optionen scheitern nicht an der Technik, sondern an der Nutzenseite.**

---

## 4. Das Platzhalter-Risiko (falls jemand es doch aktiviert)

Für den Fall, dass jemand Prosa-Kompression einschaltet, hier die ungeschönte
Risikoanalyse — sie ist der Grund, warum diese Integration auch *mit* Nutzen nur
mit einer Schutzschicht gebaut werden dürfte.

Die Re-Identifikation setzt zwei Dinge voraus:

1. Der Platzhalter (`<PERSON_0>`) erreicht das Modell **wortwörtlich**.
2. Das Modell gibt ihn **wortwörtlich** in der Antwort zurück.

Eine Kompression, die Prosa umschreibt, verletzt potenziell Punkt 1. Und der
Fehlerfall ist besonders unangenehm:

- **Er ist still.** `reidentify_full()` und der `ReidStreamProcessor` matchen
  exakt. Ein verändertes oder weggekürztes `<PERSON_0>` wirft keinen Fehler — es
  wird schlicht nicht ersetzt.
- **Er ist asymmetrisch.** Kein PII-Leck (Platzhalter enthalten keine PII, siehe
  Fail-Semantik im Guardrail), aber eine **falsche oder pseudonymisierte Antwort**
  beim Nutzer, ohne jeden Hinweis, dass etwas schiefging.
- **Es gibt keine Gegenmaßnahme in Headroom.** Ein Preserve-Pattern für literale
  Zeichenketten in freiem Text existiert laut Doku nicht.

Erschwerend: der frisch ergänzte `ANONYMIZATION_NOTICE` weist das Zielmodell
explizit an, Platzhalter *exakt* zurückzugeben. Eine Kompressionsschicht, die
denselben Text umformuliert, arbeitet direkt gegen diese Anweisung.

**Konsequenz:** Wer das je aktiviert, muss eine Integritätsprüfung davorschalten —
Platzhalter-Multimenge vor der Kompression gleich Multimenge danach, sonst
deterministischer Fallback auf den unkomprimierten Text. Ohne diesen Guard ist die
Kompression im Datenschleuse-Pfad nicht verantwortbar.

---

## 5. Was das Projektprinzip hier verlangt

Das Projekt sagt an anderer Stelle offen "Erkennungsrate ist nie 100 %". Dieselbe
Ehrlichkeit gilt hier:

> Eine Garantie, dass Kompression und Platzhalter-Erhalt zusammen zu 100 %
> funktionieren, kann **niemand** geben — weder wir noch Headroom. Headroom
> dokumentiert für freien Text keine Verbatim-Zusage, und ein trainiertes
> Kompressionsmodell ist per Konstruktion nicht bit-genau. Verifizierbar wäre
> nur die *Erkennung* einer Verletzung (§4), nicht ihre Abwesenheit.

Dazu kommt ein Aspekt, der bei einem DSGVO-Werkzeug schwerer wiegt als bei einer
beliebigen App: **jede Komponente im Datenpfad muss auditierbar sein.** Ein
Pre-1.0-Projekt mit 155 Releases, das Nachrichteninhalte zwischen Maskierung und
Modell umschreibt, ist für Self-Hoster zusätzliche Angriffsfläche und zusätzlicher
Prüfaufwand. Das ist vertretbar, wenn es echten Nutzen bringt — nicht für 0 %.

---

## 6. Wann diese Entscheidung neu zu bewerten ist

Konkrete Trigger, nicht "irgendwann":

1. **Tool-Use / Function-Calling** kommt in die Datenschleuse. Dann entstehen echte
   Tool-Outputs mit struktureller Redundanz — Headrooms Kernkompetenz. Dann ist
   Option A (Proxy-Hop) die richtige Wahl, weil sie ohne ML-Deps im Guardrail-Image
   auskommt.
2. **RAG-Chunks** werden Teil des Payloads.
3. **Lange Multi-Turn-Konversationen** werden zum dominierenden Kostenfaktor. Auch
   dann gilt: nur die History komprimieren, niemals die jüngste maskierte Message,
   und nur mit dem Integritäts-Guard aus §4.
4. **Headroom liefert ein dokumentiertes Preserve-Pattern für literale Strings.**
   Das würde §4 von "selbst absichern" auf "vom Upstream garantiert" heben.

Solange keiner dieser Punkte zutrifft: nicht integrieren. Ein Feature-Flag, das im
Regelfall nichts bewirkt, ist kein kostenloses Feature — es ist Dokumentations-,
Test- und Support-Last für jeden Self-Hoster, der es findet und sich fragt, ob er
es einschalten sollte.

---

## Quellen

- <https://github.com/headroomlabs-ai/headroom> — README
- <https://headroomlabs-ai.github.io/headroom/proxy/> — Proxy-Server-Doku
- <https://headroomlabs-ai.github.io/headroom/configuration/> — Konfigurationsoptionen
- <https://deepwiki.com/headroomlabs-ai/headroom/2.1-provider-routing-and-request-lifecycle> — Request-Lifecycle, Streaming-Verhalten
- <https://dev.to/tejas_chopra/stop-feeding-junk-tokens-to-your-llm-i-built-a-proxy-to-fix-it-1hg9> — Motivation des Autors
