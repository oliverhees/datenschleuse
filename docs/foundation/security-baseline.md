# Security-Baseline

> Bindend per Gesetz 5. Maßstab für jedes Security-Audit.
> Anspruch: verkaufsfähige Software auf Audit-Niveau.

## Verbindliche Standards
- Backend/API: OWASP ASVS, Level 2 als Ziel
- Mobile App: OWASP MASVS (+ MASTG als Prüfleitfaden)
- Web-Anteile: OWASP Top 10 als Minimum-Checkliste

## Baseline-Regeln (Auszug — vom security-auditor gepflegt)
- Auth: bewährte Verfahren/Provider, keine Eigenbau-Crypto, Token-Lebenszeiten
  definiert, Refresh-Rotation.
- Storage (Mobile): Secrets nur in Keychain/Keystore, nie in AsyncStorage
  oder Klartext-Dateien.
- Transport: TLS überall, Certificate Pinning für kritische Endpunkte prüfen.
- Input: serverseitige Validierung ist Pflicht, Client-Validierung ist Komfort.
- Logging: keine PII, keine Tokens, keine Passwörter in Logs.
- Dependencies: Lockfile, CVE-Scan in CI (gitleaks + npm audit / semgrep).

## Allowlist-Prinzip für Routen (bindend)

Die äußerste Ebene ist nicht das Feld und nicht die Nachricht, sondern die
**Route**. LiteLLM übergibt jedem Guardrail einen `call_type`, und jede Route
bringt ihr eigenes Payload-Schema mit. Eine Route, deren Schema die Maskierung
nicht abdeckt, wird **geblockt** — nie ungeprüft durchgereicht.

Warum das eine eigene Regel ist: eine Route stillschweigend durchzulassen ist
der schwerste Defektfall, den dieses Produkt haben kann. Nicht „Schutz
schwach", sondern *Schutz abwesend bei zugesichertem Schutz* — der Betreiber
hält seinen Verkehr für anonymisiert, während er es nie war. Genau das war
**DATENSCHLE-69** (behoben).

Verbindliches Routen-Register (Quelle: `CALL_TYPES_CHAT_MESSAGES` /
`CALL_TYPES_TEXT_PROMPT` / `KNOWN_UNSUPPORTED_CALL_TYPES` in
`litellm/datenschleuse_guardrail.py` — Code und Tabelle werden gemeinsam
geändert, nie einzeln):

| Route | `call_type` | Payload | Verhalten |
|---|---|---|---|
| `/v1/chat/completions` | `acompletion`, `completion` | `messages[]` | geprüft im Umfang der beiden Register unten |
| `/v1/completions` | `atext_completion` | `prompt` | geprüft im Umfang der beiden Register unten, Rückweg über `choices[].text` |
| `/v1/messages` (Anthropic) | `anthropic_messages` | eigenes Schema | **blockiert** |
| `/v1/responses` | `aresponses` | eigenes Schema | **blockiert** |
| Embeddings, Bild, Audio, Moderation, Rerank, Batch, Vector Store, MCP, Passthrough, Google GenAI | siehe Register | jeweils eigenes Schema | **blockiert** |
| jede künftige/unbekannte Route | — | — | **blockiert** |

Regeln dazu:
- Eine Route gilt erst als unterstützt, wenn **beide Richtungen** belegt sind:
  Maskierung des ausgehenden Payloads *und* Re-Identifikation der Antwort,
  jeweils mit eigenem Test. „Unterstützt" ohne Rückweg ist eine falsche
  Zusage, kein halber Fortschritt.
- Der `call_type` sagt nur, **welche** Route spricht — nicht, **wie** ihr
  Payload aussieht. Jeder unterstützte Pfad prüft deshalb zusätzlich die Form
  seines Payloads und blockt bei Abweichung. Ein Payload, der zu zwei Routen
  gleichzeitig passt, ist mehrdeutig und blockt.
- Die Typprüfung des `call_type` steht im **Validate-Pfad**, nicht als
  `isinstance`-Guard im Verarbeitungspfad. Ein Guard, der bei unerwartetem Typ
  still überspringt, ist immer ein Durchlass.
- **Blocken ist eine gültige Antwort.** Eine Route bewusst zu blocken und das
  zu dokumentieren ist erlaubt; sie stillschweigend durchzulassen nie.
- Eine neue LiteLLM-Route ist ein eigenes Work Item mit Eintrag im Register —
  nie eine stillschweigende Erweiterung im Code.

`/v1/messages` und `/v1/responses` sind bewusst geblockt, nicht vergessen:
beide brauchen ein eigenes Block-Register **und** einen eigenen Rückweg. Sie
als unterstützt zu führen, ohne ihre Struktur tatsächlich zu maskieren, wäre
derselbe Defekt noch einmal — nur dokumentiert falsch. Aufnahme jeweils als
eigenes Work Item.

## Allowlist-Prinzip für die Top-Level-Felder des Payloads (bindend)

Die Route zu registrieren genügt nicht. Der `call_type` sagt nur, **welche**
Route spricht — die **Felder** ihres Bodys sind eine eigene Ebene, und sie war
die sechste Fundstelle derselben Fehlerklasse (DATENSCHLE-69, zweite Runde):
das Trägerfeld (`messages`/`prompt`) lief durch die Maskierung, seine
Geschwisterfelder liefen ungeprüft daran vorbei.

Warum ein ungeprüftes Top-Level-Feld ein echter Ausgangskanal ist — empirisch
gegen litellm 1.97.0 belegt, nicht angenommen:

- `get_non_default_completion_params` (`utils.py`, Funktionsdefinition — in
  1.97.0 Zeile 9255) filtert die Top-Level-Keys gegen
  `litellm.types.utils.all_litellm_params`.
- Was **nicht** in dieser Liste steht, geht an den Provider: benannte
  OpenAI-Parameter direkt (`suffix` über `main.py:7154`), alles Übrige über
  `extra_body` (`utils.py`::`add_provider_specific_params_to_optional_params`,
  in 1.97.0 ab Zeile 4410). `_ensure_extra_body_is_safe`
  (`litellm_core_utils/llm_request_utils.py:6`) filtert dort nichts
  Sicherheitsrelevantes.
- **Das genügt aber nicht als Kriterium.** Der Body ist nur einer von
  mehreren Wegen nach draußen — siehe die Regel zum Transport-Umschlag unten.
  Belegstellen werden ab jetzt auf **Funktionsdefinitionen** bezogen, nicht
  auf Rumpfzeilen: ein Beleg muss nachschlagbar bleiben, auch wenn sich in
  der Datei darüber etwas verschiebt.

Verbindliches Register (Quelle: `CHAT_PAYLOAD_ROUTE` / `TEXT_PAYLOAD_ROUTE` /
`PAYLOAD_FIELDS_INFRASTRUCTURE` / `KNOWN_UNSUPPORTED_PAYLOAD_FIELDS` in
`litellm/datenschleuse_guardrail.py` — Code und Tabelle werden gemeinsam
geändert, nie einzeln):

| Gruppe | Felder | Behandlung |
|---|---|---|
| Trägerfeld + Freitext | `messages`, `prompt`, `suffix`, `stop`, `user` | maskiert, über **denselben** Masker und dasselbe `reid_map` |
| Strukturierter Freitext | `tools`, `tool_choice`, `functions`, `function_call`, `response_format` | strukturerhaltend maskiert (JSON-Knoten-Masker, inkl. Tiefenbegrenzung und Verifikationsdurchlauf) |
| Steuerparameter | `model`, `temperature`, `top_p`, `n`, `seed`, `stream`, `stream_options`, `max_tokens`, `max_completion_tokens`, `logprobs`, `logit_bias`, Penalties, `best_of`, `echo`, `service_tier`, `reasoning_effort`, `store`, `parallel_tool_calls` … | auf Form validiert, unverändert weitergereicht |
| Infrastruktur | `metadata`, `proxy_server_request`, `secret_fields`, `litellm_*`, `cache`, `ttl`, `tags`, `headers`, `api_*` … | passieren — jeder Eintrag steht in `all_litellm_params` und erreicht den Provider nachweislich nicht |
| Bekannt, nicht behandelt | `audio`, `modalities`, `prediction`, `thinking`, `web_search_options`, `safety_identifier`, `extra_headers`, `extra_body`, Prompt-Management-Felder | **blockiert**, beim Namen genannt |
| Alles Übrige | — | **blockiert**, nur als Fingerprint genannt |

Regeln dazu:
- **Ein Feld steht in genau einer Liste.** Was in keiner steht, blockt. Ein
  neues Feld der OpenAI-API erzwingt damit eine bewusste Entscheidung im
  Register statt lautlos ein Leck zu öffnen.
- **Ein Feld gilt erst als behandelt, wenn belegt ist, was mit ihm passiert** —
  maskiert *oder* validiert, jeweils mit eigenem Test. „Steht im Register" ohne
  Behandlung ist eine falsche Zusage.
- **Infrastruktur-Keys brauchen einen Beleg, keine Vermutung — und der Beleg
  ist eine Messung, keine Namensliste.** Ein Key darf nur dann unmaskiert
  passieren, wenn **beides** nachgewiesen ist:
  1. Er erreicht den Provider auf **keinem** Weg — nicht im Body, nicht als
     HTTP-Header, **nicht in der URL bzw. deren Query-String**, nicht über
     Verbindungs-Konfiguration.
  2. Er bestimmt nicht, **wohin** die Anfrage geht, **mit wessen**
     Zugangsdaten oder **ob** sie überhaupt hinausgeht. Diese Bedingung ist
     schärfer als die erste: `api_base` trägt selbst keine PII und leitet
     trotzdem den kompletten Verkehr auf einen fremden Server um.

- **Das Nachweisverfahren (bindend).** Mitschneidender Server an der Stelle
  des Providers, ein echter `completion()`-Aufruf pro Key, geprüft wird der
  **gesamte** ausgehende Request:
  - **URL inklusive Query-String**, roh *und* URL-dekodiert — sonst versteckt
    sich der Fund hinter Prozent-Kodierung;
  - alle HTTP-Header;
  - der Body.

  Dazu vier Regeln, jede aus einem konkreten Beinahe-Fehler entstanden:
  - **Provider-abhängig messen, mindestens `openai` und `azure`.** Was gegen
    einen Provider-Handler dicht ist, muss es gegen einen anderen nicht sein:
    `api_version` ist gegen `openai` dicht und geht gegen `azure` im
    Query-String hinaus. Ein Ergebnis ohne Provider-Angabe ist kein Ergebnis.
  - **Ein Fehler ist kein Freibrief.** Läuft der Aufruf nicht durch oder
    kommt kein Request an, lautet das Ergebnis *nicht gemessen* — und ein
    nicht gemessener Key gehört nicht auf die Passier-Liste. So wäre
    `model_list` beinahe durchgerutscht, und so ist `mock_response`
    herausgeflogen.
  - **Eine Messung ist nur so gut wie ihre Wertform.** Ein Marker in einer
    Struktur, die der Key real nie annimmt, misst nichts und meldet fälschlich
    „sauber". Jeder Key bekommt eine Form, die er tatsächlich annehmen kann.
  - **Die Messliste wird gegen die Konstante abgeglichen, nicht von Hand
    geführt.** Sechs Keys waren nie gemessen worden — darunter `api_base` —,
    weil sie in der Messliste schlicht fehlten. Der Abgleich ist als Test
    festgeschrieben (`TestMeasurementCoverage`): die Passier-Liste muss
    Teilmenge der gemessenen Keys sein.
- **Der Eintrag in `all_litellm_params` ist notwendig, nicht hinreichend.**
  Genau diese Verwechslung war ein High-Finding: `headers` steht dort und geht
  trotzdem hinaus, als HTTP-Header (`main.py:5029`). Die gemessenen
  Ausgangskanäle stehen in `PAYLOAD_FIELDS_TRANSPORT_CHANNELS`:

  | Key | Weg nach draußen | Behandlung |
  |---|---|---|
  | `headers`, `extra_headers` | HTTP-Header | blockiert |
  | `provider_specific_header` | HTTP-Header (provider-abhängig) | blockiert |
  | `model_list` | HTTP-Header über `litellm_params.extra_headers` der Deployments | blockiert |
  | `api_base` | bestimmt das **Ziel** der Anfrage | blockiert |
  | `api_version` | **URL/Query-String**, nur auf Azure | eng validiert |
  | `api_key` | `authorization`-Header | eng validiert |

- **Ein Transportkanal passiert nie ungeprüft — blocken oder eng validieren.**
  Validiert wird nur, wenn der Wert den Provider byte-identisch erreichen muss
  und der Proxy ihn legitim selbst setzt (`api_version` aus dem Query-String
  eines Azure-Clients, `api_key` bei Pass-Through-Auth). Dieselbe Logik wie
  bei `tool_call_id` auf Message-Ebene. Das Muster für `api_version` verbietet
  ausdrücklich `&` und `=` — genau die Zeichen, mit denen man einen zweiten
  Query-Parameter an die Provider-URL hängt.
- **Zwei Namen für denselben Kanal müssen dieselbe Behandlung bekommen.**
  `extra_headers` war korrekt geblockt, `headers` — der ältere Name, der in
  LiteLLM im selben dict landet — passierte. Das war kein Abwägen, sondern ein
  übersehener Alias. Bei jedem neuen Eintrag ist deshalb zu prüfen, ob es
  einen Zweitnamen für dieselbe Sache gibt.
- **Der Beleg wird in der Suite festgehalten, nicht nur im Commit.** Eine
  Laufzeitprüfung verifiziert, dass die Infrastruktur-Liste weiterhin
  Teilmenge von `all_litellm_params` der *installierten* litellm-Version ist.
  Verlässt ein Key diese Liste bei einem Upgrade, schlägt der Test an, statt
  dass der Key still zum Provider-Kanal wird. Eine Import-Zeit-Zusicherung
  verhindert zusätzlich, dass ein gemessener Transportkanal je wieder auf der
  Passier-Liste landet — das Modul startet dann nicht mehr.
- **Mehrdeutigkeit blockt in beide Richtungen.** Ein Body, der zugleich
  `messages` und `prompt` trägt, passt auf zwei Routen und wird geblockt —
  egal, über welche der beiden Routen er hereinkommt. Vorher war diese Regel
  nur bei der Text-Route umgesetzt.
- **Fehlt das Trägerfeld, blockt der Request.** Ohne `messages` bzw. `prompt`
  gibt es keinen Anwendertext zu prüfen — der Rest des Bodys ginge trotzdem
  hinaus.
- **Typprüfung im Validate-Pfad, nie im Mask-Pfad** (siehe unten). Ein
  registriertes Feld mit falschem Typ ist derselbe Defekt wie ein unbekanntes
  Feld: niemand hat den Inhalt geprüft.
- **Der QI-Layer ist Teil des Verarbeitungspfads, nicht optional.** Ein
  Text-Slot, den die Generalisierung nicht bedienen kann, blockt. Ein still
  übersprungener Slot lässt Quasi-Identifier in **voller Auflösung** hinaus,
  weil der Masker sie bewusst dem QI-Layer überlässt. Ein fail-closed-Block aus
  dem QI-Layer darf deshalb nicht vom defensiven Fehler-Handler geschluckt
  werden, der gewöhnliche QI-Fehler bewusst toleriert.

## Herkunft der Stufe-2-Freigabe (bindend)

**Freigeben darf ausschließlich der Betreiber. Niemals der Client, niemals
über den Request-Body.**

**Der Befund (DATENSCHLE-69, Security-F2).** Das Gate las
`metadata.sensitivity_approval` aus dem Request-Body. In litellm 1.97.0
überlebt ein client-gesetztes `metadata` bis in den Guardrail: gestrippt
werden nur Keys mit Prefix `user_api_key_` und eine kleine Kontroll-Liste
(`proxy/litellm_pre_call_utils.py:215-227` und `:1655-1660`).
`sensitivity_approval` steht in keiner der beiden Mengen. Gemessen: mit
`metadata: {"sensitivity_approval": true}` im Body wurde aus BLOCKED ein
PASSED. Der Kontrollierte konnte sein eigenes Kontroll-Gate abschalten.

**Die Regel.** Ein Gate, das der Kontrollierte selbst abschalten kann, ist
kein Gate. Für ein Werkzeug, dessen Zweck es ist, auch bei **fehlerhaften**
Clients zu schützen, ist Client-Vertrauen an dieser Stelle nicht
verteidigbar. litellm begründet seinen eigenen `user_api_key_`-Strip wörtlich
genauso: ein Aufrufer, der solche Keys vorbelegt, bekäme "their forged values
surface in guardrails, spend tracking, audit logs, and identity resolution".

**Die zwei gültigen Wege — mehr gibt es nicht:**

| Weg | Quelle | Warum betreiberkontrolliert |
|-----|--------|------------------------------|
| Key-/Team-Konfiguration | `user_api_key_dict.metadata` bzw. `.team_metadata`, Key `datenschleuse_sensitivity_approval` | Stammt aus der Proxy-Datenbank; der Betreiber setzt sie beim Anlegen des Virtual Key. litellm strippt client-gesetzte `user_api_key_*`-Metadaten selbst. |
| Header mit Geheimnis | Header `x-datenschleuse-sensitivity-approval`, Wert = konfiguriertes Geheimnis | Ein **bloßer** Header wäre wieder Client-Eingabe. Erst das Geheimnis macht ihn zum Betreiber-Kanal. |

**Bindende Detailregeln:**

- **Ohne konfiguriertes Geheimnis ist der Header-Weg AUS** — nicht "offen für
  alle". Der sichere Default ist die abgeschaltete Tür.
- **Konstantzeitiger Vergleich** (`hmac.compare_digest`) des Geheimnisses.
- **Das Geheimnis wird nach der Prüfung redigiert**, auch bei falschem Wert.
  `proxy_server_request.headers` geht in die Logging-Callbacks; ein Secret hat
  dort nichts zu suchen (Gesetz 5).
- **Das Body-Flag wird nicht nur ignoriert, sondern entfernt** — aus
  `metadata` *und* `litellm_metadata`. Bliebe es stehen, wanderte es durch den
  Logging-Kanal weiter und sähe für jeden späteren Leser aus, als **hätte**
  eine Freigabe vorgelegen: eine Falschaussage im Audit-Trail. Beide Kanäle,
  weil litellm je nach Codepfad den einen oder den anderen propagiert — ein
  Fix für nur einen wäre derselbe Alias-Fehler wie seinerzeit
  `headers`/`extra_headers`.
- **Kein stiller No-op.** Wird ein Body-Flag gefunden, wird die Tatsache
  geloggt (nie der Wert), und die Blockmeldung nennt beide gültigen
  Betreiber-Wege. Ein Client, der glaubt, seine Freigabe wirke, ist gefährlicher
  als einer, der eine klare Fehlermeldung bekommt.
- **Die Stufe (`sensitivity_level`) darf ein Client weiterhin setzen.** Sie
  kann nur **erhöhen** (monotone `max()`-Regel) und ist damit kein
  Bypass-Kanal: wer sich höher einstuft, schärft die Prüfung nur.
- **Stufe 3 bleibt unerreichbar für jeden Freigabeweg** — auch für den neuen
  Betreiber-Weg. `enforce_tier_3_block` nimmt bewusst nur das
  Classification-Objekt und bekommt niemals einen Bypass-Parameter.

## Der Logging-Kanal ist ein Ausgangskanal (bindend)

**"Erreicht den Provider nicht" heißt nicht "ist harmlos".**

**Der Befund (DATENSCHLE-69, Security-F1).** litellm baut **vor** dem
Guardrail einen flachen Schnappschuss des Bodys
(`proxy/litellm_pre_call_utils.py:1690-1692`):

```python
_body_snapshot = {k: v for k, v in data.items() if k not in exclude}
data["proxy_server_request"]["body"] = _body_snapshot
```

**Flach** ist das entscheidende Wort: pro Key hält der Schnappschuss dieselbe
Objekt-Referenz wie `data`. Daraus folgt unmittelbar:

- Ein **in-place** mutiertes Feld (`messages`) ist im Schnappschuss
  automatisch mitmaskiert — beide zeigen auf dasselbe Objekt.
- Ein durch **Rebinding** maskiertes Feld (`data[feld] = maskiert`) ist es
  **nicht** — der Schnappschuss hält weiter den alten, unmaskierten Wert.

Gemessen: `prompt`, `suffix`, `stop`, `user` und `tools` waren auf dem
Provider-Weg dicht und standen im Log im Klartext.
`turn_off_message_logging` rettet nicht: `perform_redaction`
(`litellm_core_utils/redact_messages.py:238-240`) redigiert ausschließlich
`messages`, `prompt` und `input`.

**Die Regel — eine dritte Registerkategorie.** Neben "passiert" und "blockt"
gibt es **behandelt** (`PAYLOAD_FIELDS_RESYNCED`): Keys, die den Payload nicht
weitertragen, sondern ihn **spiegeln**. Das alte Passier-Kriterium fragte
"erreicht dieser Key den Provider?" und war damit richtig, aber unvollständig.
Die fehlende Frage lautet:

> **Trägt dieser Key eine veraltete, unmaskierte Kopie genau des Payloads, den
> wir gerade maskiert haben?**

**Bindende Detailregeln:**

- **Der Schnappschuss wird neu gebaut, nicht feldweise nachgezogen.** Ein
  feldweiser Abgleich deckt ab, woran jemand gedacht hat; der Neubau deckt
  alles ab, was im Payload steht — auch das, was ein künftiger Commit
  hinzufügt.
- **Durchgängiges In-place ist keine Option und ist auch keine gültige
  Alternative.** `prompt` (als String), `suffix`, `user` und `stop` (als
  String) sind Python-`str`, also unveränderlich. Eine Regel "immer in-place"
  wäre unerfüllbar und würde still gebrochen — genau die Fehlerklasse, die
  geschlossen werden soll.
- **Der Re-Sync läuft als letzter Schritt, nach dem QI-Layer.** Der
  vergröbert Texte **nach** der Maskierung; ein Schnappschuss davor trüge die
  feiner aufgelösten Werte ins Log. Was das Modell nicht sehen darf, darf das
  Log erst recht nicht sehen.
- **Der Schnappschuss wird nicht geleert.** `spend_tracking_utils` und
  `standard_logging_payload` lesen ihn. Ein leerer Body wäre dicht, würde aber
  die Kostenerfassung des Betreibers kaputtmachen — ein Fix, der einen anderen
  Defekt erzeugt.
- **Fail-closed auf die Form:** `proxy_server_request` als Nicht-Objekt
  blockt; `body` als roher JSON-String blockt. Er trägt denselben Klartext,
  lässt sich aber nicht neu aufbauen. Was wir nicht neu bauen können, dürfen
  wir nicht maskiert glauben.

## Allowlist-Prinzip für eingehende Nachrichten (bindend)

Jede Ebene einer eingehenden Chat-Message wird nach Allowlist behandelt:
geprüft wird, was ausdrücklich als prüfbar erfasst ist — alles Übrige
blockiert fail-closed. Denylists ("diese bekannten Felder sind gefährlich")
sind hier verboten: sie sind erst vollständig, wenn jemand die Lücke findet.

Historie derselben Lücke — der Grund für diese Regel:
- DATENSCHLE-57: Content-**Parts** (`file`, `input_audio`, unbekannte Typen)
- DATENSCHLE-64: der `content`-**Container** selbst (dict statt Liste)
- DATENSCHLE-66: alle **Felder neben `content`**, allen voran
  `tool_calls[].function.arguments` (für agentische Clients der Normalfall)
- DATENSCHLE-65: die **Feldebene innerhalb eines Parts**
- DATENSCHLE-69: die **Route** selbst — siehe „Allowlist-Prinzip für Routen"
- DATENSCHLE-69 (zweite Runde): die **Top-Level-Felder des Payloads** — die
  Route war registriert, ihre Felder nicht. Siehe den gleichnamigen Abschnitt.
- DATENSCHLE-69 (dritte Runde): der **Transport-Umschlag** — die Felder waren
  registriert, aber das Kriterium prüfte nur den Body. `headers` ging als
  HTTP-Header hinaus.
- DATENSCHLE-69 (vierte Runde): die **URL** — das Kriterium deckte Header und
  Body ab, nicht den Query-String. `api_version` ging auf Azure dort hinaus.
  Diesmal lag der Fehler nicht im Register, sondern in der **Messmethode**.

Achtmal dieselbe Ursache: gelesen wurde, was man kannte, alles Übrige lief
still durch. Deshalb wird auf jeder Ebene **einmal vollständig erfasst** statt
Fall für Fall entdeckt. Und deshalb sind nach dem Schließen einer Ebene drei
Fragen zu stellen, nicht eine:
1. Welche Ebene darüber oder darunter hat dieselbe Bauart?
2. Deckt das *Kriterium* der geschlossenen Ebene wirklich alle Wege ab — oder
   nur den, an den man zuerst gedacht hat?
3. Deckt die *Messung*, die das Kriterium belegen soll, wirklich alles ab, was
   das Kriterium behauptet? Runde vier entstand nicht aus einem lückenhaften
   Register, sondern aus einer lückenhaften Messung. Ein Beleg, der weniger
   prüft als er zusagt, ist kein Beleg.

Verbindliches Feld-Register (Quelle: `MESSAGE_FIELDS_MASKED` /
`MESSAGE_FIELDS_VALIDATED` in `litellm/datenschleuse_guardrail.py` — Code und
Tabelle werden gemeinsam geändert, nie einzeln):

| Ebene | maskiert | validiert (nicht maskiert) | Rest |
|---|---|---|---|
| Message | `content`, `name`, `refusal`, `reasoning_content`, `tool_calls`, `function_call` | `role`, `tool_call_id`, `cache_control` | blockiert |
| tool_call | `function` | `id`, `type`, `index` | blockiert |
| function | `name`, `arguments` | — | blockiert |
| content-Part | `text` | `image_url` (nach Image-Policy) | Part-**Typ** blockiert; Part-**Felder** ⚠️ siehe unten |

> ⚠️ **Bekannte Abweichung auf der Part-Ebene (DATENSCHLE-65).** Die Allowlist
> greift für content-Parts derzeit auf den Part-**Typ**; die **Feldebene**
> innerhalb eines Parts ist noch nicht erfasst und in Arbeit. Die Zeile oben
> beschreibt insoweit den Soll-, nicht den Ist-Zustand: die Zusage „Rest
> blockiert" gilt auf der Part-Ebene bis zum Merge von **DATENSCHLE-65**
> **nicht**. Der Defekt stammt aus DATENSCHLE-57.
>
> Der genaue Umfang steht am Work Item, nicht hier — Begründung im Abschnitt
> „Offene Schwachstellen in eigener Doku".
>
> Diese Warnung bleibt stehen, bis DATENSCHLE-65 gemerged ist. Eine
> dokumentierte Sicherheitszusage, auf die sich ein Betreiber verlässt, ist
> selbst ein Sicherheitsmerkmal — eine zu weit gefasste Zusage ist ein Defekt,
> auch wenn der Code darunter älter ist als sie.

Regeln dazu:
- IDs werden **validiert statt maskiert**: ihr Wert muss byte-identisch
  bleiben, sonst findet das Modell das Tool-Ergebnis nicht zu seinem Aufruf.
  Genau deshalb müssen sie eng geprüft werden — sonst sind sie der bequemste
  Schmuggelkanal der Nachricht.
- `arguments` wird strukturerhaltend maskiert (JSON parsen, Werte und
  Schlüssel ersetzen, serialisieren). Nicht parsebares JSON wird als
  Freitext maskiert, nie ungeprüft durchgelassen.
- Blockmeldungen enthalten **nie** Client-Werte — auch kein Feldname, denn
  auch der ist Client-Inhalt (Gesetz 5).
- Ein neues Feld der OpenAI-API ist ein eigenes Work Item mit Eintrag im
  Register, nicht ein stillschweigendes Durchreichen.
- **Typprüfung gehört in den Validate-Pfad, nie in den Mask-Pfad.** Ein
  `if isinstance(x, str)` vor einer Maskierung ist immer ein stiller
  Durchlass: der Nicht-String fällt durch und geht ungeprüft raus. Ein
  bekanntes Feld mit falschem Typ muss blocken (Security-Audit F1).
- **Verifikationsdurchlauf auf dem Ergebnis.** Der fertig maskierte
  `arguments`-String geht erneut durch den Analyzer; findet der dort noch
  Entitäten, wird blockiert. Alle anderen Prüfungen sind pfadgebunden —
  diese greift unabhängig davon, welchen Weg ein Wert genommen hat.
- **JSON muss eindeutig sein.** Doppelte Schlüssel (`json.loads` behält still
  den letzten Wert, der erste wird nie geprüft) und nicht standardkonforme
  Konstanten (`NaN`, `Infinity`) werden abgelehnt, nicht interpretiert.
- **Fehlerpfade sind fail-closed, nicht Absturz.** Zu tief verschachteltes
  JSON blockt kontrolliert, statt einen `RecursionError` aus dem Hook zu
  werfen.
- **Diagnose ohne Preisgabe.** Blockmeldungen und Logs nennen Feldnamen nur
  aus unserem eigenen konstanten Vokabular; frei gewählte Feldnamen erscheinen
  ausschließlich als stabiler Fingerprint. Ein Feldname ist Client-Inhalt und
  kann selbst PII sein — Werte erscheinen nie, weder im Log noch am Client.

### Feld-Fingerprint — Formel

Damit ein Betreiber einen Fingerprint selbst nachrechnen kann, ohne in den
Quellcode zu sehen:

```
fingerprint(feldname) = sha256(repr(feldname).encode("utf-8")).hexdigest()[:8]
```

`repr()` (nicht `str()`), weil ein Feldname nicht zwingend ein String ist.
Nachrechnen in der Shell:

```bash
python3 -c 'import hashlib;print(hashlib.sha256(repr("mein_feld").encode()).hexdigest()[:8])'
```

Der Fingerprint ist stabil: derselbe Name ergibt immer denselben Wert. Damit
lässt sich ein blockendes Feld durch Vergleich eingrenzen, ohne dass der Name
selbst das System verlässt.

### Verifikationsdurchlauf — bekannte Grenzen

Der Durchlauf ist bewusst streng und erhöht die Blockrate für **legitime**
Aufrufe messbar. Das ist der akzeptierte Preis, keine Fehlfunktion:

- **Boundary-Artefakte der Erkennung.** Derselbe Analyzer kann an derselben
  Stelle im zweiten Durchlauf anschlagen, wo er im ersten nichts fand, weil
  sich der umgebende Kontext durch die Ersetzung verändert hat. Gegen echtes
  Presidio belegt: `{"projekt":"Digitalisierung Rathaus Muenchen",
  "ansprechpartner":"Frau Schmidt"}` wird geblockt — der Knoten-Durchlauf
  erkennt „Digitalisierung" als LOCATION und übersieht „Rathaus Muenchen",
  der Verifikationsdurchlauf findet es dann. **Kein Code-Fehler.** Die
  Blockmeldung nennt deshalb beide möglichen Ursachen und unterstellt keine.
- **Kosten.** Ein zusätzlicher Analyzer-Call pro `arguments`-String.
- **Der Durchlauf ist ein Netz, kein Ersatz.** Er ersetzt keine der
  vorgelagerten Prüfungen; er fängt nur, was an ihnen vorbeigekommen ist.

## Offene Schwachstellen in eigener Doku (bindend)

Eigene Doku benennt eine offene Schwachstelle im **Umfang**, nie im **Bauplan**.
Kein Beispiel-Payload, kein Reproduktionspfad für etwas Unbehobenes. Ehrlichkeit
über den Ist-Zustand ja, Anleitung nein.

Der Maßstab in einem Satz: Der Leser muss erkennen, worauf er sich **nicht**
verlassen darf — er darf daraus nicht ableiten können, wie er es auslöst.

- **Nennen:** betroffene Ebene, Tragweite der Abweichung, Work Item, ab wann die
  Zusage wieder gilt.
- **Weglassen:** Payload, Feldnamen, Struktur, Typ, Aufrufreihenfolge — alles,
  woraus sich der Weg zur Lücke zusammensetzen lässt.
- Der vollständige Sachverhalt gehört ans Work Item. Plane ist intern, dieses
  Repository ist öffentlich: jede Zeile hier ist eine Veröffentlichung.
- Nach dem Merge des Fixes darf die Beschreibung vollständig werden — vorher nicht.

Das ist kein Widerspruch zum Klartext-Gebot: Vollständigkeit gilt nach innen,
Zurückhaltung nach außen. Eine zu weit gefasste Sicherheitszusage ist ein Defekt
(siehe Part-Ebene oben) — eine mitgelieferte Anleitung, sie zu umgehen, ist einer
mit Reichweite.

## Threat Model
- Beim Kickoff: STRIDE-Kurzdurchlauf pro Kernfeature, Ergebnis als
  `docs/adr/` bzw. Anhang hier. Bei neuen Angriffsflächen aktualisieren.

## Audit-Protokoll
- Jedes Audit: Findings mit Severity (Critical/High/Medium/Low) als
  Kommentare am Work Item. Merge-Sperre bei Critical/High (Gesetz 5).
