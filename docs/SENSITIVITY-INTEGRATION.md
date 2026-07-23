# Schutzklassen-Modell — Integrations-Interface

> Wie der Sensitivitaets-Klassifizierer (`litellm/sensitivity_classifier.py`)
> in den bestehenden Guardrail (`litellm/datenschleuse_guardrail.py`)
> eingehaengt wird. **Vorschlag** — die finale Verdrahtung uebernimmt der
> Projektverantwortliche von Hand. Dieses Modul integriert sich NICHT selbst.

## Was das Modul liefert

| Baustein | Zweck |
|----------|-------|
| `Tier` (IntEnum: `TIER_1`/`TIER_2`/`TIER_3`) | Die drei Schutzklassen. `TIER_3 > TIER_2 > TIER_1`. |
| `SensitivityClassifier` | Regelbasierte, deterministische Einstufung eines Textes. |
| `Classification` | Ergebnisobjekt mit Stufe **und Begruendung** (auditierbar). |
| `enforce_tier_3_block(classification)` | **Harte** Stufe-3-Garantie. Wirft `Tier3Blocked`. Kein Bypass-Parameter. |
| `enforce_tier_2_gate(classification, approved)` | Stufe-2-Freigabe-Gate. Wirft `Tier2ApprovalRequired`, wenn Freigabe fehlt. |
| `is_release_approved(metadata)` | Liest das Freigabe-Flag sicher aus den Metadaten. |
| Exceptions | `Tier3Blocked`, `Tier2ApprovalRequired`, `SensitivityConfigError`. |

Der Kern hat **keine** Presidio-/LiteLLM-Abhaengigkeit. Die Personen-Erkennung
bekommt die Presidio-`/analyze`-Entities als **Eingabe** uebergeben — genau wie
`Masker` in `datenschleuse_guardrail.py`. Der Klassifizierer ruft Presidio nicht
selbst auf.

## Wo im Kontrollpfad?

**VOR der Maskierung.** Begruendung:

- **Stufe 3** muss blocken, *bevor* ueberhaupt irgendetwas Richtung Cloud
  aufbereitet wird. Der harte Block ist am wertvollsten, wenn er so frueh wie
  moeglich greift.
- Die Klassifizierung braucht ohnehin die Presidio-Entities (fuer die
  Personen-Referenz). Diese werden im `async_pre_call_hook` pro Nachricht schon
  via `self._analyze(...)` geholt. Man analysiert also **einmal**, klassifiziert
  mit dem Ergebnis, und maskiert danach mit demselben Ergebnis weiter.

Reihenfolge im `async_pre_call_hook`:

```
1. Presidio /analyze  (bereits vorhanden)
2. classify(...)      (NEU)
3. enforce_tier_3_block(...)   -> Stufe 3: Tier3Blocked, Ende. Kein Cloud-Call.
4. enforce_tier_2_gate(...)    -> Stufe 2 ohne Freigabe: Tier2ApprovalRequired.
5. masker.mask(...)   (bereits vorhanden)  -> nur Stufe 1 oder freigegebene Stufe 2
```

## Freigabe-Flag: warum `metadata`, nicht Header

Gewaehlt: **`metadata.sensitivity_approval: true`** (plus optionale explizite
Stufe `metadata.sensitivity_level: 1|2|3`).

Begruendung — Kompatibilitaet mit der bestehenden Guardrail-Architektur:

- `datenschleuse_guardrail.py` legt sein Re-Id-Mapping bereits unter
  `data["metadata"][REID_MAP_KEY]` ab und liest es in den post_call-Hooks aus
  `request_data["metadata"]` / `litellm_metadata` zurueck. Metadaten sind also
  der **erprobte** Propagationskanal in diesem Projekt.
- Der `async_pre_call_hook` bekommt `data` (das Request-Dict). HTTP-Header sind
  dort nicht garantiert und versionsabhaengig verfuegbar; `data["metadata"]`
  ist der dokumentierte, stabile Weg, den der Guardrail schon nutzt.
- LiteLLM-Clients (inkl. OpenAI-kompatible wie Hermes) koennen `metadata` im
  Request-Body mitschicken — kein Header-Handling noetig.

Der sichere Default bleibt: **fehlt das Flag, ist es NICHT freigegeben.**

## Konkretes Code-Beispiel (Vorschlag, direkt umsetzbar)

Im Konstruktor von `DatenschleuseGuardrail` den Klassifizierer **einmalig**
instanziieren (die Config wird dabei geladen; schlaegt das fehl, startet der
Guardrail gar nicht erst — fail-closed beim Start):

```python
# oben in datenschleuse_guardrail.py
from sensitivity_classifier import (
    SensitivityClassifier,
    enforce_tier_3_block,
    enforce_tier_2_gate,
    is_release_approved,
    SENSITIVITY_LEVEL_KEY,
    Tier3Blocked,           # optional, falls du sie in DatenschleuseBlocked uebersetzen willst
    Tier2ApprovalRequired,  # dito
)

class DatenschleuseGuardrail(_GuardrailBase):
    def __init__(self, ..., **kwargs):
        ...
        # Einmalig; laedt presidio/sensitivity-keywords.yml (fail-closed beim Start).
        self.classifier = SensitivityClassifier()
```

Im `async_pre_call_hook`, **bevor** maskiert wird. Der Aufbau spiegelt die
vorhandene Schleife; pro Nachricht wird `_analyze` genau einmal genutzt (fuer
Klassifizierung UND Maskierung):

```python
async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
    if call_type not in ("completion", "text_completion", "acompletion", None):
        return data

    messages = data.get("messages")
    masker = Masker()

    # Metadaten fuer explizite Stufe + Freigabe-Flag.
    meta_in = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    requested_level = meta_in.get(SENSITIVITY_LEVEL_KEY)
    approved = is_release_approved(meta_in)

    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                entities = await self._analyze(content)          # 1x analysieren

                # --- NEU: klassifizieren VOR dem Maskieren ---
                classification = self.classifier.classify(
                    content, entities=entities, requested_level=requested_level,
                )
                # Stufe 3: HARTER Block. Kein Cloud-Call, auch nicht maskiert.
                enforce_tier_3_block(classification)
                # Stufe 2: ohne Freigabe blocken.
                enforce_tier_2_gate(classification, approved)

                msg["content"] = masker.mask(content, entities)  # danach maskieren
            elif isinstance(content, list):
                for part in content:
                    if (isinstance(part, dict) and part.get("type") == "text"
                            and isinstance(part.get("text"), str)):
                        entities = await self._analyze(part["text"])
                        classification = self.classifier.classify(
                            part["text"], entities=entities, requested_level=requested_level,
                        )
                        enforce_tier_3_block(classification)
                        enforce_tier_2_gate(classification, approved)
                        part["text"] = masker.mask(part["text"], entities)

    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        data["metadata"] = metadata
    metadata[REID_MAP_KEY] = masker.reid_map
    return data
```

### Exception-Handling

`Tier3Blocked` und `Tier2ApprovalRequired` sind — wie `DatenschleuseBlocked` —
im pre_call geworfene Exceptions und fuehren damit zum Guardrail-Block (Request
geht nicht ans LLM). Zwei Optionen:

1. **So lassen** — LiteLLM behandelt jede pre_call-Exception als Block. Sauber.
2. **Vereinheitlichen** — in `DatenschleuseBlocked` uebersetzen, wenn du EIN
   Block-Exception-Typ nach aussen willst:

   ```python
   try:
       enforce_tier_3_block(classification)
       enforce_tier_2_gate(classification, approved)
   except (Tier3Blocked, Tier2ApprovalRequired) as exc:
       raise DatenschleuseBlocked(str(exc)) from exc
   ```

### Wichtig fuer die Reihenfolge

`enforce_tier_3_block` **immer vor** `enforce_tier_2_gate` aufrufen. Der harte
Stufe-3-Block darf nie von einem Freigabe-Flag beeinflusst werden — deshalb
zuerst und getrennt. `enforce_tier_2_gate` ist fuer Stufe 1 und Stufe 3 ohnehin
ein No-op.

## Konfiguration

- **Keywords/Muster:** `presidio/sensitivity-keywords.yml` (erweiterbar; jede
  Ergaenzung macht das Gate strenger). Alternativer Pfad via ENV
  `SENSITIVITY_KEYWORDS_PATH` oder `SensitivityClassifier(config_path=...)`.
- **Fail-closed-Stufe** bei einem einzelnen Klassifizierungsfehler:
  `SensitivityClassifier(fail_closed_tier=Tier.TIER_2)` (Default) oder
  `Tier.TIER_3` fuer maximal streng. Laxer als `TIER_2` ist bewusst nicht
  erlaubt.

## Nicht verhandelbar

Stufe 3 ist eine **Code-Level-Garantie**, keine Konfiguration. `enforce_tier_3_block`
nimmt bewusst nur das `Classification`-Objekt und **keinen** Bypass-Parameter
(kein `force`, kein `override`). Baue niemals eine Umgehung ein — auch nicht
"nur fuer Tests" oder "nur intern". Wenn Stufe 3 zu breit greift, ist der
richtige Hebel, die **Klassifizierung** zu praezisieren (Keyword-Listen), nicht
den Block aufzuweichen.
