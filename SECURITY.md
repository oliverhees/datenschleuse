# Security Policy

## Geltungsbereich

Diese Policy gilt für den offenen Kern der Datenschleuse in diesem Repository
(AGPL-3.0: Presidio-Integration, LiteLLM-Guardrail, Streaming-Re-Identifikation,
Quasi-Identifier-Layer, Schutzklassen-Modell, Docker-/Coolify-Deploy).

Cockpit-Dashboard und Self-Learning-Filter sind proprietär und nicht Teil
dieses Repos (siehe [Lizenz](README.md#-lizenz)) — Meldungen dazu bitte
ebenfalls über den Kontakt unten.

## Unterstützte Versionen

Das Projekt befindet sich in der Beta-Phase (siehe Status-Badge in der
[README](README.md)). Es gibt noch keine versionierten Releases mit
langfristigem Support — Sicherheitsfixes fließen direkt in `main`.

## Sicherheitslücke melden

**Bitte keine Sicherheitslücken über öffentliche GitHub Issues melden.**

Stattdessen per E-Mail an **oliverhees@gmail.com**, mit:

- Beschreibung der Lücke
- Schritte zur Reproduktion
- Betroffene Komponente (Guardrail, Presidio-Config, QI-Layer,
  Schutzklassen-Modell, Docker-/Coolify-Setup, Admin-UI, ...)
- Potenzielle Auswirkung (z. B. PII-Leak, Auth-Bypass, Tier-3-Umgehung)

Ich bestätige den Eingang innerhalb von 72 Stunden und halte dich über den
Fortschritt auf dem Laufenden. Bei kritischen Lücken (insbesondere: PII
verlässt das System trotz aktivem Guardrail im Klartext, oder der harte
Tier-3-Block lässt sich umgehen) priorisiere ich den Fix.

Ich bitte um angemessene Zeit zur Behebung, bevor Details öffentlich gemacht
werden (Coordinated Disclosure).

## Bekannte, konzeptionelle Grenzen

Kein Ersatz für eine Meldung, aber zur Einordnung, was *keine* Sicherheitslücke
im engeren Sinn ist:

- **PII-Erkennungsrate ist nie 100 %.** Die Datenschleuse ist eine technische
  Zusatzschutzschicht nach Art. 25 DSGVO, keine Zertifizierung und kein
  Freifahrtschein — siehe [Ehrliche DSGVO-Einordnung](README.md#️-ehrliche-dsgvo-einordnung-bitte-lesen).
- **Fail-Closed-Prinzip:** Maskierungsfehler blockieren die Anfrage.
  Re-Identifikationsfehler lassen Platzhalter im Klartext der Antwort stehen
  (kein PII-Leak, nur eine UX-Verschlechterung).
- **Tier-3-Block ist bewusst hart codiert**, ohne Override-/Bypass-Parameter
  (siehe [Schutzklassen-Modell](README.md#schutzklassen-modell-drei-sensitivitätsstufen)).
  Ein gefundener Umgehungsweg ist immer meldenswert.
