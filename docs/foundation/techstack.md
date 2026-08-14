# Tech-Stack

> Bindend per Gesetz 12. Jede Zeile braucht Version UND Begründung.
> Änderungen nur via Work Item + ADR.

## Kern

| Ebene | Wahl | Version | Warum (Kurzbegründung) |
|---|---|---|---|
| App-Framework | _z.B. React Native + Expo_ | | |
| Sprache | _z.B. TypeScript (strict)_ | | |
| Navigation | | | |
| State Management | | | |
| Backend / API | | | |
| Datenbank | | | |
| Auth | | | |

## Test & Qualität

| Zweck | Wahl | Version | Warum |
|---|---|---|---|
| Unit-Tests | | | |
| E2E (Mobile) | _z.B. Maestro / Detox_ | | |
| Lint/Format | | | |
| SAST | _z.B. semgrep_ | | |

## Regeln
- Neue Dependency? → Prüfung nach Gesetz 5 (Verbreitung, Wartung, CVEs),
  Eintrag hier, Begründung am Work Item.
- Major-Upgrades sind eigene Work Items.
