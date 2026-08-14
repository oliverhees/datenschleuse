# UI-Komponenten-Katalog

> Bindend per Gesetz 11. Erst hier nachschauen, DANN bauen.
> Eigenbau nur, wenn keine Katalog-Komponente den Fall abdeckt —
> begründet vom ux-reviewer am Work Item.

## Komponentenbibliothek
- Gewählte Bibliothek: _(beim Kickoff festlegen, z.B. React Native Paper /
  Tamagui / gluestack-ui — Entscheidung als ADR)_
- Version:
- Theming: angebunden an Design-Tokens aus `branding.md`

## Komponenten-Register

| Bedarf | Komponente | Quelle (Lib/eigen) | Status |
|---|---|---|---|
| Button (primär/sekundär/destruktiv) | | | |
| Text-Input inkl. Validierungs-State | | | |
| Liste / Card | | | |
| Modal / Bottom Sheet | | | |
| Toast / Feedback | | | |
| Loading / Skeleton | | | |
| Empty State | | | |
| Error State | | | |

## Regeln
- Neue Komponente = neuer Eintrag hier + Screenshot im PR.
- Varianten entstehen über Props/Tokens, nicht über Copy-Paste.
