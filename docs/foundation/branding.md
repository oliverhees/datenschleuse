# Branding & Design-Tokens

> Bindend per Gesetz 11/12. Keine Ad-hoc-Farben, -Abstände oder
> -Schriften im Code — alles kommt von hier.

## Marke
- Name / Wortmarke:
- Tonalität (3 Adjektive):
- Logo-Assets: `docs/foundation/assets/`

## Design-Tokens

| Token | Wert | Verwendung |
|---|---|---|
| color.primary | | Primäraktionen, Links |
| color.surface | | Hintergründe |
| color.text | | Fließtext |
| color.danger | | Fehler, destruktive Aktionen |
| radius.base | | Buttons, Cards |
| spacing.unit | | Basisraster (alle Abstände = Vielfache) |
| font.family | | |
| font.scale | | z.B. 12/14/16/20/24 |

## UI-Prinzipien
- Plattform-Konventionen schlagen Eigenkreation (HIG / Material).
- Jede Screen-Ansicht definiert: Loading-, Empty-, Error-State.
- Kontrast mindestens WCAG 2.2 AA. Touch-Targets ≥ 44pt.
- Dark Mode: von Anfang an mitgedacht, nicht nachgerüstet.
