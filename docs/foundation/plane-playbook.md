# Plane-Playbook

> Bindend per Gesetz 1. Plane ist das Betriebssystem der Firma —
> dieses Playbook definiert, wie jede Funktion genutzt wird.

## Projekt-Struktur
- **Intern:** ein Plane-Projekt pro Kundenprojekt (voller Klartext).
- **Schaufenster:** ein kuratiertes Projekt pro Kunde (Gast-Zugang,
  Gesetz 13).
- **Firma:** ein Meta-Projekt für Retro-Items, Methoden-Verbesserungen
  und Betriebs-Backlog (Hooklog-Erkenntnisse landen hier).

## States (Workflow) — in jedem internen Projekt anlegen
Backlog → Ready → In Progress → In Audit → Fix → Done (+ Cancelled)
- **Ready** heißt: 98%-Regel erfüllt (Gesetz 9) — Ziel, Scope,
  Akzeptanzkriterien stehen. Nur Ready-Items dürfen in den Cycle.
- **In Audit** heißt: Laufzettel läuft (Blindprüfungen aktiv).
- **Fix** heißt: Findings offen, zurück beim Dev.

## Estimates = Context-Points (Methode #1)
- Skala aktivieren (Punkte). Bedeutung: 1 = trivial, 2 = klein,
  3 = normale Session, 5 = obere Grenze einer Session.
- Regel: Größer als 5 gibt es nicht — das Item wird gesplittet.
- Kompaktierung trotz <=5? Am Item vermerken → Retro justiert die Skala.

## Labels — fester Katalog (keine Wildwuchs-Labels)
- Typ: `feature` `bug` `chore` `security` `docs`
- Prozess: `turnier` (Best-of-N-Item), `rewrite` (Methode #9 ausgelöst)
- Sichtbarkeit: `kundensichtbar` (Liaison darf übersetzen)
- Eskalation: `ampel-rot` (wartet auf Oliver — IMMER mit Assignee Oliver)
- Neue Labels nur per Retro-Beschluss.

## Relations — die Landeslots des Leads
- Abhängigkeiten IMMER als blocked_by/blocking pflegen; der Lead plant
  die Merge-Reihenfolge aus dieser Sicht (methoden.md, lead.md).
- Duplikate bei der Triage als duplicate verknüpfen, nie löschen.

## Modules
- Ein Module pro Feature-Komplex/Deliverable (z.B. "Auth",
  "Onboarding", "Payment"). Items gehören zu genau einem Module.
- Module-Fortschritt ist die Basis der Meilenstein-Updates des Liaison.

## Sub-Work-Items
- Stories dürfen Teilaufgaben als Sub-Items tragen (z.B. pro
  Turnier-Lane eines). In den Cycle geht nur das Eltern-Item.

## Intake — der Kundeneingang
- Kundenwünsche und Community-Meldungen landen im Intake, nie direkt
  im Backlog. Der PO triagiert: annehmen (→ Backlog, Ready-Kriterien
  erarbeiten), ablehnen (begründet), Duplikat (verknüpfen).
- Triage-Takt: mindestens einmal pro Cycle.

## Views — Standard-Cockpits (als gespeicherte Views anlegen)
- "Wartet auf Oliver": Label ampel-rot, offen — DEIN Freigabe-Posteingang
- "Im Audit": State In Audit — was hängt in den Gates?
- "Blockiert": Relation blocked_by aktiv — wo klemmt die Kette?
- "Cycle aktuell": laufender Cycle, gruppiert nach State

## Attachments = Artefakt-Anker (Methode #10)
- Testlauf-Outputs, Screenshots (UI!), Reports werden am Item
  angehängt oder verlinkt. Fertigmeldung verweist darauf.

## Drafts
- Liaison-Entwürfe (Updates, Kunden-Doku) entstehen als Draft/
  unveröffentlichte Page und gehen erst nach Freigabe live.

## Archivierung
- Done-Items werden am Cycle-Ende archiviert (Auto-Archiv aktivieren,
  z.B. nach 7 Tagen). Archiv ist durchsuchbar — Gesetz 1 bleibt erfüllt.

## Ehrlichkeits-Hinweis (Community vs. Pro)
- Diese Playbook-Funktionen sind auf der Community Edition ausgelegt.
- Pro-Funktionen (u.a. Epics, Initiatives, natives Time-Tracking,
  erweiterte Dashboards) sind NICHT vorausgesetzt: Epics ersetzen wir
  durch Modules, Time-Tracking durch unser worklog.jsonl, Dashboards
  durch Controller-Berichte + Views. Falls die Instanz Pro hat:
  nutzen, Playbook per Retro erweitern.
