# Methodenhandbuch der Schmiede

> Bindend per Verfassung (Arbeitsweise). Diese Methoden sind das WIE
> hinter den Gesetzen. Jede hat Problem → Regel → Umsetzung.

## 1. Context-Points statt Story Points
- Problem: Das Kontextfenster ist die knappste Ressource. Zu große
  Stories erzwingen Kompaktierung = stiller Qualitätsverlust.
- Regel: Eine Story muss in EINE Session passen, ohne Kompaktierung.
  Faustgröße: ein Feature-Schnitt, <= ~10 Dateien, klarer Testumfang.
- Umsetzung: Der Scrum Master schneidet danach. Tritt Kompaktierung
  auf, wird das am Item vermerkt — Signal für kleineres Schneiden.

## 2. Frische-Session-Prinzip
- Problem: Lange Sessions degradieren; komprimierter Kontext lügt leise.
- Regel: Session töten schlägt Session komprimieren. Umsetzung wird
  AUTOMATISIERT: Der Lead delegiert jedes Item und jedes Audit als
  Subagent (eigener frischer Kontext, stirbt nach Fertigmeldung) bzw.
  als Teammate-Session im Worktree, die er nach Abschluss beendet.
  Manuelles /clear ist nur der Fallback für Solo-Arbeit.
- Wichtig: Der Abschlussbericht an den Lead ist NICHT das Archiv —
  Erkenntnisse gehen VOR der Fertigmeldung an Plane + Memory (Gesetz 7).
- Auch der Lead altert: Nach jedem Cycle bzw. Meilenstein wird die
  Lead-Session beendet und frisch gestartet (session-brief.sh lädt
  den Stand in Minuten).

## 3. Der Laufzettel — SHA-gepinnte Gate-Verdicts
- Problem: "Audit bestanden, danach noch schnell geändert" ist das
  größte Loch aller Review-Prozesse.
- Regel: Auditoren urteilen nur über committete Stände. Jedes Verdict
  pinnt den geprüften Commit-SHA. Jeder spätere Code-Commit macht es
  automatisch ungültig.
- Umsetzung: `.claude/hooks/verdict.sh <gate> <pass|fail>` schreibt
  `.gates/<gate>.json` und committet es. Der CI-Check `gates` erzwingt
  vor dem Merge: pass-Verdicts vorhanden UND kein Code-Commit nach dem
  gepinnten SHA. Doku-only-PRs sind ausgenommen.

## 4. Auditor-Isolation (Blindprüfung)
- Problem: Ein Prüfer im Kontext des Erbauers prüft Absichten statt Code.
- Regel: security-auditor, qa-manager und ux-reviewer laufen IMMER als
  frische Subagents. Input: Diff + Work Item + Grundbuch. Nie der
  Chat des Erbauers.
- Umsetzung: Der Lead startet Audits ausschließlich so; die
  Agent-Definitionen unter .claude/agents/ verbieten Code-Änderungen.

## 5. Drei-Fehlversuche-Regel
- Problem: Agents beißen sich fest und verbrennen Kontext an derselben
  falschen Idee.
- Regel: Dreimal derselbe Fehler → Zwangsstopp. Erkenntnisse ans Work
  Item, Memory konsultieren, dann Lead bzw. Oliver fragen. Nie denselben
  Ansatz ein viertes Mal.
- Umsetzung: Verhaltensregel für alle Agents; der Lead behandelt die
  Meldung als normalen Eskalationspfad, nicht als Versagen.

## 6. Hook-Telemetrie + Retro
- Problem: Regeln, aus denen niemand lernt, veralten oder nerven.
- Regel: Jeder Hook-Block wird protokolliert. Pro Plane-Cycle läuft eine
  Retro-Session: hooklog.jsonl + erledigte Items auswerten, Verbesserungen
  an Gesetzen, Skills und Story-Schnitt als Work Items vorschlagen.
- Umsetzung: guard.sh schreibt `.claude/hooklog.jsonl` (lokal,
  gitignored). Retro-Prompt: "Lies hooklog + letzte Cycle-Items. Welche
  Regel feuert oft (unklar?), welche nie (überflüssig?), welche Stories
  waren zu groß? Vorschläge als Plane-Items."

## 7. Pre-Mortem beim Kickoff
- Problem: Risiken werden erst gesehen, wenn sie eingetreten sind.
- Regel: Vor Phase Build tagt das Team mit der Annahme "das Projekt IST
  gescheitert — warum?". Top-Risiken werden ADRs oder Guard-Items.
- Umsetzung: Teil des Projekt-Kickoffs (siehe ANLEITUNG), moderiert vom
  Analyst, dokumentiert unter docs/adr/ und in Plane.

---

# KI-native Regeln

> Wir sind keine Menschen-Firma. Diese Regeln existieren, WEIL unsere
> Arbeiter klonbar, egolos, unermüdlich — aber driftend und
> selbstüberschätzend — sind.

## 8. Turnier-Prinzip (Best-of-N)
- Problem: Menschen können sich Mehrfach-Lösungen nicht leisten. Wir schon.
- Regel: Bei kritischen oder unklaren Items startet der Lead 2-3
  UNABHÄNGIGE Implementierungen in getrennten Worktrees. Ein blinder
  Auditor kürt den Sieger; Verlierer werden gelöscht, Erkenntnisse
  wandern ins Memory. Gleiches Prinzip für Architektur-Entscheidungen:
  zwei unabhängige Vorschläge, die Abweichung ist Information.
- Umsetzung: Lead-Entscheidung, dokumentiert am Work Item ("Turnier: 3
  Lanes"). Kür-Kriterien vorab festlegen.

## 9. Kein Code-Besitz
- Problem: Verteidigung des eigenen Codes und Sunk-Cost-Flickerei.
- Regel: Code hat keinen Autor — ab Commit gehört er der Firma. Findings
  werden nie diskutiert, nur behoben oder eskaliert. Ab hoher
  Finding-Dichte (Richtwert: Audit findet mehr als 5 substanzielle
  Punkte in einem Modul) gilt: neu schreiben statt reparieren.
- Umsetzung: Verhaltensregel aller Agents; der Lead ordnet Rewrites an.

## 10. Artefakt-Pflicht
- Problem: KI behauptet überzeugend. Vertrauen darf nie auf Aussagen
  beruhen.
- Regel: Jede Fertig- oder Statusmeldung verweist auf Artefakte:
  Testlauf-Output, Diff, Verdict-Datei, Screenshot, Log. Meldungen ohne
  Artefakt gelten als nicht erfolgt.
- Umsetzung: Lead und Auditoren weisen artefaktlose Meldungen zurück.
  Artefakte bzw. deren Fundort werden am Work Item verlinkt.

## 11. Doku-Falsifikationstest
- Problem: Ob Doku vollständig ist, merkt man sonst erst im Ernstfall.
- Regel: Doku wird getestet wie Code: Ein FRISCHER, kontextfreier Agent
  erhält nur das Grundbuch (+ docs/) und muss eine getroffene
  Entscheidung herleiten oder eine Fachfrage beantworten. Weicht sein
  Ergebnis ab, ist die Doku unvollständig — das wird ein Work Item.
- Umsetzung: Pflicht beim Kickoff-Checkpoint und Teil jeder Retro
  (2-3 Stichproben pro Cycle).

## 12. Dritte-Wiederholung-Regel
- Problem: KI wird nicht gelangweilt — sie driftet bei Wiederholung.
- Regel: Führt ein Agent dieselbe Transformation zum dritten Mal aus,
  MUSS er daraus ein Skript oder einen Skill bauen (eigenes Work Item,
  wenn nötig). Determinismus schlägt Wiederholung.
- Umsetzung: Neue Skripte unter tools/, neue Skills via skill-creator;
  Eintrag im Grundbuch bzw. CONTEXT.md.

## 13. Klartext-Gebot + Unsicherheits-Ausweis
- Problem: Höflichkeit zwischen Agents ist Kontext-Verschwendung;
  stille Annahmen sind die billigste Bug-Quelle.
- Regel: Agent-zu-Agent-Kommunikation ist maximal direkt — keine
  Floskeln, kein Lob, keine Abschwächung von Findings. Jede Übergabe
  trägt einen Unsicherheits-Ausweis: Liste der getroffenen Annahmen
  plus offene Restzweifel. Auditoren prüfen die Annahmen ZUERST.
- Umsetzung: Pflichtabschnitt "Annahmen:" in jeder Fertigmeldung und
  jedem PR-Text; fehlt er, gilt Methode #10 (Meldung nicht erfolgt).

---

# Agentur-Betrieb

## 14. Kunden-Schaufenster (Zwei-Kanal-Prinzip)
- Problem: Interner Klartext würde Kunden verunsichern; Schweigen auch.
- Regel: Der Kunde erhält Gast-Zugang auf ein kuratiertes Plane-Projekt
  ("Schaufenster"): Meilensteine, verständliche Updates, Entscheidungs-
  Begründungen aus den ADRs. Interne Projekte sieht er nie.
- Umsetzung: client-liaison erstellt nach jedem Meilenstein den
  Update-Entwurf; Versand nur nach Freigabe (Gesetz 13). Plane:
  Kunde als Gast NUR auf das Schaufenster-Projekt berechtigen.

## 15. Modell-Ökonomie
- Problem: Überall das stärkste Modell = teuer; überall das billigste
  = riskant.
- Prinzip: Intelligenz wird dort eingekauft, wo Irrtum teuer ist —
  beim Entscheiden und Prüfen. Ausführung darf günstig sein, WEIL die
  Gates sie absichern.
- Matrix (in den Agent-Definitionen hinterlegt, Aliase opus/sonnet/haiku):
  | Aufgabe | Modell |
  |---|---|
  | Lead/Orchestrierung, Architektur, Security-Audit | stark (opus) |
  | Feature-Entwicklung, QA-Audit, UX-Review, Liaison, Controller | mittel (sonnet) |
  | Doku-Formatierung, Commit-Messages, Routine-Umbenennungen | klein (haiku) |
- Merksatz: Ein Turnier aus 3 Mittelklasse-Lanes schlägt oft eine
  einzelne Top-Modell-Lane — zum ähnlichen Preis (Methode #8).

## 16. Betriebsdaten & Berichte
- Problem: "Rekordzeit und maximale Qualität" muss belegbar sein —
  intern und gegenüber dem Kunden.
- Datenquellen: `.claude/worklog.jsonl` (Zeiten pro Branch/Item,
  automatisch via Hook), `npx ccusage@latest` (Tokens & Kosten aus den
  lokalen Claude-Code-Logs), Plane (Items, Durchlaufzeiten),
  .gates/ + hooklog (Qualität).
- Regel: Pro Cycle ein interner Zwischenbericht, pro Projekt ein
  Abschlussbericht in zwei Fassungen (intern voll, Kunde kuratiert) —
  erstellt vom controller, abgelegt unter docs/reports/, verlinkt in
  Plane. Zahlen immer mit Quelle; Näherungen gekennzeichnet.
- Publikation: Jeder Bericht wird zusätzlich als Plane Page
  veröffentlicht — intern im Firmen-Workspace (inkl. Kosten- und
  Token-Aufschlüsselung pro Cycle/Item), kuratiert im Schaufenster
  (Stunden & Meilensteine, keine internen Kostendetails ohne Freigabe).

## 18. Plane-Takt: Cycles & Pages
- Problem: Ohne Takt kein Rhythmus, ohne Publikationsschicht kein
  gemeinsames Bild.
- Cycles = Taktgeber: Der Lead plant Items in den laufenden Cycle;
  Cycle-Ende löst automatisch aus: Retro (Methode #6), Controller-
  Zwischenbericht (Methode #16), Liaison-Kundenupdate (Methode #14).
  Unfertige Items wandern begründet in den nächsten Cycle.
- Pages = Publikationsschicht mit drei Regalen:
  1. Grundbuch-Spiegel (aus docs/foundation/, nach jedem Merge der
     Doku aktualisiert)
  2. Berichte & Kostenaufschlüsselungen (vom controller)
  3. Kunden-Doku im Schaufenster (vom client-liaison: Anleitungen,
     FAQ, Entscheidungs-Erklärungen)
- Eiserne Regel: Quelle der Wahrheit ist IMMER das Repo. Pages werden
  nie direkt editiert — Sync-Richtung Repo → Pages, ausgeführt vom
  Agent, der den zugrunde liegenden Merge verantwortet hat.

## 17. Ampel-Autonomie (/goal)
- Problem: Autonomie ohne definierte Grenzen ist Kontrollverlust.
- Regel: 🟢 läuft ohne Rückfrage, 🟡 wird gesammelt und am Ende als
  Block zur Freigabe vorgelegt, 🔴 stoppt sofort (Grundbuch, Critical/
  High-Ausnahmen, ALLES Richtung Kunde, Scope-Sprengung, Destruktives,
  Budget). Details: .claude/commands/goal.md
- Umsetzung: /goal <Ziel> startet den autonomen Lauf mit dem Lead als
  Dirigent.
