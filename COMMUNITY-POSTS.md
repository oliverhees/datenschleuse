# Datenschleuse — Community-Kommunikation

Chronologisches Log aller Community-Posts zum Projekt. Texte werden hier von Oliver kopiert und in der eigenen Community gepostet (nicht Skool — eigene Plattform).

---

## 2026-07-22 — Ankündigung: Warum wir die Datenschleuse bauen

**Kontext:** Erster öffentlicher Post zum Projekt. Entstanden direkt im Anschluss an die Architektur-/Lizenz-Entscheidungsrunde (siehe `ISA.md`, `PROJEKT-STATUS.md`). Deckt ab: Hermes-Fokus, technischer Stack (LiteLLM+Presidio), Differenzierung vs. Markt (ohne Konkurrenten namentlich zu nennen), EU-Router-Integration, Self-Learning-Filter, AGPL-3.0, Art.-25-Framing, KI-Betriebssystem-Vision mit deutscher Hermes-Version, Video-Angebot.

**Status:** Bereit zum Posten (von Oliver manuell auf der Community-Plattform veröffentlicht).

---

**Projekt Datenschleuse: Warum wir gerade an einem PII-Schutzschild für Hermes bauen**

Kurz das Problem, für alle die neu dabei sind: Sobald du mit Hermes (oder generell mit ner Cloud-KI) arbeitest, gehen deine Prompts irgendwo raus. Kundenname hier, Rechnungsnummer da, vielleicht die Steuer-ID aus Versehen mit reinkopiert. Macht fast jeder, macht sich aber kaum einer Gedanken drüber.

**Die Datenschleuse ist in erster Linie für Hermes gebaut.** Wir schreiben gerade aktiv ein eigenes Hermes-Plugin dafür. Kein Umweg, kein Bastel-Setup, ein Befehl (`hermes plugins install`) und du hast ein Cockpit direkt in Hermes, das dir zeigt, was maskiert wurde, wie oft, bei welchem Modell, ohne dass da jemals Klartext drinsteht. Technisch lässt sich die Datenschleuse an so ziemlich jede KI anbinden, die OpenAI-kompatibel ist, das geht also breiter. Aber der Fokus liegt bewusst auf Hermes, weil wir Hermes als unser KI-Betriebssystem einsetzen und genau darauf aufbauen wollen.

**Und genau da kommt auch der größere Plan ins Spiel:** Mit der geplanten deutschen Hermes-Version wollen wir einen Layer schaffen, der es gerade deutschen Unternehmen und in Deutschland ansässigen Leuten leichter macht, ihre KI-Nutzung so konform wie nur irgend möglich zu gestalten. Kein Freifahrtschein, aber ein echter, spürbarer Schritt in die richtige Richtung, direkt eingebaut statt nachträglich draufgeklatscht.

**Wie es technisch funktioniert:** Wir bauen nicht bei null. Unter der Haube läuft LiteLLM (der Proxy, der die Anfragen durchreicht) kombiniert mit Microsoft Presidio (die Erkennungs-Engine für personenbezogene Daten). Presidio kann von Haus aus schon einiges, aber deutsche Entitäten wie Steuer-ID, Sozialversicherungsnummer, Handelsregisternummer oder KFZ-Kennzeichen erkennt es out of the box quasi gar nicht. Genau da bauen wir unsere eigenen Recognizer drauf, das ist unser eigentlicher Mehrwert.

**Warum wir besser werden als das, was gerade am Markt ist:**
- Die meisten Lösungen die es aktuell gibt sind entweder Closed-Source-Enterprise-Kram mit Preisen auf Anfrage, oder erkennen nur einzelne Wörter statt Kontext (also "Rechnungsnummer 12345" ja, aber "42, männlich, Ingenieur in Weimar" als Kombination die dich trotzdem eindeutig macht, nein).
- Wir bauen deshalb an einer Quasi-Identifier-Erkennung, die genau solche Kombinationen erwischt, nicht nur Einzelwörter.
- Wir haben eine direkte EU-Router-Integration eingebaut (eurouter.ai, EU-gehostet, DSGVO, Zero Data Retention), das heißt Gürtel und Hosenträger: EU-Hosting plus PII-Stripping davor. Und weil wir das über den Proxy laufen lassen, kannst du gleich mehrere Modelle darüber wählen, nicht nur eins fest verdrahtet wie bei den meisten Setups.
- Wir bauen ein skalierbares Filtersystem ein. Wenn Presidio mal ein Muster übersieht (zum Beispiel eure interne Rechnungsnummer-Formatierung), trägst du das direkt im Cockpit nach, ohne Neustart, ohne Coding. Das System wird mit jedem Setup schlauer, ohne dass irgendwo eure echten Daten gespeichert oder trainiert werden. Nur das Muster selbst wird gelernt, nie der Inhalt.

**Und ganz wichtig, weil ich da ehrlich sein will:** Wir verkaufen das nicht als "DSGVO-konform". Das wäre gelogen. Es ist eine technische Zusatzschutzschicht nach Art. 25 DSGVO, kein Freifahrtschein und keine Zertifizierung. Wer euch was anderes erzählt, verkauft euch heiße Luft.

Der Kern wird offen (AGPL-3.0), selbst hostbar, selbst nachprüfbar.

Ist noch früh, das Grundgerüst steht, die Architektur ist entschieden, Plugin-Bau läuft gerade. 🔒

Wer selbst mit sensiblen Daten arbeitet und da ne Meinung zu hat, ob technisch, ob zu Prioritäten, ob "das brauch ich auch für XY": schreibt's gerne unter den Post. Nehmen wir eventuell direkt mit rein.

Und falls sich jemand ein Video zum Fortschritt wünscht: sagt einfach Bescheid, mach ich gerne, dann können wir da auch nochmal explizit im Detail drüber sprechen.

---

## 2026-07-23 — Beta-Update: Code öffentlich, Coolify-Self-Hosting

**Kontext:** Update-Post nach Live-Verifikation mit echtem eurouter-Key + Open-Core-Lizenzentscheidung (AGPL-3.0 für den Kern, Dashboard/Self-Learning-Filter bleiben proprietär). Deckt ab: Repo-Link (github.com/oliverhees/datenschleuse), Lizenz-Erklärung, Open-Core-Trennung, zwei Nutzungswege (Self-Hosting via Coolify-Template vs. individuelle gebuchte Instanz), ehrlicher Beta-Hinweis (noch keine hochsensiblen Produktivdaten).

**Status:** Gepostet.

---

**Update zur Datenschleuse: Beta ist da, Code ist öffentlich 🔒**

Kurzes Update zum letzten Post. Ist schneller gegangen als gedacht, aber genau deswegen will ich auch ehrlich sagen, was Stand ist und was noch nicht.

**Der Kern ist jetzt öffentlich auf GitHub:** github.com/oliverhees/datenschleuse. AGPL-3.0, also echtes Open Source, keine Marketing-Lizenz. Ihr könnt euch den Code angucken, selbst hosten, verändern, alles. Die einzige Auflage: wer's verändert und als Dienst anbietet, muss seine Änderungen auch wieder offenlegen. Das schützt davor, dass sich jemand den Kern schnappt und closed-source draus macht, verhindert aber nicht, dass ihr's kommerziell nutzt.

**Wichtig für die Ehrlichkeit, weil's gefragt wurde:** Das Cockpit-Dashboard und der Self-Learning-Filter (das Nachtragen eigener Muster im laufenden Betrieb) sind NICHT Teil vom offenen Kern. Die bleiben erstmal bei mir. Der Grund ist simpel: der Erkennungs- und Schutz-Teil ist das, wo Vertrauen und Reichweite dranhängen, das soll jeder prüfen können. Das Drumherum ist der Teil, aus dem irgendwann ein Geschäftsmodell wird. Sauber getrennt, nicht vermischt.

**Zwei Wege, wie ihr's nutzen könnt:**
1. **Selbst hosten.** Es gibt ein fertiges Coolify-Template, ein paar Klicks und läuft. Braucht euren eigenen eurouter.ai-Key, eure Instanz, eure Daten bleiben komplett bei euch.
2. **Ich hoste euch eine eigene Instanz.** Wenn ihr keinen Bock auf Selbst-Hosten habt, könnt ihr bei mir buchen, dann setze ich euch was Eigenes auf. Auch da: eigene Instanz pro Person, kein gemeinsamer Topf.

**Ehrlicher Beta-Hinweis:** Ist frisch draußen, live gegen einen echten eurouter-Key getestet (Maskierung, Streaming, die ganze Pipeline funktioniert), aber eben noch Beta. Schickt da aktuell noch keine hochsensiblen Produktivdaten durch, testet erstmal, gebt mir Feedback, dann optimieren wir zusammen weiter.

Wer direkt reinschauen will: Repo ist oben verlinkt, README sollte alles Wichtige erklären. Fragen, Bugs, "das brauch ich auch noch" — immer gerne her damit.

---

## 2026-07-23 — Diskussion zum Ankündigungspost: Schutzklassen-Modell übernommen

**Kontext:** Unter dem Post vom 22.07. entstand eine inhaltlich starke Diskussion (7 Kommentare). Zentraler Impuls kam von jemandem, der ein ähnliches System ("Variante D", lokaler Anonymisierungs-Tunnel mit Presidio+LiteLLM) bereits produktiv fährt und ein **3-Stufen-Schutzklassen-Modell** vorstellte:
- Stufe 1 (niedrig sensibel) → nach Anonymisierung erlaubt
- Stufe 2 (vertraulich) → Anonymisierung + explizites Freigabe-Gate (Human-in-the-loop)
- Stufe 3 (höchst sensibel) → hart im Code geblockt, nie Cloud, auch nicht anonymisiert, keine Config-Umgehung möglich

Oliver hat entschieden, das Modell sofort und vollständig zu übernehmen ("gleich mit angehen, keine halben Sachen"). Wird als eigenständiges Modul gebaut, siehe ISA.md Decisions 2026-07-23 und Plane-Task "Schutzklassen-Modell (3-Stufen-Sensitivitätsklassifizierung)".

Weitere Diskussionspunkte:
- Handwerksbetrieb-Use-Case: Pseudonymisierung für Angebote/Anfragen, auftragsbezogen konsistent halten (Feature-Idee für später, noch nicht umgesetzt).
- Schweiz-Frage: Ansatz ist technisch länderunabhängig (reine Datenminimierung vor Cloud-Versand), aber die rechtliche Einordnung (Art. 25 DSGVO) gilt nur EU/Deutschland — für die Schweiz wäre das revDSG die relevante Grundlage, eigenständig zu prüfen, nicht 1:1 übertragbar.
- "Nord-Süd-Teilung"-Kommentar: Deutung unsicher — plausibelste Lesart ist die bekannte Varianz in der Auslegungsstrenge zwischen den 16 deutschen Landesdatenschutzbehörden, aber nicht zweifelsfrei aus dem Kommentar ableitbar. Bei Bedarf beim Kommentator direkt nachfragen.
- Größere Vision eines "Company Brain/OS" (Vertragsmanagement, Dashboards, Zeiterfassung, Rechnungsstellung) wurde geäußert — deutlich größerer Scope als Datenschleuse, eigenes Thema, hier nur als Kontext vermerkt.
