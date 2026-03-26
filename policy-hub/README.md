# Policy Hub - Firewall Profile Sammlung

Vorgefertigte TOML-Profile für typische Use-Cases in policy-gate Anwendungen.

## Verzeichnisstruktur

```
policy-hub/
├── profiles/                 # Hauptverzeichnis für Profile
│   ├── research-agent/      # Research-Agent Profil
│   │   └── firewall.toml
│   ├── code-assistant/      # Code-Assistant Profil
│   │   └── firewall.toml
│   └── customer-support/    # Customer-Support Profil
│       └── firewall.toml
├── presets/                  # Wiederverwendbare Presets
│   ├── strict.toml          # Strikte Grundeinstellungen
│   └── permissive.toml      # Permissive Grundeinstellungen
└── README.md                # Diese Dokumentation
```

## Profile Übersicht

### 1. Research-Agent Profil

**Pfad:** `policy-hub/profiles/research-agent/firewall.toml`

**Eigenschaften:**
- `context_window = 5` - Erhöht für mehr Kontext bei Recherche
- Erlaubte Intents: QuestionFactual, QuestionCausal, QuestionComparative, TaskTextSummarisation, TaskDataExtraction, ConversationalGreeting, ConversationalAcknowledgement
- Verbotene Intents: TaskCodeGeneration, TaskTranslation, StructuredOutput, ControlledCreative, SystemMetaQuery
- Keine externen Links erlaubt

**Erweiterte Egress-Kontrollen:**
| Option | Wert | Beschreibung |
|--------|------|-------------|
| `require_citations` | `true` | Quellenangaben erforderlich für alle Fakten |
| `prevent_fabricated_references` | `true` | Verhindert erfundene/fiktive Referenzen |
| `allowed_source_types` | `["academic", "official", "verified"]` | Nur vertrauenswürdige Quellen-Typen erlaubt |

**Anwendungsfall:**
- Wissenschaftliche Recherche
- Literatur-Reviews
- Fakten-Checks
- Daten-Analyse

### 2. Code-Assistant Profil

**Pfad:** `policy-hub/profiles/code-assistant/firewall.toml`

**Eigenschaften:**
- `context_window = 3` - Standard-Wert
- Erlaubte Intents: QuestionFactual, QuestionCausal, QuestionComparative, TaskCodeGeneration, TaskTextSummarisation, ConversationalGreeting, ConversationalAcknowledgement, SystemMetaQuery
- Verbotene Intents: TaskTranslation, TaskDataExtraction, StructuredOutput, ControlledCreative

**Code-spezifische Regeln:**
| Option | Wert | Beschreibung |
|--------|------|-------------|
| `allowed_languages` | `["python", "javascript", "typescript", "rust", "go", "java", "c", "cpp"]` | Erlaubte Programmiersprachen |
| `allow_system_commands` | `false` | Keine system-level Befehle erlaubt |
| `allow_db_queries` | `false` | Keine Datenbank-Befehle (SQL injection Prävention) |
| `allow_shell_execution` | `false` | Keine Shell-Befehle |
| `secure_coding_only` | `true` | Nur sichere Code-Patterns erlauben |

**Egress-Kontrollen:**
| Option | Wert | Beschreibung |
|--------|------|-------------|
| `prevent_credential_leakage` | `true` | Keine Credentials im Output |
| `prevent_api_key_exposure` | `true` | Keine API-Keys im Output |
| `prevent_internal_info_leakage` | `true` | Keine interne Informationen preisgeben |

**Anwendungsfall:**
- Code-Generierung
- Code-Reviews
- API-Dokumentation
- Technische Unterstützung

### 3. Customer-Support Profil

**Pfad:** `policy-hub/profiles/customer-support/firewall.toml`

**Eigenschaften:**
- `context_window = 3` - Standard-Wert
- Erlaubte Intents: ConversationalGreeting, ConversationalAcknowledgement, TaskTextSummarisation, QuestionFactual, QuestionCausal
- Verbotene Intents: TaskCodeGeneration, TaskTranslation, TaskDataExtraction, QuestionComparative, StructuredOutput, ControlledCreative, SystemMetaQuery

**PII-Schutz Konfiguration:**
| Option | Wert | Beschreibung |
|--------|------|-------------|
| `enabled` | `true` | PII-Erkennung aktiviert |
| `prevent_pii_exposure` | `true` | Keine PII im Output erlauben |
| `auto_anonymize` | `true` | Automatische Anonymisierung |

**Geschützte PII-Typen:**
- `email` - E-Mail-Adressen
- `phone` - Telefonnummern
- `address` --physische Adressen
- `credit_card` - Kreditkartendaten
- `ssn` - Sozialversicherungsnummern
- `bank_account` - Bankkonto-Informationen
- `password` - Passwörter
- `api_key` - API-Schlüssel

**Egress-Kontrollen:**
| Option | Wert | Beschreibung |
|--------|------|-------------|
| `prevent_pii_leakage` | `true` | Keine PII-Daten |
| `prevent_internal_info_leakage` | `true` | Keine internen Informationen |
| `prevent_external_links` | `true` | Keine externen Links |
| `prevent_confidential_data_leakage` | `true` | Keine vertraulichen Daten |
| `secure_communication_only` | `true` | Nur sichere Kommunikation |

**Anwendungsfall:**
- Kundenkommunikation
- Support-Anfragen
- Bestellstatus-Abfragen

## Presets Übersicht

### 1. Strict Preset

**Pfad:** `policy-hub/presets/strict.toml`

**Eigenschaften:**
- `context_window = 1` - Minimales Context Window
- Nur grundlegende Intents erlaubt
- Maximale Einschränkungen für alle Aktionen
- Voller PII-Schutz und Egress-Kontrollen

**Anwendungsfall:**
- Hochsichere Umgebungen
- Kritische Infrastruktur
- Maximale Kontrolle erforderlich

### 2. Permissive Preset

**Pfad:** `policy-hub/presets/permissive.toml`

**Eigenschaften:**
- `context_window = 5` - Höheres Context Window
- Alle grundlegenden Intents erlaubt
- Minimale Einschränkungen
- PII-Schutz deaktiviert

**Anwendungsfall:**
- Nicht-kritische Anwendungsfälle
- Entwicklung/Testing
- Sandbox-Umgebungen

## Nutzung

### Profil laden

```typescript
import { Firewall } from "policy-gate";
import { readFileSync } from "fs";

// Profil laden
const profileConfig = readFileSync('./policy-hub/profiles/research-agent/firewall.toml', 'utf-8');

const firewall = await Firewall.create({
  config: profileConfig,
  onAudit: async (entry) => {
    console.log(entry);
  },
});
```

### Preset kombinieren

```typescript
import { Firewall } from "policy-gate";

// Basis-Preset laden und anpassen
const basePreset = readFileSync('./policy-hub/presets/strict.toml', 'utf-8');

// Custom Intents hinzufügen
const customConfig = `
${basePreset}

# Eigene Intents hinzufügen
[[custom_intents]]
id = "IP-300"
intent = "TaskTextSummarisation"
regex = "(?i)\\b(custom pattern)\\b.{0,100}"
`;

const firewall = await Firewall.create({
  config: customConfig,
});
```

## Konfigurations-Optionen

### Context Window

```toml
context_window = 3  # Anzahl der recent messages für sliding window evaluation
```

### Erlaubte/Verbotene Intents

```toml
[allowed_intents]
QuestionFactual = true
TaskCodeGeneration = true

[blocked_intents]
TaskTranslation = true
ControlledCreative = true
```

### Zusätzliche Einschränkungen

```toml
[additional_restrictions]
allow_external_links = false
allow_system_commands = false
```

### PII-Schutz

```toml
[pii_protection]
enabled = true
prevent_pii_exposure = true
auto_anonymize = true
```

### Benutzerdefinierte Intents

Benutzerdefinierte Intents ermöglichen die Erkennung spezifischer Muster für individuelle Anwendungsfälle. Die ID sollte im IP-2xx Bereich liegen.

```toml
[[custom_intents]]
id = "IP-200"           # Eigene ID im IP-2xx Bereich
intent = "TaskCodeGeneration"  # MatchedIntent Typ
regex = "(?i)\\b(pattern)\\b.{0,100}"  # Regex Pattern
```

#### Research-Agent Custom Intents (IP-200 bis IP-214)

| ID | Intent | Regex Pattern | Beschreibung |
|----|--------|--------------|--------------|
| IP-200 | TaskTextSummarisation | `\b(literature review|research overview|state of the art|survey)\b` | Literatur-Review Muster |
| IP-201 | TaskDataExtraction | `\b(extract|parse|analyze data|statistical analysis|meta-analysis)\b` | Daten-Extraktion Muster |
| IP-202 | QuestionFactual | `\b(verify|fact check|is it true that|confirm|debunk)\b` | Fakten-Check Muster |
| IP-203 | QuestionCausal | `\b(why does|what causes|how does|explain the mechanism|root cause)\b` | Kausale Analyse |
| IP-204 | QuestionComparative | `\b(compare|versus|vs |difference between|advantages.*disadvantages)\b` | Vergleichende Analyse |

#### Code-Assistant Custom Intents (IP-210 bis IP-214)

| ID | Intent | Regex Pattern | Beschreibung |
|----|--------|--------------|--------------|
| IP-210 | TaskCodeGeneration | `\b(code review|refactor|optimise|optimize|debug|fix bug)\b` | Code-Review Muster |
| IP-211 | TaskTextSummarisation | `\b(api documentation|docs|readme|technical spec|endpoint)\b` | API-Dokumentation |
| IP-212 | QuestionFactual | `\b(how to|what is the|explain|what does|implementation)\b` | Technische Frage |
| IP-213 | QuestionComparative | `\b(which is better|framework comparison|library vs|microservice vs|monolith)\b` | Architektur-Vergleich |
| IP-214 | SystemMetaQuery | `\b(build status|ci/cd|pipeline|deploy|version|dependencies)\b` | DevOps Meta-Abfragen |

#### Customer-Support Custom Intents (IP-220 bis IP-224)

| ID | Intent | Regex Pattern | Beschreibung |
|----|--------|--------------|--------------|
| IP-220 | ConversationalGreeting | `\b(hello|hi|good morning|good afternoon|good evening|welcome)\b` | Begrüßung |
| IP-221 | ConversationalAcknowledgement | `\b(thank you|thanks|appreciate|confirmed|understood|got it|no problem)\b` | Bestätigung |
| IP-222 | TaskTextSummarisation | `\b(problem|issue|help|support|complaint|question|inquiry)\b` | Support-Anfrage |
| IP-223 | QuestionFactual | `\b(status|order|delivery|shipping|account|balance|refund)\b` | Status-Anfrage |
| IP-224 | QuestionCausal | `\b(why|reason|cause|because|explain|how come)\b` | Kausale Erklärung |

### Metadata-Sektion

Die `[metadata]` Sektion enthält wichtige Informationen über das Profil:

```toml
[metadata]
name = "profile-name"           # Eindeutiger Profil-Name
description = "Beschreibung"   # Kurzbeschreibung
version = "1.0.0"              # Versionsnummer
author = "policy-gate"         # Autor
preset = true                   # Optional: Markiert als Preset
```

**Felder:**
- `name` (erforderlich): Eindeutige Kennung für das Profil
- `description` (optional): Beschreibung des Verwendungszwecks
- `version` (optional): Semantische Versionsnummer
- `author` (optional): Urheber des Profils
- `preset` (optional, boolean): Kennzeichnet das Profil als wiederverwendbares Preset

## Sicherheitshinweise

1. **Custom Intents**: Benutzerdefinierte Intents werden NICHT durch Z3 verifiziert. Sie müssen manuell validiert werden.

2. **Profile anpassen**: Passen Sie die Profile an Ihre spezifischen Anforderungen an.

3. **Testen**: Testen Sie alle Profile mit Ihrem Conformance-Dataset bevor Sie sie in Produktion nutzen.

4. **Updates**: Halten Sie Ihre Profile aktuell mit den neuesten Versionen von policy-gate.

## Lizenz

Apache License 2.0 - Siehe [LICENSE](../../LICENSE)