<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-penreport/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-penreport

![Version](https://img.shields.io/badge/version-2.7-crimson)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![VampSecure Labs](https://img.shields.io/badge/VampSecure-Labs-7c3aed)

**Professional pentest report aggregator for VampSecure Labs toolkit.**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

`vamp-penreport` reads JSON output files from any VSL tool, normalizes and deduplicates all findings, computes a global risk score, and produces polished HTML, PDF, and Markdown reports ready for client delivery.

It is **not a scanner** — it is a report aggregator and generator. It has no finding prefix of its own; it works with findings produced by other VSL tools.

---

### Features

- Ingests multiple VSL JSON output files in a single run
- Normalizes severity labels and deduplicates findings across tools
- Computes global risk score (0–100) with qualitative label (Low / Moderate / High / Critical)
- Executive summary with inline SVG gauge and category bar chart
- Prioritized remediation roadmap (4 phases: Immediate / Urgent / Planned / Continuous)
- **MITRE ATT&CK coverage section**: auto-detected from `vamp-log-analyzer` FORA-NNN findings — 25 detectors mapped to 12 tactics; rendered as an interactive table with severity badges and technique tooltips
- Detailed technical findings section with estimated CVSS range
- **Local logo embedding**: `--logo-file PATH` embeds any PNG/JPG/SVG as a base64 data URI — the HTML is fully self-contained with no external requests
- Printable HTML with full CSS `@media print` support
- Native PDF via `fpdf2` (no browser required)
- Markdown output for integration into wikis or documentation systems
- Consolidated JSON export for pipeline integration

---

### Installation

```bash
pip install vamp-penreport
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-penreport
```

```bash
cd vamp-penreport
pip install -r requirements.txt
```

`fpdf2` is only required for PDF output. HTML and Markdown generation work with Python stdlib alone.

---

### Usage

#### Basic — HTML only

```bash
python3 vamp_penreport.py scan1.json \
  --client "Acme Corp" \
  --engagement "External Pentest Q3 2026"
```

#### Full report — HTML + PDF + Markdown

```bash
python3 vamp_penreport.py scan1.json scan2.json scan3.json \
  --client "Acme Corp" \
  --engagement "External Pentest Q3 2026" \
  --auditor "VampSecure Labs Red Team" \
  --scope "Perimeter web applications and exposed APIs" \
  --start-date 2026-07-01 \
  --end-date 2026-07-31 \
  --logo-file /path/to/client_logo.png \
  --report-html report.html \
  --report-pdf report.pdf \
  --report-md report.md \
  --report-json consolidated.json
```

#### Executive summary only (no detailed technical findings)

```bash
python3 vamp_penreport.py scan1.json scan2.json \
  --client "Acme Corp" \
  --engagement "Quick Assessment" \
  --executive-only \
  --report-html executive_summary.html
```

#### Forensic log report with MITRE ATT&CK coverage

When the input includes output from `vamp-log-analyzer`, the report automatically adds a **MITRE ATT&CK coverage section** showing which tactics and techniques were observed:

```bash
python3 vamp_penreport.py \
  recon.json ssl.json http.json logs_forensic.json \
  --client "Acme Corp" \
  --engagement "Full Perimeter Assessment" \
  --report-html full_report.html
```

#### All options

```
usage: vamp-penreport [-h] --client NAME [--engagement DESC]
                      [--auditor NAME] [--scope TEXT]
                      [--start-date DATE] [--end-date DATE]
                      [--report-html FILE] [--report-pdf FILE]
                      [--report-md FILE] [--report-json FILE]
                      [--logo-url URL] [--logo-file FILE]
                      [--executive-only] [--verbose]
                      INPUT [INPUT ...]

positional arguments:
  INPUT                One or more VSL JSON output files

options:
  --client NAME        Client name (required)
  --engagement DESC    Engagement description
  --auditor NAME       Auditor name/team (default: VampSecure Labs)
  --scope TEXT         Engagement scope
  --start-date DATE    Start date (YYYY-MM-DD)
  --end-date DATE      End date (YYYY-MM-DD)
  --report-html FILE   HTML output file (default: report.html)
  --report-pdf FILE    PDF output file (requires fpdf2)
  --report-md FILE     Markdown output file
  --report-json FILE   Consolidated JSON output file
  --logo-url URL       Client logo URL (HTML only, optional)
  --logo-file FILE     Local logo file embedded as base64 (PNG/JPG/SVG)
  --executive-only     Executive summary only, no technical findings
  --verbose            Verbose/debug output
```

---

### Input JSON schema

VSL tools produce output files in the following standard schema. All fields are optional except `findings`.

| Field | Type | Description |
|-------|------|-------------|
| `tool` | string | Tool name (e.g. `vamp-docker-audit`) |
| `version` | string | Tool version |
| `target` | string | Scan target (hostname, IP, path…) |
| `timestamp` | string | ISO 8601 scan timestamp |
| `findings` | array | Array of finding objects (see below) |
| `summary` | object | Count by severity (optional, for reference) |

#### Finding object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Finding identifier (e.g. `DOCK-001`, `FORA-001`) |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `title` | string | Short finding title |
| `description` | string | Technical description |
| `evidence` | string | Raw evidence / proof of concept |
| `remediation` | string | Recommended fix |
| `references` | array | External references (CVEs, CWEs, URLs…) |

Alternative field names are also accepted: `results`/`issues`/`vulnerabilities` instead of `findings`; `risk`/`level` instead of `severity`; `detail`/`details` instead of `description`; `output`/`proof` instead of `evidence`; `fix`/`recommendation` instead of `remediation`.

---

### Report sections

| Section | Description |
|---------|-------------|
| **Cover page** | Client name, dates, auditor, CONFIDENTIAL classification, optional logo |
| **Table of contents** | Navigable index with dynamic numbering |
| **Executive summary** | Risk gauge (SVG), severity table, top 5 findings, tool distribution chart |
| **Remediation roadmap** | 4-phase plan: Immediate (0–7d), Urgent (7–30d), Planned (30–90d), Continuous |
| **MITRE ATT&CK coverage** | Auto-generated when FORA-NNN findings are present — tactics matrix with severity badges and technique tooltips |
| **Technical findings** | Full detail per finding: description, evidence, remediation, CVSS estimate, references |
| **Methodology** | Tools used, severity classification table |
| **Disclaimer** | Confidentiality notice |

> The MITRE ATT&CK section only appears when the report contains findings from `vamp-log-analyzer` (FORA-NNN prefix). Section numbers adjust automatically.

---

### MITRE ATT&CK Coverage

When `vamp-log-analyzer` output is included, `vamp-penreport` automatically maps the 25 FORA-NNN detectors to MITRE ATT&CK tactics and renders a coverage matrix. Example:

| Tactic | Detected | Detectors |
|--------|----------|-----------|
| Credential Access | CRITICAL×2, HIGH×1 | `FORA-001` `FORA-002` `FORA-022` |
| Reconnaissance | HIGH×1 | `FORA-009` |
| Initial Access | MEDIUM×1 | `FORA-007` |
| … | … | … |

The 25 detectors cover 12 tactics: Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration.

---

### Compatible VSL tools

`vamp-penreport` works with JSON output from any tool in the VampSecure Labs toolkit:

- `vamp-log-analyzer` — Forensic log analysis — 25 MITRE ATT&CK detectors, STIX 2.1 *(triggers ATT&CK section)*
- `vamp-docker-audit` — Docker container and daemon security
- `vamp-k8s-audit` — Kubernetes cluster security review
- `vamp-ssl-audit` — TLS/SSL certificate and configuration analysis
- `vamp-secrets-scanner` — Hardcoded secrets and credential detection
- `vamp-http-audit` — HTTP headers and web security checks
- `vamp-wp2shell-audit` — WordPress vulnerability assessment
- `vamp-passive-recon` — OSINT and passive reconnaissance
- `vamp-subdomain-takeover` — Subdomain takeover detection
- `vamp-cve-oracle` — CVE correlation and vulnerability lookup
- `vamp-jwt-audit` — JWT token security analysis
- `vamp-llm-probe` — LLM endpoint security assessment
- `vamp-mail-audit` — Email security (SPF/DKIM/DMARC)
- `vamp-arp-sentinel` — ARP spoofing and network analysis
- `vamp-entropy-watch` — Entropy-based anomaly detection
- `vamp-forticheck` — Multi-vendor edge device CVE scanner
- `vamp-cloud-enum` — Cloud asset enumeration

---

### Sample Output

```bash
$ python3 vamp_penreport.py \
    recon.json ssl.json http.json logs_forensic.json \
    --client "Acme Corp" \
    --engagement "External Pentest Q3 2026" \
    --auditor "VampSecure Labs Red Team" \
    --scope "Perimeter web applications and public APIs" \
    --start-date 2026-07-01 --end-date 2026-07-31 \
    --logo-file /path/to/acme_logo.png \
    --report-html pentest_report.html \
    --report-pdf  pentest_report.pdf \
    --report-json consolidated.json
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  vamp-penreport v2.7 · VampSecure Labs Security Research Division            │
╰──────────────────────────────────────────────────────────────────────────────╯

Loading input files…
  ✓ recon.json          (vamp-passive-recon v1.2.1  ·  4 findings)
  ✓ ssl.json            (vamp-ssl-audit v2.3.1       ·  2 findings)
  ✓ http.json           (vamp-http-audit v1.8.0      ·  5 findings)
  ✓ logs_forensic.json  (vamp-log-analyzer v3.1      ·  4 findings — MITRE ATT&CK)

Normalization: 15 raw findings → 14 unique (1 deduplicated SSL/HTTP)
Risk score:    raw=185 → 91/100  [Critical]

Report sections:
  [1] Cover page             → Acme Corp · External Pentest Q3 2026
  [2] Table of contents      → 8 sections with dynamic numbering
  [3] Executive summary      → SVG gauge + top 5 findings + chart by tool
  [4] Remediation roadmap    → Immediate (2) · Urgent (5) · Planned (5) · Continuous (2)
  [5] MITRE ATT&CK coverage  → 4 tactics · 4 FORA-NNN detectors (auto-generated)
  [6] Technical findings     → 14 findings with evidence, CVSS estimate and references
  [7] Methodology            → tools used, severity classification table
  [8] Legal notice and confidentiality

Embedded logo: acme_logo.png → base64 data URI (128 KB)

Generating outputs…
  ✓ pentest_report.html    (self-contained file, no external requests)
  ✓ pentest_report.pdf     (18 pages, generated with fpdf2)
  ✓ consolidated.json      (VSL schema 2.2, 14 findings)
```

---

### Why vamp-penreport vs. Dradis · PlexTrac · Serpico

| Capability | vamp-penreport | Dradis | PlexTrac | Serpico |
|---|---|---|---|---|
| Native VSL JSON ingestion | ✅ | ❌ (manual parsers) | ✅ (import) | ❌ |
| Native PDF without browser (fpdf2) | ✅ | ✅ | ✅ | ✅ |
| Auto-generated MITRE ATT&CK section | ✅ | ❌ | ✅ | ❌ |
| Automatic ENS RD 311/2022 checklist | ✅ (`--sector admin-publica`) | ❌ | ❌ | ❌ |
| Self-hosted, CLI without web backend | ✅ | ✅ | ❌ (SaaS) | ✅ |
| Base64-embedded logo (self-contained HTML) | ✅ | ❌ | ❌ | ❌ |
| Open source (MIT) | ✅ | ✅ | ❌ (commercial) | ✅ |
| Integrated logarithmic scoring | ✅ | ❌ | ❌ | ❌ |

- Zero backend dependencies: a single CLI command generates HTML, PDF, and Markdown ready for client delivery.
- The MITRE ATT&CK section is generated automatically from FORA-NNN findings in `vamp-log-analyzer` — no additional configuration or manual mapping required.
- The ENS RD 311/2022 checklist (`--sector admin-publica`) automatically marks controls affected by engagement findings, reducing drafting time for Spanish public-sector clients.
- The HTML is completely self-contained (logo, SVG charts embedded) — no external requests when opening the report on the client side.

---

### Report Sections Coverage

| Report section | Generated content | Condition |
|---|---|---|
| Cover page | Client, dates, auditor, scope, logo, CONFIDENTIAL classification | Always |
| Table of contents | Navigable index with dynamic numbering, HTML anchors | Always |
| Executive summary | SVG risk gauge, severity table, top 5 findings, chart by tool | Always |
| Remediation roadmap | 4 phases: Immediate (0–7d), Urgent (7–30d), Planned (30–90d), Continuous | Always |
| MITRE ATT&CK coverage | Tactics/techniques matrix with severity badges and technique tooltips | Only if FORA-NNN findings present |
| Technical findings | Description, evidence, CVSS estimate, references, remediation per finding | Omitted with `--executive-only` |
| ENS RD 311/2022 checklist | Status by control (op.acc, op.exp, op.mon, mp.com, mp.sw, mp.info…) | `--sector admin-publica` |
| Methodology | Tools used with version, VSL severity classification table | Always |
| Legal notice | Confidentiality, authorization scope, disclaimer | Always |

---

### Version History

| Version | Main changes |
|---------|-------------|
| v2.7 | Bilingual README (EN/ES) |
| v2.6 | ENS RD 311/2022 checklist in `--sector admin-publica`: automatic control status (op.acc.1–6, op.exp.2/7, op.mon.1, mp.com.1/3, mp.sw.1, mp.info.3) |
| v2.5 | Additional sectors (generic, healthcare); configurable executive report |
| v2.4 | VampSecure Labs Security Research Division — initial public release |

---

### License

MIT — See `LICENSE` file.

---

© VampSecure Studios — VampSecure Labs Security Research Division

*Authorized use only in environments with explicit written permission.*

---

<a name="español"></a>
## 🇪🇸 Español

`vamp-penreport` lee ficheros JSON de salida de cualquier herramienta VSL, normaliza y deduplica todos los hallazgos, calcula una puntuación de riesgo global y genera informes HTML, PDF y Markdown listos para entregar al cliente.

**No es un escáner** — es un agregador y generador de informes. No tiene prefijo de hallazgo propio; trabaja con los hallazgos producidos por otras herramientas VSL.

---

### Características

- Ingesta múltiples ficheros JSON de salida VSL en una sola ejecución
- Normaliza etiquetas de severidad y deduplica hallazgos entre herramientas
- Calcula puntuación de riesgo global (0–100) con etiqueta cualitativa (Bajo / Moderado / Alto / Crítico)
- Resumen ejecutivo con gauge SVG inline y gráfico de barras por categoría
- Roadmap de remediación priorizado (4 fases: Inmediata / Urgente / Planificada / Continua)
- **Sección de cobertura MITRE ATT&CK**: auto-detectada de hallazgos FORA-NNN de `vamp-log-analyzer` — 25 detectores mapeados a 12 tácticas; renderizada como tabla interactiva con badges de severidad y tooltips de técnica
- Sección de hallazgos técnicos detallados con rango CVSS estimado
- **Embedding de logo local**: `--logo-file RUTA` embebe cualquier PNG/JPG/SVG como data URI base64 — el HTML es completamente autocontenido sin peticiones externas
- HTML imprimible con soporte CSS `@media print` completo
- PDF nativo via `fpdf2` (sin necesidad de navegador)
- Salida Markdown para integración en wikis o sistemas de documentación
- Exportación JSON consolidado para integración en pipelines

---

### Instalación

```bash
pip install vamp-penreport
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-penreport
```

```bash
cd vamp-penreport
pip install -r requirements.txt
```

`fpdf2` solo es necesario para la salida PDF. La generación de HTML y Markdown funciona solo con la biblioteca estándar de Python.

---

### Uso

#### Básico — solo HTML

```bash
python3 vamp_penreport.py scan1.json \
  --client "Acme Corp" \
  --engagement "Pentest Externo Q3 2026"
```

#### Informe completo — HTML + PDF + Markdown

```bash
python3 vamp_penreport.py scan1.json scan2.json scan3.json \
  --client "Acme Corp" \
  --engagement "Pentest Externo Q3 2026" \
  --auditor "VampSecure Labs Red Team" \
  --scope "Aplicaciones web perimetrales y APIs expuestas" \
  --start-date 2026-07-01 \
  --end-date 2026-07-31 \
  --logo-file /ruta/al/logo_cliente.png \
  --report-html informe.html \
  --report-pdf informe.pdf \
  --report-md informe.md \
  --report-json consolidado.json
```

#### Solo resumen ejecutivo (sin hallazgos técnicos detallados)

```bash
python3 vamp_penreport.py scan1.json scan2.json \
  --client "Acme Corp" \
  --engagement "Evaluación Rápida" \
  --executive-only \
  --report-html resumen_ejecutivo.html
```

#### Informe forense con cobertura MITRE ATT&CK

Cuando la entrada incluye salida de `vamp-log-analyzer`, el informe añade automáticamente una **sección de cobertura MITRE ATT&CK** que muestra qué tácticas y técnicas fueron observadas:

```bash
python3 vamp_penreport.py \
  recon.json ssl.json http.json logs_forensic.json \
  --client "Acme Corp" \
  --engagement "Evaluación Perimetral Completa" \
  --report-html informe_completo.html
```

---

### Esquema JSON de entrada

Las herramientas VSL producen ficheros de salida con el siguiente esquema estándar. Todos los campos son opcionales excepto `findings`.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `tool` | string | Nombre de la herramienta (p.ej. `vamp-docker-audit`) |
| `version` | string | Versión de la herramienta |
| `target` | string | Objetivo del escaneo (hostname, IP, ruta…) |
| `timestamp` | string | Timestamp del escaneo en ISO 8601 |
| `findings` | array | Array de objetos de hallazgo (ver abajo) |
| `summary` | object | Conteo por severidad (opcional, a título informativo) |

#### Objeto de hallazgo

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | string | Identificador del hallazgo (p.ej. `DOCK-001`, `FORA-001`) |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` o `INFO` |
| `title` | string | Título corto del hallazgo |
| `description` | string | Descripción técnica |
| `evidence` | string | Evidencia bruta / prueba de concepto |
| `remediation` | string | Corrección recomendada |
| `references` | array | Referencias externas (CVEs, CWEs, URLs…) |

También se aceptan nombres de campo alternativos: `results`/`issues`/`vulnerabilities` en lugar de `findings`; `risk`/`level` en lugar de `severity`; `detail`/`details` en lugar de `description`; `output`/`proof` en lugar de `evidence`; `fix`/`recommendation` en lugar de `remediation`.

---

### Secciones del informe

| Sección | Descripción |
|---------|-------------|
| **Portada** | Nombre del cliente, fechas, auditor, clasificación CONFIDENTIAL, logo opcional |
| **Tabla de contenidos** | Índice navegable con numeración dinámica |
| **Resumen ejecutivo** | Gauge de riesgo (SVG), tabla de severidades, top 5 hallazgos, gráfico por herramienta |
| **Roadmap de remediación** | Plan de 4 fases: Inmediata (0–7d), Urgente (7–30d), Planificada (30–90d), Continua |
| **Cobertura MITRE ATT&CK** | Auto-generada cuando hay hallazgos FORA-NNN — matriz de tácticas con badges de severidad y tooltips de técnica |
| **Hallazgos técnicos** | Detalle completo por hallazgo: descripción, evidencia, remediación, CVSS estimado, referencias |
| **Metodología** | Herramientas utilizadas, tabla de clasificación de severidad |
| **Aviso legal** | Aviso de confidencialidad |

> La sección MITRE ATT&CK solo aparece cuando el informe contiene hallazgos de `vamp-log-analyzer` (prefijo FORA-NNN). La numeración de secciones se ajusta automáticamente.

---

### Cobertura MITRE ATT&CK

Cuando se incluye la salida de `vamp-log-analyzer`, `vamp-penreport` mapea automáticamente los 25 detectores FORA-NNN a las tácticas MITRE ATT&CK y renderiza una matriz de cobertura. Ejemplo:

| Táctica | Detectado | Detectores |
|---------|-----------|-----------|
| Credential Access | CRITICAL×2, HIGH×1 | `FORA-001` `FORA-002` `FORA-022` |
| Reconnaissance | HIGH×1 | `FORA-009` |
| Initial Access | MEDIUM×1 | `FORA-007` |
| … | … | … |

Los 25 detectores cubren 12 tácticas: Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration.

---

### Herramientas VSL compatibles

`vamp-penreport` funciona con la salida JSON de cualquier herramienta del toolkit VampSecure Labs:

- `vamp-log-analyzer` — Análisis forense de logs — 25 detectores MITRE ATT&CK, STIX 2.1 *(activa la sección ATT&CK)*
- `vamp-docker-audit` — Seguridad de contenedores y daemon Docker
- `vamp-k8s-audit` — Revisión de seguridad de clústeres Kubernetes
- `vamp-ssl-audit` — Análisis de certificados y configuración TLS/SSL
- `vamp-secrets-scanner` — Detección de secretos y credenciales hardcodeadas
- `vamp-http-audit` — Cabeceras HTTP y checks de seguridad web
- `vamp-wp2shell-audit` — Evaluación de vulnerabilidades WordPress
- `vamp-passive-recon` — OSINT y reconocimiento pasivo
- `vamp-subdomain-takeover` — Detección de subdomain takeover
- `vamp-cve-oracle` — Correlación CVE y búsqueda de vulnerabilidades
- `vamp-jwt-audit` — Análisis de seguridad de tokens JWT
- `vamp-llm-probe` — Evaluación de seguridad de endpoints LLM
- `vamp-mail-audit` — Seguridad de correo electrónico (SPF/DKIM/DMARC)
- `vamp-arp-sentinel` — ARP spoofing y análisis de red
- `vamp-entropy-watch` — Detección de anomalías por entropía
- `vamp-forticheck` — Escáner CVE para dispositivos de red multi-vendor
- `vamp-cloud-enum` — Enumeración de activos en la nube

---

### Why vamp-penreport vs. Dradis · PlexTrac · Serpico

| Capacidad | vamp-penreport | Dradis | PlexTrac | Serpico |
|---|---|---|---|---|
| Ingesta directa de JSON VSL nativa | ✅ | ❌ (parsers manuales) | ✅ (importación) | ❌ |
| PDF nativo sin browser (fpdf2) | ✅ | ✅ | ✅ | ✅ |
| Sección MITRE ATT&CK auto-generada | ✅ | ❌ | ✅ | ❌ |
| Checklist ENS RD 311/2022 automático | ✅ (`--sector admin-publica`) | ❌ | ❌ | ❌ |
| Self-hosted, CLI sin backend web | ✅ | ✅ | ❌ (SaaS) | ✅ |
| Logo embebido base64 (HTML autocontenido) | ✅ | ❌ | ❌ | ❌ |
| Open source (MIT) | ✅ | ✅ | ❌ (comercial) | ✅ |
| Scoring logarítmico integrado | ✅ | ❌ | ❌ | ❌ |

- Cero dependencias de backend: un único comando CLI genera HTML, PDF y Markdown listos para entregar al cliente.
- La sección MITRE ATT&CK se genera automáticamente a partir de los findings FORA-NNN de `vamp-log-analyzer` — sin configuración adicional ni mapeo manual.
- El checklist ENS RD 311/2022 (`--sector admin-publica`) marca automáticamente los controles afectados por los findings del engagement, reduciendo el tiempo de redacción para clientes de la Administración Pública española.
- El HTML es completamente autocontenido (logo, gráficos SVG embebidos) — sin peticiones externas al abrir el informe en el cliente.

---

### Cobertura de secciones del informe

| Sección del informe | Contenido generado | Condición |
|---|---|---|
| Portada | Cliente, fechas, auditor, scope, logo, clasificación CONFIDENTIAL | Siempre |
| Tabla de contenidos | Índice con numeración dinámica, navegable por anclas HTML | Siempre |
| Resumen ejecutivo | Gauge SVG de riesgo, tabla de severidades, top 5 findings, gráfico por herramienta | Siempre |
| Roadmap de remediación | 4 fases: Inmediata (0–7d), Urgente (7–30d), Planificada (30–90d), Continua | Siempre |
| Cobertura MITRE ATT&CK | Matriz de tácticas/técnicas con badges de severidad y tooltips de técnica | Solo si hay findings FORA-NNN |
| Hallazgos técnicos | Descripción, evidencia, CVSS estimado, referencias, remediación por finding | Omitido con `--executive-only` |
| Checklist ENS RD 311/2022 | Estado por control (op.acc, op.exp, op.mon, mp.com, mp.sw, mp.info…) | `--sector admin-publica` |
| Metodología | Herramientas usadas con versión, tabla de clasificación de severidad VSL | Siempre |
| Aviso legal | Confidencialidad, alcance de la autorización, descargo de responsabilidad | Siempre |

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v2.7 | README bilingüe (EN/ES) |
| v2.6 | Checklist ENS RD 311/2022 en `--sector admin-publica`: estado automático por control (op.acc.1–6, op.exp.2/7, op.mon.1, mp.com.1/3, mp.sw.1, mp.info.3) |
| v2.5 | Sectores adicionales (genérico, sanidad); informe ejecutivo configurable |
| v2.4 | VampSecure Labs Security Research Division — versión inicial pública |

---

### Licencia

MIT — Ver fichero `LICENSE`.

---

© VampSecure Studios — VampSecure Labs Security Research Division

*Uso autorizado únicamente en entornos con permiso escrito explícito.*
