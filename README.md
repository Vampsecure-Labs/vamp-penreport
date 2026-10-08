<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-penreport/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-penreport

![Version](https://img.shields.io/badge/version-2.6-crimson)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![VampSecure Labs](https://img.shields.io/badge/VampSecure-Labs-7c3aed)

**Professional pentest report aggregator for VampSecure Labs toolkit.**

`vamp-penreport` reads JSON output files from any VSL tool, normalizes and deduplicates all findings, computes a global risk score, and produces polished HTML, PDF, and Markdown reports ready for client delivery.

It is **not a scanner** — it is a report aggregator and generator. It has no finding prefix of its own; it works with findings produced by other VSL tools.

---

## Features

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

## Installation


```bash
pip install vamp-penreport
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-penreport
```

```bash
cd vamp-penreport
pip install -r requirements.txt
```

`fpdf2` is only required for PDF output. HTML and Markdown generation work with Python stdlib alone.

---

## Usage

### Basic — HTML only

```bash
python3 vamp_penreport.py scan1.json \
  --client "Acme Corp" \
  --engagement "External Pentest Q3 2026"
```

### Full report — HTML + PDF + Markdown

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

### Executive summary only (no detailed technical findings)

```bash
python3 vamp_penreport.py scan1.json scan2.json \
  --client "Acme Corp" \
  --engagement "Quick Assessment" \
  --executive-only \
  --report-html executive_summary.html
```

### Forensic log report with MITRE ATT&CK coverage

When the input includes output from `vamp-log-analyzer`, the report automatically adds a **MITRE ATT&CK coverage section** showing which tactics and techniques were observed:

```bash
python3 vamp_penreport.py \
  recon.json ssl.json http.json logs_forensic.json \
  --client "Acme Corp" \
  --engagement "Full Perimeter Assessment" \
  --report-html full_report.html
```

### All options

```
usage: vamp-penreport [-h] --client NOMBRE [--engagement DESC]
                      [--auditor NOMBRE] [--scope TEXTO]
                      [--start-date FECHA] [--end-date FECHA]
                      [--report-html FILE] [--report-pdf FILE]
                      [--report-md FILE] [--report-json FILE]
                      [--logo-url URL] [--logo-file FICHERO]
                      [--executive-only] [--verbose]
                      INPUT [INPUT ...]

positional arguments:
  INPUT                One or more VSL JSON output files

options:
  --client NOMBRE      Client name (required)
  --engagement DESC    Engagement description
  --auditor NOMBRE     Auditor name/team (default: VampSecure Labs)
  --scope TEXTO        Engagement scope
  --start-date FECHA   Start date (YYYY-MM-DD)
  --end-date FECHA     End date (YYYY-MM-DD)
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

## Input JSON schema

VSL tools produce output files in the following standard schema. All fields are optional except `findings`.

| Field | Type | Description |
|-------|------|-------------|
| `tool` | string | Tool name (e.g. `vamp-docker-audit`) |
| `version` | string | Tool version |
| `target` | string | Scan target (hostname, IP, path…) |
| `timestamp` | string | ISO 8601 scan timestamp |
| `findings` | array | Array of finding objects (see below) |
| `summary` | object | Count by severity (optional, for reference) |

### Finding object

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

## Report sections

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

## MITRE ATT&CK Coverage

When `vamp-log-analyzer` output is included, `vamp-penreport` automatically maps the 25 FORA-NNN detectors to MITRE ATT&CK tactics and renders a coverage matrix. Example:

| Tactic | Detected | Detectors |
|--------|----------|-----------|
| Credential Access | CRITICAL×2, HIGH×1 | `FORA-001` `FORA-002` `FORA-022` |
| Reconnaissance | HIGH×1 | `FORA-009` |
| Initial Access | MEDIUM×1 | `FORA-007` |
| … | … | … |

The 25 detectors cover 12 tactics: Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration.

---

## Compatible VSL tools

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
- `vamp-k8s-audit` — Kubernetes cluster security review
- `vamp-llm-probe` — LLM endpoint security assessment
- `vamp-mail-audit` — Email security (SPF/DKIM/DMARC)
- `vamp-arp-sentinel` — ARP spoofing and network analysis
- `vamp-entropy-watch` — Entropy-based anomaly detection
- `vamp-forticheck` — Multi-vendor edge device CVE scanner
- `vamp-cloud-enum` — Cloud asset enumeration

---

## License

MIT — See `LICENSE` file.

---

© VampSecure Studios — VampSecure Labs Security Research Division

*Authorized use only in environments with explicit written permission.*

---

## Sample Output

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
│  vamp-penreport v2.6 · VampSecure Labs Security Research Division            │
╰──────────────────────────────────────────────────────────────────────────────╯

Cargando ficheros de entrada…
  ✓ recon.json          (vamp-passive-recon v1.2.0  ·  4 findings)
  ✓ ssl.json            (vamp-ssl-audit v2.3.1       ·  2 findings)
  ✓ http.json           (vamp-http-audit v1.8.0      ·  5 findings)
  ✓ logs_forensic.json  (vamp-log-analyzer v3.1      ·  4 findings — MITRE ATT&CK)

Normalización: 15 findings brutos → 14 únicos (1 deduplicado SSL/HTTP)
Risk score:    raw=185 → 91/100  [Critical]

Secciones del informe:
  [1] Portada                    → Acme Corp · External Pentest Q3 2026
  [2] Tabla de contenidos        → 8 secciones con numeración dinámica
  [3] Resumen ejecutivo          → gauge SVG + top 5 hallazgos + gráfico por herramienta
  [4] Roadmap de remediación     → Inmediata (2) · Urgente (5) · Planificada (5) · Continua (2)
  [5] Cobertura MITRE ATT&CK     → 4 tácticas · 4 detectores FORA-NNN (auto-generada)
  [6] Hallazgos técnicos         → 14 hallazgos con evidencia, CVSS estimado y referencias
  [7] Metodología                → herramientas usadas, tabla de clasificación de severidad
  [8] Aviso legal y confidencialidad

Logo embebido: acme_logo.png → base64 data URI (128 KB)

Generando salidas…
  ✓ pentest_report.html    (fichero autocontenido, sin peticiones externas)
  ✓ pentest_report.pdf     (18 páginas, generado con fpdf2)
  ✓ consolidated.json      (schema VSL 2.2, 14 findings)
```

---

## Why vamp-penreport vs. Dradis · PlexTrac · Serpico

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

## Report Sections Coverage

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

## Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v2.6 | Checklist ENS RD 311/2022 en `--sector admin-publica`: estado automático por control (op.acc.1–6, op.exp.2/7, op.mon.1, mp.com.1/3, mp.sw.1, mp.info.3) |
| v2.5 | Sectores adicionales (genérico, sanidad); informe ejecutivo configurable |
| v2.4 | VampSecure Labs Security Research Division — versión inicial pública |
