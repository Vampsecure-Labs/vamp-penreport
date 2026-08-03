# vamp-penreport

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
- Detailed technical findings section with estimated CVSS range
- Printable HTML with full CSS `@media print` support
- Native PDF via `fpdf2` (no browser required)
- Markdown output for integration into wikis or documentation systems
- Consolidated JSON export for pipeline integration

---

## Installation

```bash
cd vamp-penreport
pip install -r requirements.txt
```

`fpdf2` is only required if you need PDF output. HTML and Markdown generation work with Python stdlib alone.

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

### Using the bundled example

```bash
python3 vamp_penreport.py example_input.json \
  --client "Demo Client" \
  --engagement "Example Run" \
  --report-html demo_report.html \
  --report-pdf demo_report.pdf
```

### All options

```
usage: vamp-penreport [-h] --client NOMBRE [--engagement DESC]
                      [--auditor NOMBRE] [--scope TEXTO]
                      [--start-date FECHA] [--end-date FECHA]
                      [--report-html FILE] [--report-pdf FILE]
                      [--report-md FILE] [--report-json FILE]
                      [--logo-url URL] [--executive-only] [--verbose]
                      INPUT [INPUT ...]

positional arguments:
  INPUT               One or more VSL JSON output files

options:
  --client NOMBRE     Client name (required)
  --engagement DESC   Engagement description
  --auditor NOMBRE    Auditor name/team (default: VampSecure Labs)
  --scope TEXTO       Engagement scope
  --start-date FECHA  Start date (YYYY-MM-DD)
  --end-date FECHA    End date (YYYY-MM-DD)
  --report-html FILE  HTML output file (default: report.html)
  --report-pdf FILE   PDF output file (requires fpdf2)
  --report-md FILE    Markdown output file
  --report-json FILE  Consolidated JSON output file
  --logo-url URL      Client logo URL (HTML only, optional)
  --executive-only    Executive summary only, no technical findings
  --verbose           Verbose/debug output
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
| `id` | string | Finding identifier (e.g. `DOCK-001`) |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `title` | string | Short finding title |
| `description` | string | Technical description |
| `evidence` | string | Raw evidence / proof of concept |
| `remediation` | string | Recommended fix |
| `references` | array | External references (CVEs, CWEs, URLs…) |

Alternative field names are also accepted for compatibility: `results`/`issues`/`vulnerabilities` instead of `findings`; `risk`/`level` instead of `severity`; `detail`/`details` instead of `description`; `output`/`proof` instead of `evidence`; `fix`/`recommendation` instead of `remediation`.

---

## Report sections

| Section | Description |
|---------|-------------|
| **Cover page** | Client name, dates, auditor, CONFIDENTIAL classification |
| **Table of contents** | Navigable index |
| **Executive summary** | Risk gauge (SVG), severity table, top 5 findings, tool distribution chart |
| **Remediation roadmap** | 4-phase plan: Immediate (0–7d), Urgent (7–30d), Planned (30–90d), Continuous |
| **Technical findings** | Full detail per finding: description, evidence, remediation, CVSS estimate, references |
| **Methodology** | Tools used, severity classification table |
| **Disclaimer** | Confidentiality notice |

---

## Compatible VSL tools

`vamp-penreport` works with JSON output from any tool in the VampSecure Labs toolkit:

- `vamp-docker-audit` — Docker container and daemon security
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
- `vamp-log-hunter` — Log analysis and anomaly detection
- `vamp-mail-audit` — Email security (SPF/DKIM/DMARC)
- `vamp-arp-sentinel` — ARP spoofing and network analysis
- `vamp-entropy-watch` — Entropy-based anomaly detection
- `vamp-icmp-shadow` — ICMP traffic analysis
- `vamp-forticheck` — FortiGate configuration review
- `vamp-cloud-enum` — Cloud asset enumeration

---

## License

MIT — See `LICENSE` file.

---

© VampSecure Studios — VampSecure Labs Security Research Division

*Authorized use only in environments with explicit written permission.*
