#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VampSecure Labs — PenReport
============================
Generador profesional de informes de auditoría de seguridad.

Agrega los resultados JSON de múltiples herramientas del toolkit VampSecure
Labs y produce informes consolidados en formato HTML ejecutivo, PDF y
Markdown, listos para entrega al cliente.

Características:
  · Ingesta de múltiples ficheros JSON de salida VSL
  · Normalización y deduplicación de hallazgos
  · Puntuación de riesgo global y por categoría
  · Resumen ejecutivo automático con métricas
  · Roadmap de remediación priorizado
  · Sección de hallazgos técnicos con CVSS estimado
  · Exportación HTML imprimible, PDF nativo y Markdown

© VampSecure Studios — VampSecure Labs Security Research Division

Uso autorizado exclusivamente en entornos con permiso explícito.
"""

import argparse
import json
import os
import sys
import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path
from html import escape as html_escape

# ---------------------------------------------------------------------------
# Constantes y configuración
# ---------------------------------------------------------------------------

VERSION = "2.0.0"
COPYRIGHT = "© VampSecure Studios — VampSecure Labs Security Research Division"
DISCLAIMER = (
    "Este informe es CONFIDENCIAL y está destinado exclusivamente al cliente indicado. "
    "Contiene información sensible sobre vulnerabilidades de seguridad. "
    "Su distribución o reproducción sin autorización expresa está prohibida. "
    "VampSecure Labs no se hace responsable del uso indebido de la información contenida "
    "en este documento."
)

# Colores ANSI para consola
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[33m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    MAGENTA = "\033[95m"
    GREY    = "\033[90m"
    WHITE   = "\033[97m"

# Colores HTML por severidad
SEV_COLOR_HTML = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

# Pesos para el cálculo de puntuación de riesgo
SEV_WEIGHT = {
    "CRITICAL": 25,
    "HIGH":     10,
    "MEDIUM":    5,
    "LOW":       1,
    "INFO":      0,
}

# CVSS estimado por severidad (valor representativo, es estimación)
SEV_CVSS = {
    "CRITICAL": "9.0–10.0",
    "HIGH":     "7.0–8.9",
    "MEDIUM":   "4.0–6.9",
    "LOW":      "1.0–3.9",
    "INFO":     "0.0",
}

# Fases de remediación
REMEDIATION_PHASES = [
    ("Fase 1 — Inmediata",       "0–7 días",    ["CRITICAL"]),
    ("Fase 2 — Urgente",         "7–30 días",   ["HIGH"]),
    ("Fase 3 — Planificada",     "30–90 días",  ["MEDIUM"]),
    ("Fase 4 — Mejora continua", "+90 días",    ["LOW", "INFO"]),
]

# Mapeo FORA-NNN → (táctica MITRE ATT&CK, técnica ATT&CK)
FORA_ATTACK_MAP: Dict[str, Tuple[str, str]] = {
    "FORA-001": ("Credential Access",      "T1110.001 — Brute Force: Password Guessing"),
    "FORA-002": ("Credential Access",      "T1110.003 — Brute Force: Password Spraying (HTTP)"),
    "FORA-003": ("Credential Access",      "T1110.003 — Brute Force: Password Spraying"),
    "FORA-004": ("Initial Access",         "T1190 — Exploit Public-Facing Application (SQLi)"),
    "FORA-005": ("Initial Access",         "T1190 — Exploit Public-Facing Application (DB SQLi)"),
    "FORA-006": ("Initial Access",         "T1059.007 — Command and Scripting Interpreter: XSS"),
    "FORA-007": ("Initial Access",         "T1190 — Exploit Public-Facing Application (LFI/RFI)"),
    "FORA-008": ("Persistence",            "T1505.003 — Server Software Component: Web Shell"),
    "FORA-009": ("Reconnaissance",         "T1595 — Active Scanning"),
    "FORA-010": ("Reconnaissance",         "T1595.003 — Active Scanning: Wordlist Scanning"),
    "FORA-011": ("Exfiltration",           "T1048 — Exfiltration Over Alternative Protocol"),
    "FORA-012": ("Collection",             "T1005 — Data from Local System (DB)"),
    "FORA-013": ("Privilege Escalation",   "T1548 — Abuse Elevation Control Mechanism"),
    "FORA-014": ("Privilege Escalation",   "T1136 — Create Account"),
    "FORA-015": ("Defense Evasion",        "T1078 — Valid Accounts (off-hours access)"),
    "FORA-016": ("Persistence",            "T1053 — Scheduled Task/Job"),
    "FORA-017": ("Execution",              "T1059 — Command and Scripting Interpreter"),
    "FORA-018": ("Lateral Movement",       "T1021 — Remote Services"),
    "FORA-019": ("Discovery",              "T1083 — File and Directory Discovery"),
    "FORA-020": ("Privilege Escalation",   "T1078.003 — Valid Accounts: Local Accounts (root)"),
    "FORA-021": ("Defense Evasion",        "T1027 — Obfuscated Files or Information"),
    "FORA-022": ("Credential Access",      "T1110.004 — Brute Force: Credential Stuffing"),
    "FORA-023": ("Command & Control",      "T1071 — Application Layer Protocol (C2 beacon)"),
    "FORA-024": ("Credential Access",      "T1110 — Brute Force: Slow Drip"),
    "FORA-025": ("Exfiltration",           "T1048.003 — Exfiltration Over Unencrypted Protocol"),
}

# Orden canónico de tácticas ATT&CK para el informe
ATTACK_TACTICS_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command & Control",
    "Exfiltration",
]

# Mapeo de alias de severidad a canónico
SEV_ALIASES = {
    "CRIT":     "CRITICAL",
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "MED":      "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW":      "LOW",
    "INFO":     "INFO",
    "INFORMATIONAL": "INFO",
    "NONE":     "INFO",
}

# ---------------------------------------------------------------------------
# Banner ASCII
# ---------------------------------------------------------------------------

BANNER = r"""
  ██╗   ██╗ █████╗ ███╗   ███╗██████╗
  ██║   ██║██╔══██╗████╗ ████║██╔══██╗
  ██║   ██║███████║██╔████╔██║██████╔╝
  ╚██╗ ██╔╝██╔══██║██║╚██╔╝██║██╔═══╝
   ╚████╔╝ ██║  ██║██║ ╚═╝ ██║██║
    ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝

  ██████╗ ███████╗███╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔══██╗██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██████╔╝█████╗  ██╔██╗ ██║██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║
  ██╔═══╝ ██╔══╝  ██║╚██╗██║██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║
  ██║     ███████╗██║ ╚████║██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝
"""

# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Representa un hallazgo de seguridad normalizado."""
    id: str
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: str
    evidence: str
    remediation: str
    references: List[str]
    source_tool: str        # Herramienta VSL que lo generó
    target: str             # Objetivo del escaneo

    @property
    def cvss_estimate(self) -> str:
        """Devuelve el rango CVSS estimado según la severidad."""
        return SEV_CVSS.get(self.severity, "N/A")

    @property
    def color_html(self) -> str:
        """Color HTML asociado a la severidad."""
        return SEV_COLOR_HTML.get(self.severity, "#6b7280")


@dataclass
class ReportMeta:
    """Metadatos del informe de auditoría."""
    client: str
    engagement: str
    auditor: str = "VampSecure Labs"
    scope: str = ""
    start_date: str = ""
    end_date: str = ""
    logo_url: str = ""
    logo_b64: str = ""   # data URI base64 (tiene prioridad sobre logo_url)
    generated_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds"))


@dataclass
class ToolResult:
    """Resultado de una herramienta VSL cargada."""
    tool: str
    version: str
    target: str
    timestamp: str
    findings_count: int
    filepath: str


# ---------------------------------------------------------------------------
# Funciones de utilidad de consola
# ---------------------------------------------------------------------------

def cprint(text: str, color: str = "", bold: bool = False) -> None:
    """Imprime texto con color ANSI opcional."""
    prefix = ""
    if bold:
        prefix += Color.BOLD
    if color:
        prefix += color
    suffix = Color.RESET if (prefix) else ""
    print(f"{prefix}{text}{suffix}")


def cprint_sev(severity: str, text: str) -> None:
    """Imprime texto con el color correspondiente a la severidad."""
    color_map = {
        "CRITICAL": Color.RED,
        "HIGH":     Color.ORANGE,
        "MEDIUM":   Color.YELLOW,
        "LOW":      Color.BLUE,
        "INFO":     Color.GREY,
    }
    color = color_map.get(severity, Color.RESET)
    cprint(text, color)


def print_banner() -> None:
    """Muestra el banner de inicio."""
    cprint(BANNER, Color.MAGENTA, bold=True)
    cprint(f"  PenReport v{VERSION} — Generador de Informes de Auditoría", Color.CYAN, bold=True)
    cprint(f"  {COPYRIGHT}", Color.GREY)
    print()


def verbose_log(msg: str, verbose: bool = False) -> None:
    """Imprime mensajes de depuración solo en modo verbose."""
    if verbose:
        cprint(f"  [DBG] {msg}", Color.GREY)


# ---------------------------------------------------------------------------
# Normalización de hallazgos
# ---------------------------------------------------------------------------

def normalize_severity(raw: str) -> str:
    """
    Normaliza un valor de severidad a uno de los canónicos:
    CRITICAL, HIGH, MEDIUM, LOW, INFO.
    Si no se reconoce, devuelve INFO por defecto.
    """
    if not raw:
        return "INFO"
    upper = raw.strip().upper()
    return SEV_ALIASES.get(upper, "INFO")


def extract_findings_from_json(data: Dict[str, Any], filepath: str, verbose: bool = False) -> Tuple[List[Dict], str, str, str]:
    """
    Extrae hallazgos brutos de un JSON VSL, intentando múltiples estructuras.
    Devuelve (lista_de_hallazgos, nombre_tool, version, target).
    """
    tool    = data.get("tool",      Path(filepath).stem)
    version = data.get("version",   "unknown")
    target  = data.get("target",    "N/A")

    # Campo principal
    findings_raw = data.get("findings")

    # Campos alternativos si no existe 'findings'
    if findings_raw is None:
        for alt in ("results", "issues", "vulnerabilities", "alerts", "checks"):
            if alt in data and isinstance(data[alt], list):
                findings_raw = data[alt]
                verbose_log(f"Campo alternativo '{alt}' usado en {filepath}", verbose)
                break

    if findings_raw is None:
        findings_raw = []
        verbose_log(f"No se encontraron hallazgos en {filepath}", verbose)

    return findings_raw, tool, version, target


def normalize_finding(raw: Dict[str, Any], source_tool: str, target: str, index: int) -> Finding:
    """
    Normaliza un hallazgo bruto a la estructura Finding canónica.
    Intenta múltiples nombres de campo para mayor compatibilidad.
    """
    # ID
    fid = (
        raw.get("id") or
        raw.get("finding_id") or
        raw.get("check_id") or
        f"{source_tool.upper()[:4]}-{index:03d}"
    )

    # Severidad
    sev_raw = (
        raw.get("severity") or
        raw.get("risk") or
        raw.get("level") or
        raw.get("priority") or
        "INFO"
    )

    # Título
    title = (
        raw.get("title") or
        raw.get("name") or
        raw.get("check") or
        raw.get("message") or
        f"Hallazgo #{index}"
    )

    # Descripción
    description = (
        raw.get("description") or
        raw.get("detail") or
        raw.get("details") or
        raw.get("info") or
        ""
    )

    # Evidencia
    evidence = (
        raw.get("evidence") or
        raw.get("output") or
        raw.get("raw_output") or
        raw.get("proof") or
        raw.get("data") or
        ""
    )

    # Remediación
    remediation = (
        raw.get("remediation") or
        raw.get("fix") or
        raw.get("recommendation") or
        raw.get("mitigation") or
        "Consultar con el equipo de seguridad para definir plan de remediación."
    )

    # Referencias
    refs = raw.get("references") or raw.get("refs") or raw.get("links") or []
    if isinstance(refs, str):
        refs = [refs]

    return Finding(
        id=str(fid),
        severity=normalize_severity(str(sev_raw)),
        title=str(title),
        description=str(description),
        evidence=str(evidence),
        remediation=str(remediation),
        references=refs,
        source_tool=source_tool,
        target=str(raw.get("target", target)),
    )


# ---------------------------------------------------------------------------
# Clase principal PenReport
# ---------------------------------------------------------------------------

class PenReport:
    """
    Agregador y generador de informes de auditoría VSL.

    Carga múltiples ficheros JSON de salida de herramientas VSL,
    normaliza y deduplica los hallazgos, y genera informes en
    HTML, PDF y Markdown.
    """

    def __init__(self, meta: ReportMeta, verbose: bool = False) -> None:
        self.meta = meta
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.tool_results: List[ToolResult] = []

    # ------------------------------------------------------------------
    # Carga de datos
    # ------------------------------------------------------------------

    def load_vsl_json(self, filepath: str) -> int:
        """
        Carga un fichero JSON de salida VSL y agrega sus hallazgos.
        Devuelve el número de hallazgos cargados desde ese fichero.
        """
        path = Path(filepath)
        if not path.exists():
            cprint(f"  [!] Fichero no encontrado: {filepath}", Color.RED)
            return 0
        if not path.suffix.lower() == ".json":
            cprint(f"  [!] El fichero no es JSON: {filepath}", Color.YELLOW)

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            cprint(f"  [!] Error al parsear JSON en {filepath}: {exc}", Color.RED)
            return 0
        except OSError as exc:
            cprint(f"  [!] Error al leer {filepath}: {exc}", Color.RED)
            return 0

        findings_raw, tool, version, target = extract_findings_from_json(
            data, filepath, self.verbose
        )

        loaded = 0
        for idx, raw_finding in enumerate(findings_raw, start=1):
            if not isinstance(raw_finding, dict):
                verbose_log(f"Hallazgo #{idx} ignorado (no es dict) en {filepath}", self.verbose)
                continue
            finding = normalize_finding(raw_finding, tool, target, idx)
            self.findings.append(finding)
            loaded += 1

        # Registrar resultado de la herramienta
        summary = data.get("summary", {})
        self.tool_results.append(ToolResult(
            tool=tool,
            version=version,
            target=target,
            timestamp=data.get("timestamp", ""),
            findings_count=loaded,
            filepath=filepath,
        ))

        cprint(f"  [+] {path.name}: {loaded} hallazgo(s) cargados "
               f"(tool={tool}, target={target})", Color.GREEN)
        return loaded

    # ------------------------------------------------------------------
    # Deduplicación
    # ------------------------------------------------------------------

    def deduplicate(self) -> int:
        """
        Elimina hallazgos duplicados.
        Criterio: mismo ID, o mismo título+severidad.
        Mantiene el primero encontrado y elimina los posteriores.
        Devuelve el número de duplicados eliminados.
        """
        seen_ids: set = set()
        seen_title_sev: set = set()
        unique: List[Finding] = []
        removed = 0

        for f in self.findings:
            key_id = f.id.strip().upper()
            key_ts = (f.title.strip().lower(), f.severity)

            if key_id in seen_ids or key_ts in seen_title_sev:
                removed += 1
                verbose_log(
                    f"Duplicado eliminado: {f.id} — {f.title} ({f.severity})",
                    self.verbose,
                )
                continue

            seen_ids.add(key_id)
            seen_title_sev.add(key_ts)
            unique.append(f)

        self.findings = unique
        return removed

    # ------------------------------------------------------------------
    # Puntuación de riesgo
    # ------------------------------------------------------------------

    def risk_score(self) -> int:
        """
        Calcula la puntuación de riesgo global (0-100).
        Fórmula: min(100, CRITICAL*25 + HIGH*10 + MEDIUM*5 + LOW*1)
        """
        counts = self._severity_counts()
        score = (
            counts["CRITICAL"] * SEV_WEIGHT["CRITICAL"] +
            counts["HIGH"]     * SEV_WEIGHT["HIGH"] +
            counts["MEDIUM"]   * SEV_WEIGHT["MEDIUM"] +
            counts["LOW"]      * SEV_WEIGHT["LOW"]
        )
        return min(100, score)

    def risk_label(self) -> str:
        """Clasifica la puntuación de riesgo en una etiqueta cualitativa."""
        score = self.risk_score()
        if score <= 25:
            return "Bajo"
        elif score <= 50:
            return "Moderado"
        elif score <= 75:
            return "Alto"
        else:
            return "Crítico"

    # ------------------------------------------------------------------
    # Ayudantes internos
    # ------------------------------------------------------------------

    def _severity_counts(self) -> Dict[str, int]:
        """Cuenta hallazgos por severidad."""
        counts = {sev: 0 for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _findings_by_severity(self) -> List[Finding]:
        """Devuelve los hallazgos ordenados por severidad (mayor a menor)."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(self.findings, key=lambda f: order.get(f.severity, 5))

    def _top_findings(self, n: int = 5) -> List[Finding]:
        """Devuelve los N hallazgos más críticos."""
        return self._findings_by_severity()[:n]

    def _findings_by_tool(self) -> Dict[str, List[Finding]]:
        """Agrupa hallazgos por herramienta de origen."""
        grouped: Dict[str, List[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(f.source_tool, []).append(f)
        return grouped

    def _findings_for_phase(self, severities: List[str]) -> List[Finding]:
        """Devuelve hallazgos que pertenecen a las severidades indicadas."""
        return [f for f in self._findings_by_severity() if f.severity in severities]

    # ------------------------------------------------------------------
    # Cobertura MITRE ATT&CK (hallazgos FORA-NNN)
    # ------------------------------------------------------------------

    def _fora_attack_coverage(self) -> Dict[str, List["Finding"]]:
        """
        Agrupa los hallazgos FORA-NNN por táctica MITRE ATT&CK.

        Usa el campo finding.id para buscar en FORA_ATTACK_MAP y el campo
        mitre_tactic (si existe en el JSON fuente) como respaldo.
        Devuelve un dict {táctica: [Finding, …]} solo con tácticas que tienen hallazgos.
        """
        by_tactic: Dict[str, List["Finding"]] = {}
        for f in self.findings:
            fid = f.id.strip().upper()
            # Buscar en el mapa estático
            if fid in FORA_ATTACK_MAP:
                tactic, _ = FORA_ATTACK_MAP[fid]
            elif fid.startswith("FORA-"):
                tactic = "Unknown"
            else:
                continue
            by_tactic.setdefault(tactic, []).append(f)
        return by_tactic

    def _build_attack_html(self) -> str:
        """Genera el HTML de la sección de cobertura MITRE ATT&CK."""
        by_tactic = self._fora_attack_coverage()
        if not by_tactic:
            return ""

        rows_html = ""
        for tactic in ATTACK_TACTICS_ORDER:
            findings = by_tactic.get(tactic, [])
            if not findings:
                continue
            by_sev_count: Dict[str, int] = {}
            for f in findings:
                by_sev_count[f.severity] = by_sev_count.get(f.severity, 0) + 1

            badge_str = " ".join(
                f"<span class='badge' style='background:{SEV_COLOR_HTML[s]}'>{s[:4]} ×{n}</span>"
                for s, n in sorted(by_sev_count.items(),
                                   key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x[0]))
            )
            fid_parts = []
            for f in findings:
                tip = FORA_ATTACK_MAP.get(f.id.upper(), ("", f.title))[1]
                fid_parts.append(
                    "<code title='" + html_escape(tip) + "'>" + html_escape(f.id) + "</code>"
                )
            fid_links = " ".join(fid_parts)
            rows_html += (
                f"<tr>"
                f"<td><strong>{html_escape(tactic)}</strong></td>"
                f"<td>{badge_str}</td>"
                f"<td class='fid-cell'>{fid_links}</td>"
                f"</tr>\n"
            )

        return f"""
<table class='findings-table attack-table'>
  <thead>
    <tr>
      <th style='width:200px'>Táctica ATT&amp;CK</th>
      <th style='width:260px'>Severidad detectada</th>
      <th>Detectores activados (FORA-NNN)</th>
    </tr>
  </thead>
  <tbody>
{rows_html}
  </tbody>
</table>
<p class='section-note' style='margin-top:12px'>
  Cobertura basada en los detectores de <strong>vamp-log-analyzer</strong> mapeados al
  framework <a href='https://attack.mitre.org/' style='color:#7c3aed'>MITRE ATT&amp;CK</a>.
  Solo se muestran las tácticas con al menos un hallazgo confirmado.
</p>"""

    def _build_attack_md(self) -> List[str]:
        """Genera las líneas Markdown de la sección de cobertura MITRE ATT&CK."""
        by_tactic = self._fora_attack_coverage()
        if not by_tactic:
            return []

        lines = [
            "## Cobertura MITRE ATT&CK",
            "",
            "| Táctica | Severidades | Detectores |",
            "|---------|-------------|------------|",
        ]
        for tactic in ATTACK_TACTICS_ORDER:
            findings = by_tactic.get(tactic, [])
            if not findings:
                continue
            by_sev_count: Dict[str, int] = {}
            for f in findings:
                by_sev_count[f.severity] = by_sev_count.get(f.severity, 0) + 1
            sev_str = ", ".join(f"{s}×{n}" for s, n in by_sev_count.items())
            fid_str = " ".join(f"`{f.id}`" for f in findings)
            lines.append(f"| {tactic} | {sev_str} | {fid_str} |")
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Resumen en consola
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """Muestra un resumen de los hallazgos en consola."""
        counts = self._severity_counts()
        score  = self.risk_score()
        label  = self.risk_label()

        print()
        cprint("=" * 60, Color.CYAN)
        cprint("  RESUMEN DE HALLAZGOS", Color.CYAN, bold=True)
        cprint("=" * 60, Color.CYAN)
        cprint(f"  Cliente:     {self.meta.client}", Color.WHITE)
        cprint(f"  Engagement:  {self.meta.engagement}", Color.WHITE)
        cprint(f"  Total:       {len(self.findings)} hallazgos", Color.WHITE)
        cprint(f"  Puntuación:  {score}/100 — {label}", Color.WHITE)
        print()

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = counts[sev]
            if cnt > 0:
                cprint_sev(sev, f"  {sev:<10} {cnt:>4} hallazgo(s)")

        print()
        cprint("  Herramientas cargadas:", Color.GREY)
        for tr in self.tool_results:
            cprint(f"    · {tr.tool} ({tr.findings_count} hallazgos, target: {tr.target})", Color.GREY)
        print()

    # ------------------------------------------------------------------
    # Generación de HTML
    # ------------------------------------------------------------------

    def to_html(self, filepath: str, executive_only: bool = False) -> None:
        """
        Genera el informe completo en formato HTML imprimible.
        Si executive_only=True, omite la sección de hallazgos técnicos.
        """
        counts = self._severity_counts()
        score  = self.risk_score()
        label  = self.risk_label()
        html   = self._build_html(counts, score, label, executive_only)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html)
        cprint(f"  [+] HTML generado: {filepath}", Color.GREEN)

    def _build_html(
        self,
        counts: Dict[str, int],
        score: int,
        label: str,
        executive_only: bool,
    ) -> str:
        """Construye el HTML completo del informe."""

        meta = self.meta
        now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        # --- SVG: Gauge de puntuación de riesgo ---
        gauge_svg = self._svg_gauge(score)

        # --- SVG: Gráfico de barras por categoría ---
        bar_svg = self._svg_bars_by_tool()

        # --- Tabla de hallazgos por severidad ---
        severity_table_rows = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt   = counts[sev]
            color = SEV_COLOR_HTML[sev]
            severity_table_rows += (
                f"<tr>"
                f"<td><span class='badge' style='background:{color}'>{sev}</span></td>"
                f"<td class='count-cell'>{cnt}</td>"
                f"</tr>\n"
            )

        # --- Top 5 hallazgos ---
        top5_rows = ""
        for f in self._top_findings(5):
            color = f.color_html
            top5_rows += (
                f"<tr>"
                f"<td><span class='badge' style='background:{color}'>{f.severity}</span></td>"
                f"<td><strong>{html_escape(f.id)}</strong></td>"
                f"<td>{html_escape(f.title)}</td>"
                f"<td>{html_escape(f.source_tool)}</td>"
                f"</tr>\n"
            )

        # --- Roadmap de remediación ---
        roadmap_html = self._build_roadmap_html()

        # --- Hallazgos técnicos ---
        technical_html = "" if executive_only else self._build_technical_html()

        # --- Sección ATT&CK (solo si hay hallazgos FORA-NNN) ---
        attack_html      = self._build_attack_html()
        has_attack       = bool(attack_html)

        # Numeración dinámica de secciones
        sec_exec      = 1
        sec_roadmap   = 2
        sec_attack    = 3 if has_attack else None
        _offset       = 1 if has_attack else 0
        sec_technical = (3 + _offset) if not executive_only else None
        sec_method    = 3 + _offset + (1 if not executive_only else 0)
        sec_disclaim  = sec_method + 1

        # --- Índice de contenidos ---
        toc_items = [
            (f'<a href="#exec-summary">{sec_exec}. Resumen Ejecutivo</a>',  True),
            (f'<a href="#roadmap">{sec_roadmap}. Roadmap de Remediación</a>', True),
            (f'<a href="#attack">{sec_attack}. Cobertura MITRE ATT&CK</a>',  has_attack),
            (f'<a href="#technical">{sec_technical}. Hallazgos Técnicos</a>', not executive_only),
            (f'<a href="#methodology">{sec_method}. Metodología</a>',         True),
            (f'<a href="#disclaimer">{sec_disclaim}. Disclaimer</a>',         True),
        ]
        toc_html = "<ul class='toc-list'>"
        for item, show in toc_items:
            if show:
                toc_html += f"<li>{item}</li>"
        toc_html += "</ul>"

        # --- Logo del cliente ---
        logo_html = ""
        if meta.logo_b64:
            logo_html = f"<img src='{html_escape(meta.logo_b64)}' alt='Logo cliente' class='client-logo'>"
        elif meta.logo_url:
            logo_html = f"<img src='{html_escape(meta.logo_url)}' alt='Logo cliente' class='client-logo'>"

        # --- Fechas del engagement ---
        date_range = ""
        if meta.start_date and meta.end_date:
            date_range = f"{meta.start_date} — {meta.end_date}"
        elif meta.start_date:
            date_range = f"Desde {meta.start_date}"
        elif meta.end_date:
            date_range = f"Hasta {meta.end_date}"
        else:
            date_range = now[:10]

        # --- CSS ---
        css = self._build_css()

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Informe de Auditoría — {html_escape(meta.client)}</title>
  <style>
{css}
  </style>
</head>
<body>

<!-- ===== PORTADA ===== -->
<div class="cover-page page-break-after">
  <div class="cover-header">
    <div class="vsl-brand">VampSecure Labs</div>
    <div class="vsl-division">Security Research Division</div>
  </div>

  {logo_html}

  <div class="cover-title">Informe de Auditoría de Seguridad</div>
  <div class="cover-engagement">{html_escape(meta.engagement)}</div>

  <div class="cover-meta">
    <table class="cover-table">
      <tr><td class="label">Cliente</td><td>{html_escape(meta.client)}</td></tr>
      <tr><td class="label">Auditor</td><td>{html_escape(meta.auditor)}</td></tr>
      <tr><td class="label">Período</td><td>{html_escape(date_range)}</td></tr>
      {"<tr><td class='label'>Alcance</td><td>" + html_escape(meta.scope) + "</td></tr>" if meta.scope else ""}
      <tr><td class="label">Generado</td><td>{now}</td></tr>
    </table>
  </div>

  <div class="cover-classification">
    <span class="classification-badge">CONFIDENCIAL</span>
  </div>

  <div class="cover-footer">{COPYRIGHT}</div>
</div>

<!-- ===== ÍNDICE ===== -->
<div class="section page-break-after">
  <h1 class="section-title">Índice de Contenidos</h1>
  {toc_html}
</div>

<!-- ===== RESUMEN EJECUTIVO ===== -->
<div class="section" id="exec-summary">
  <h1 class="section-title">1. Resumen Ejecutivo</h1>

  <div class="exec-grid">

    <div class="exec-card gauge-card">
      <h3>Puntuación de Riesgo Global</h3>
      {gauge_svg}
      <div class="risk-score-label risk-{label.lower()}">{score}/100 — {label}</div>
    </div>

    <div class="exec-card">
      <h3>Hallazgos por Severidad</h3>
      <table class="sev-table">
        <thead>
          <tr><th>Severidad</th><th>Total</th></tr>
        </thead>
        <tbody>
          {severity_table_rows}
          <tr class="total-row"><td><strong>TOTAL</strong></td><td class="count-cell"><strong>{len(self.findings)}</strong></td></tr>
        </tbody>
      </table>
    </div>

  </div>

  <div class="exec-card full-width">
    <h3>Distribución por Herramienta VSL</h3>
    {bar_svg}
  </div>

  <div class="exec-card full-width">
    <h3>Top 5 Hallazgos más Críticos</h3>
    <table class="findings-table">
      <thead>
        <tr>
          <th>Severidad</th>
          <th>ID</th>
          <th>Título</th>
          <th>Herramienta</th>
        </tr>
      </thead>
      <tbody>
        {top5_rows if top5_rows else "<tr><td colspan='4' class='empty-cell'>Sin hallazgos registrados</td></tr>"}
      </tbody>
    </table>
  </div>
</div>

<!-- ===== ROADMAP DE REMEDIACIÓN ===== -->
<div class="section page-break-before" id="roadmap">
  <h1 class="section-title">{sec_roadmap}. Roadmap de Remediación</h1>
  {roadmap_html}
</div>

<!-- ===== COBERTURA MITRE ATT&CK ===== -->
{"" if not has_attack else f'''
<div class="section page-break-before" id="attack">
  <h1 class="section-title">{sec_attack}. Cobertura MITRE ATT&amp;CK</h1>
  <p class="section-note">Los hallazgos forenses (FORA-NNN) han sido mapeados al framework MITRE ATT&amp;CK.
  La tabla muestra las tácticas cubiertas y los detectores activados durante el análisis de logs.</p>
  {attack_html}
</div>
'''}

<!-- ===== HALLAZGOS TÉCNICOS ===== -->
{"" if executive_only else f'''
<div class="section page-break-before" id="technical">
  <h1 class="section-title">{sec_technical}. Hallazgos Técnicos</h1>
  <p class="section-note">Los hallazgos están ordenados por severidad (mayor a menor). Los valores CVSS son estimaciones orientativas basadas en el nivel de severidad asignado por la herramienta de origen.</p>
  {technical_html}
</div>
'''}

<!-- ===== METODOLOGÍA ===== -->
<div class="section page-break-before" id="methodology">
  <h1 class="section-title">{sec_method}. Metodología</h1>
  <p>
    El presente informe ha sido generado mediante la agregación y análisis de los resultados
    producidos por las herramientas del toolkit <strong>VampSecure Labs (VSL)</strong>.
    Cada herramienta ejecuta controles específicos sobre el objetivo evaluado y produce
    hallazgos estructurados en formato JSON normalizado.
  </p>
  <h3>Herramientas evaluadas</h3>
  <table class="sev-table">
    <thead>
      <tr><th>Herramienta</th><th>Versión</th><th>Objetivo</th><th>Hallazgos</th></tr>
    </thead>
    <tbody>
      {"".join(
          f"<tr><td>{html_escape(tr.tool)}</td><td>{html_escape(tr.version)}</td>"
          f"<td>{html_escape(tr.target)}</td><td>{tr.findings_count}</td></tr>"
          for tr in self.tool_results
      )}
    </tbody>
  </table>

  <h3>Clasificación de severidad</h3>
  <table class="sev-table">
    <thead>
      <tr><th>Nivel</th><th>CVSS Estimado</th><th>Descripción</th></tr>
    </thead>
    <tbody>
      <tr><td><span class='badge' style='background:#dc2626'>CRITICAL</span></td><td>9.0–10.0</td><td>Vulnerabilidad explotable de forma inmediata con impacto máximo. Requiere remediación urgente.</td></tr>
      <tr><td><span class='badge' style='background:#ea580c'>HIGH</span></td><td>7.0–8.9</td><td>Alto riesgo de explotación. Puede comprometer datos o sistemas críticos.</td></tr>
      <tr><td><span class='badge' style='background:#d97706'>MEDIUM</span></td><td>4.0–6.9</td><td>Riesgo moderado. Explotable bajo ciertas condiciones o con información adicional.</td></tr>
      <tr><td><span class='badge' style='background:#2563eb'>LOW</span></td><td>1.0–3.9</td><td>Riesgo bajo. Impacto limitado o muy difícil de explotar de forma independiente.</td></tr>
      <tr><td><span class='badge' style='background:#6b7280'>INFO</span></td><td>0.0</td><td>Observación informativa sin riesgo directo. Puede contribuir a ataques encadenados.</td></tr>
    </tbody>
  </table>
</div>

<!-- ===== DISCLAIMER ===== -->
<div class="section" id="disclaimer">
  <h1 class="section-title">{sec_disclaim}. Disclaimer</h1>
  <div class="disclaimer-box">
    {html_escape(DISCLAIMER)}
  </div>
</div>

<!-- ===== PIE DE PÁGINA ===== -->
<div class="report-footer">
  {COPYRIGHT} · Generado el {now}
</div>

</body>
</html>"""

        return html

    def _build_css(self) -> str:
        """Devuelve el bloque CSS del informe HTML."""
        return """
    /* ===== BASE ===== */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #f8f9fa;
      color: #1a1a2e;
      font-size: 14px;
      line-height: 1.6;
    }

    /* ===== PORTADA ===== */
    .cover-page {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #0d0d1a 0%, #1a1a3e 50%, #0d0d1a 100%);
      color: #e2e8f0;
      padding: 60px 40px;
      text-align: center;
      position: relative;
    }
    .cover-header { margin-bottom: 40px; }
    .vsl-brand {
      font-size: 2.2em;
      font-weight: 900;
      letter-spacing: 0.08em;
      color: #a855f7;
      text-transform: uppercase;
    }
    .vsl-division {
      font-size: 0.95em;
      color: #7c3aed;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      margin-top: 4px;
    }
    .client-logo {
      max-width: 200px;
      max-height: 80px;
      object-fit: contain;
      margin: 20px auto;
      display: block;
    }
    .cover-title {
      font-size: 2.4em;
      font-weight: 700;
      color: #f1f5f9;
      margin: 20px 0 10px;
      line-height: 1.2;
    }
    .cover-engagement {
      font-size: 1.2em;
      color: #94a3b8;
      margin-bottom: 40px;
    }
    .cover-meta { width: 100%; max-width: 600px; margin: 0 auto 40px; }
    .cover-table { width: 100%; border-collapse: collapse; }
    .cover-table td { padding: 8px 16px; border-bottom: 1px solid #2d2d5e; text-align: left; }
    .cover-table td.label { color: #7c3aed; font-weight: 600; width: 130px; }
    .cover-classification { margin: 20px 0; }
    .classification-badge {
      background: #dc2626;
      color: white;
      font-weight: 800;
      font-size: 1.1em;
      letter-spacing: 0.2em;
      padding: 8px 28px;
      border-radius: 4px;
      text-transform: uppercase;
    }
    .cover-footer {
      position: absolute;
      bottom: 20px;
      font-size: 0.75em;
      color: #475569;
    }

    /* ===== SECCIONES ===== */
    .section {
      max-width: 1100px;
      margin: 40px auto;
      padding: 30px 40px;
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    .section-title {
      font-size: 1.6em;
      font-weight: 700;
      color: #1a1a3e;
      border-bottom: 3px solid #7c3aed;
      padding-bottom: 10px;
      margin-bottom: 24px;
    }
    .section-note {
      color: #64748b;
      font-style: italic;
      margin-bottom: 20px;
      font-size: 0.9em;
    }
    h3 {
      font-size: 1.1em;
      font-weight: 600;
      color: #374151;
      margin: 16px 0 10px;
    }
    p { margin-bottom: 12px; }

    /* ===== EXECUTIVE GRID ===== */
    .exec-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 20px;
    }
    .exec-card {
      background: #f8f9fa;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 20px;
    }
    .exec-card.full-width {
      grid-column: 1 / -1;
    }
    .gauge-card { text-align: center; }
    .risk-score-label {
      font-size: 1.4em;
      font-weight: 700;
      margin-top: 10px;
    }
    .risk-crítico { color: #dc2626; }
    .risk-alto    { color: #ea580c; }
    .risk-moderado{ color: #d97706; }
    .risk-bajo    { color: #2563eb; }

    /* ===== TABLAS ===== */
    table { width: 100%; border-collapse: collapse; margin-bottom: 12px; }
    th {
      background: #1a1a3e;
      color: white;
      padding: 10px 14px;
      text-align: left;
      font-size: 0.85em;
      letter-spacing: 0.04em;
    }
    td { padding: 9px 14px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    tr:hover td { background: #f0f4ff; }
    .total-row td { border-top: 2px solid #7c3aed; }
    .count-cell { text-align: center; font-weight: 600; }
    .empty-cell { color: #9ca3af; text-align: center; font-style: italic; }
    .sev-table th { background: #2d2d5e; }
    .attack-table th { background: #1e293b; }
    .attack-table td { vertical-align: middle; }
    .fid-cell code {
      display: inline-block;
      background: #f1f5f9;
      color: #7c3aed;
      font-size: 0.78em;
      padding: 2px 6px;
      border-radius: 4px;
      margin: 2px 2px;
      cursor: default;
    }

    /* ===== BADGE ===== */
    .badge {
      display: inline-block;
      color: white;
      font-weight: 700;
      font-size: 0.78em;
      padding: 3px 10px;
      border-radius: 12px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      white-space: nowrap;
    }

    /* ===== HALLAZGOS TÉCNICOS ===== */
    .finding-card {
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      margin-bottom: 24px;
      overflow: hidden;
    }
    .finding-header {
      padding: 12px 18px;
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }
    .finding-id {
      font-family: monospace;
      font-size: 0.9em;
      color: #475569;
      font-weight: 600;
    }
    .finding-title {
      font-size: 1.05em;
      font-weight: 700;
      flex: 1;
    }
    .finding-source {
      font-size: 0.78em;
      color: #6b7280;
      background: #f3f4f6;
      padding: 2px 8px;
      border-radius: 10px;
    }
    .finding-body { padding: 16px 18px; }
    .finding-section { margin-bottom: 14px; }
    .finding-section-title {
      font-size: 0.8em;
      font-weight: 700;
      color: #7c3aed;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 4px;
    }
    .finding-section p { margin: 0; color: #374151; }
    pre.evidence {
      background: #0d0d1a;
      color: #a0f0a0;
      padding: 12px;
      border-radius: 6px;
      font-size: 0.82em;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .cvss-badge {
      display: inline-block;
      background: #e0e7ff;
      color: #3730a3;
      font-size: 0.75em;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 8px;
      margin-left: 8px;
    }
    .refs-list { margin: 0; padding-left: 18px; }
    .refs-list li { font-size: 0.85em; color: #2563eb; }

    /* ===== ROADMAP ===== */
    .phase-card {
      border-left: 4px solid #7c3aed;
      background: #fafafa;
      border-radius: 0 8px 8px 0;
      padding: 16px 20px;
      margin-bottom: 20px;
    }
    .phase-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }
    .phase-title { font-size: 1.05em; font-weight: 700; color: #1a1a3e; }
    .phase-period {
      font-size: 0.8em;
      background: #ede9fe;
      color: #5b21b6;
      padding: 2px 10px;
      border-radius: 10px;
      font-weight: 600;
    }
    .phase-empty { color: #9ca3af; font-style: italic; font-size: 0.9em; }
    .roadmap-item {
      display: flex;
      gap: 10px;
      align-items: flex-start;
      padding: 8px 0;
      border-bottom: 1px solid #e9ecef;
    }
    .roadmap-item:last-child { border-bottom: none; }
    .roadmap-item-text { flex: 1; }
    .roadmap-item-text strong { display: block; font-size: 0.92em; }
    .roadmap-item-text span { font-size: 0.82em; color: #64748b; }

    /* ===== COLORES DE FASE POR SEVERIDAD ===== */
    .phase-card.critical { border-color: #dc2626; }
    .phase-card.high     { border-color: #ea580c; }
    .phase-card.medium   { border-color: #d97706; }
    .phase-card.low-info { border-color: #2563eb; }

    /* ===== TOC ===== */
    .toc-list { list-style: none; padding-left: 0; }
    .toc-list li {
      padding: 6px 0;
      border-bottom: 1px dotted #e2e8f0;
      font-size: 1.05em;
    }
    .toc-list a { color: #7c3aed; text-decoration: none; }
    .toc-list a:hover { text-decoration: underline; }

    /* ===== DISCLAIMER ===== */
    .disclaimer-box {
      background: #fff7ed;
      border: 1px solid #fed7aa;
      border-left: 4px solid #ea580c;
      padding: 16px 20px;
      border-radius: 0 8px 8px 0;
      color: #7c2d12;
      font-size: 0.92em;
      line-height: 1.7;
    }

    /* ===== FOOTER ===== */
    .report-footer {
      text-align: center;
      padding: 20px;
      color: #9ca3af;
      font-size: 0.8em;
      border-top: 1px solid #e2e8f0;
      margin-top: 20px;
    }

    /* ===== PRINT ===== */
    @media print {
      body { background: white; font-size: 12px; }
      .section {
        box-shadow: none;
        margin: 20px 0;
        padding: 20px 30px;
      }
      .cover-page { min-height: auto; padding: 40px; }
      .page-break-after  { page-break-after: always; }
      .page-break-before { page-break-before: always; }
      pre.evidence { color: #1a1a1a; background: #f0f0f0; }
      .cover-page { background: #1a1a3e !important; }
    }
    @media screen {
      .page-break-after  { margin-bottom: 40px; }
      .page-break-before { margin-top: 40px; }
    }
"""

    def _svg_gauge(self, score: int) -> str:
        """Genera un SVG de gauge semicircular para la puntuación de riesgo."""
        # Colores del gauge según la puntuación
        if score <= 25:
            gauge_color = "#2563eb"
        elif score <= 50:
            gauge_color = "#d97706"
        elif score <= 75:
            gauge_color = "#ea580c"
        else:
            gauge_color = "#dc2626"

        # Ángulo del gauge: 0-100 => 0-180 grados
        angle = (score / 100) * 180
        import math
        rad = math.radians(angle)
        cx, cy, r = 100, 100, 70
        x_end = cx - r * math.cos(rad)
        y_end = cy - r * math.sin(rad)
        large_arc = 1 if angle > 180 else 0

        return f"""<svg viewBox="0 0 200 120" xmlns="http://www.w3.org/2000/svg" width="200" height="120">
  <!-- Arco base -->
  <path d="M 30,100 A 70,70 0 0,1 170,100" stroke="#e2e8f0" stroke-width="14" fill="none" stroke-linecap="round"/>
  <!-- Arco de progreso -->
  <path d="M 30,100 A 70,70 0 {large_arc},1 {x_end:.2f},{y_end:.2f}"
        stroke="{gauge_color}" stroke-width="14" fill="none" stroke-linecap="round"/>
  <!-- Valor central -->
  <text x="100" y="95" text-anchor="middle" font-size="28" font-weight="bold"
        fill="{gauge_color}" font-family="Arial, sans-serif">{score}</text>
  <text x="100" y="115" text-anchor="middle" font-size="11" fill="#6b7280"
        font-family="Arial, sans-serif">/ 100</text>
  <!-- Etiquetas mínimo/máximo -->
  <text x="28"  y="116" font-size="9" fill="#9ca3af" font-family="Arial, sans-serif">0</text>
  <text x="166" y="116" font-size="9" fill="#9ca3af" font-family="Arial, sans-serif">100</text>
</svg>"""

    def _svg_bars_by_tool(self) -> str:
        """Genera un gráfico de barras SVG con la distribución de hallazgos por herramienta."""
        by_tool = self._findings_by_tool()
        if not by_tool:
            return "<p class='empty-cell'>Sin datos de herramientas.</p>"

        # Preparar datos
        tools = list(by_tool.keys())
        counts = [len(by_tool[t]) for t in tools]
        max_count = max(counts) if counts else 1

        # Dimensiones
        bar_h = 22
        bar_gap = 8
        label_w = 180
        chart_w = 350
        svg_w = label_w + chart_w + 60
        svg_h = (bar_h + bar_gap) * len(tools) + 20

        rows = ""
        for i, (tool, count) in enumerate(zip(tools, counts)):
            y = i * (bar_h + bar_gap) + 10
            bar_width = int((count / max_count) * chart_w)
            # Truncar etiqueta si es muy larga
            label = tool[:26] + "…" if len(tool) > 27 else tool
            rows += f"""
  <text x="{label_w - 6}" y="{y + bar_h//2 + 5}" text-anchor="end"
        font-size="11" fill="#374151" font-family="Arial, sans-serif">{html_escape(label)}</text>
  <rect x="{label_w}" y="{y}" width="{bar_width}" height="{bar_h}"
        fill="#7c3aed" rx="3" opacity="0.85"/>
  <text x="{label_w + bar_width + 6}" y="{y + bar_h//2 + 5}"
        font-size="11" fill="#374151" font-family="Arial, sans-serif">{count}</text>"""

        return f"""<svg viewBox="0 0 {svg_w} {svg_h}" xmlns="http://www.w3.org/2000/svg"
     width="{svg_w}" height="{svg_h}" style="max-width:100%">{rows}
</svg>"""

    def _build_roadmap_html(self) -> str:
        """Construye el HTML del roadmap de remediación por fases."""
        phase_classes = ["critical", "high", "medium", "low-info"]
        html = ""
        for (phase_name, period, severities), phase_cls in zip(REMEDIATION_PHASES, phase_classes):
            findings = self._findings_for_phase(severities)
            html += f"""<div class="phase-card {phase_cls}">
  <div class="phase-header">
    <span class="phase-title">{html_escape(phase_name)}</span>
    <span class="phase-period">{html_escape(period)}</span>
    <span class="badge" style="background:#6b7280">{len(findings)} hallazgo(s)</span>
  </div>
"""
            if not findings:
                html += "  <p class='phase-empty'>No hay hallazgos en esta fase.</p>\n"
            else:
                for f in findings:
                    color = f.color_html
                    html += f"""  <div class="roadmap-item">
    <span class="badge" style="background:{color}">{f.severity}</span>
    <div class="roadmap-item-text">
      <strong>{html_escape(f.id)} — {html_escape(f.title)}</strong>
      <span>Herramienta: {html_escape(f.source_tool)} · Objetivo: {html_escape(f.target)}</span>
      <span>{html_escape(f.remediation[:200])}</span>
    </div>
  </div>
"""
            html += "</div>\n"
        return html

    def _build_technical_html(self) -> str:
        """Construye el HTML de la sección de hallazgos técnicos."""
        if not self.findings:
            return "<p class='empty-cell'>No se han registrado hallazgos técnicos.</p>"

        html = ""
        for f in self._findings_by_severity():
            color = f.color_html
            refs_html = ""
            if f.references:
                refs_html = "<ul class='refs-list'>" + "".join(
                    f"<li>{html_escape(ref)}</li>" for ref in f.references
                ) + "</ul>"
            else:
                refs_html = "<span style='color:#9ca3af'>Sin referencias</span>"

            evidence_text = f.evidence.strip() if f.evidence.strip() else "(sin evidencia registrada)"

            html += f"""<div class="finding-card">
  <div class="finding-header" style="background:{color}18; border-bottom:2px solid {color}40;">
    <span class="badge" style="background:{color}">{html_escape(f.severity)}</span>
    <span class="finding-id">{html_escape(f.id)}</span>
    <span class="finding-title">{html_escape(f.title)}</span>
    <span class="cvss-badge">CVSS: {f.cvss_estimate} (est.)</span>
    <span class="finding-source">{html_escape(f.source_tool)}</span>
  </div>
  <div class="finding-body">
    <div class="finding-section">
      <div class="finding-section-title">Descripción</div>
      <p>{html_escape(f.description) if f.description else '<em>Sin descripción detallada.</em>'}</p>
    </div>
    <div class="finding-section">
      <div class="finding-section-title">Evidencia</div>
      <pre class="evidence">{html_escape(evidence_text)}</pre>
    </div>
    <div class="finding-section">
      <div class="finding-section-title">Remediación recomendada</div>
      <p>{html_escape(f.remediation)}</p>
    </div>
    <div class="finding-section">
      <div class="finding-section-title">Referencias</div>
      {refs_html}
    </div>
    <div class="finding-section" style="margin-bottom:0">
      <div class="finding-section-title">Objetivo evaluado</div>
      <p>{html_escape(f.target)}</p>
    </div>
  </div>
</div>
"""
        return html

    # ------------------------------------------------------------------
    # Generación de PDF
    # ------------------------------------------------------------------

    def to_pdf(self, filepath: str, executive_only: bool = False) -> None:
        """
        Genera el informe en formato PDF usando fpdf2.
        Diseño profesional con portada, tabla resumen y hallazgos.
        """
        try:
            from fpdf import FPDF
        except ImportError:
            cprint("  [!] fpdf2 no está instalado. Instálalo con: pip install fpdf2", Color.RED)
            cprint("      El PDF no se ha generado.", Color.YELLOW)
            return

        pdf = _PenReportPDF(meta=self.meta)
        pdf.set_auto_page_break(auto=True, margin=15)

        # --- Portada ---
        pdf.add_page()
        pdf.set_fill_color(13, 13, 26)
        pdf.rect(0, 0, 210, 297, "F")

        pdf.set_y(40)
        pdf.set_text_color(168, 85, 247)
        pdf.set_font("Helvetica", "B", 22)
        pdf.cell(0, 10, "VampSecure Labs", ln=True, align="C")

        pdf.set_text_color(124, 58, 237)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, "Security Research Division", ln=True, align="C")

        pdf.ln(20)
        pdf.set_text_color(241, 245, 249)
        pdf.set_font("Helvetica", "B", 18)
        pdf.multi_cell(0, 10, "Informe de Auditoría de Seguridad", align="C")

        pdf.ln(5)
        pdf.set_font("Helvetica", "", 13)
        pdf.set_text_color(148, 163, 184)
        pdf.multi_cell(0, 8, self.meta.engagement, align="C")

        pdf.ln(20)
        # Tabla de metadatos en portada
        fields = [
            ("Cliente",    self.meta.client),
            ("Auditor",    self.meta.auditor),
            ("Período",    f"{self.meta.start_date} — {self.meta.end_date}" if self.meta.start_date else "N/A"),
            ("Generado",   datetime.datetime.now().strftime("%Y-%m-%d")),
        ]
        if self.meta.scope:
            fields.insert(3, ("Alcance", self.meta.scope))

        for label, value in fields:
            pdf.set_x(40)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(124, 58, 237)
            pdf.cell(35, 8, f"{label}:", ln=False)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(226, 232, 240)
            pdf.multi_cell(0, 8, value)

        # Clasificación
        pdf.ln(15)
        pdf.set_fill_color(220, 38, 38)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_x(60)
        pdf.cell(90, 10, "  CONFIDENCIAL  ", ln=True, align="C", fill=True)

        # Footer portada
        pdf.set_y(275)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 5, COPYRIGHT, ln=True, align="C")

        # --- Resumen ejecutivo ---
        pdf.add_page()
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(26, 26, 62)

        counts = self._severity_counts()
        score  = self.risk_score()
        label  = self.risk_label()

        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(26, 26, 62)
        pdf.cell(0, 12, "Resumen Ejecutivo", ln=True)
        pdf.set_draw_color(124, 58, 237)
        pdf.set_line_width(0.8)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

        # Puntuación de riesgo
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(26, 26, 62)
        pdf.cell(0, 8, f"Puntuación de Riesgo Global: {score}/100 — {label}", ln=True)
        pdf.ln(3)

        # Tabla de severidades
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(45, 45, 94)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(80, 8, "Severidad", border=1, fill=True)
        pdf.cell(40, 8, "Hallazgos", border=1, fill=True, ln=True)

        sev_colors = {
            "CRITICAL": (220, 38, 38),
            "HIGH":     (234, 88, 12),
            "MEDIUM":   (217, 119, 6),
            "LOW":      (37, 99, 235),
            "INFO":     (107, 114, 128),
        }
        pdf.set_font("Helvetica", "", 10)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = counts[sev]
            r, g, b = sev_colors[sev]
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(80, 7, f"  {sev}", border=1, fill=True)
            pdf.set_fill_color(248, 249, 250)
            pdf.set_text_color(26, 26, 62)
            pdf.cell(40, 7, str(cnt), border=1, fill=True, align="C", ln=True)

        # Total
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(237, 233, 254)
        pdf.set_text_color(26, 26, 62)
        pdf.cell(80, 7, "  TOTAL", border=1, fill=True)
        pdf.cell(40, 7, str(len(self.findings)), border=1, fill=True, align="C", ln=True)
        pdf.ln(8)

        # Top 5
        if self.findings:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Top 5 Hallazgos más Críticos", ln=True)
            pdf.ln(2)

            # Cabecera tabla
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(45, 45, 94)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(22, 7, "Severidad", border=1, fill=True)
            pdf.cell(25, 7, "ID", border=1, fill=True)
            pdf.cell(100, 7, "Título", border=1, fill=True)
            pdf.cell(33, 7, "Herramienta", border=1, fill=True, ln=True)

            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(26, 26, 62)
            for f in self._top_findings(5):
                r, g, b = sev_colors.get(f.severity, (107, 114, 128))
                pdf.set_fill_color(r, g, b)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(22, 7, f.severity, border=1, fill=True)
                pdf.set_fill_color(248, 249, 250)
                pdf.set_text_color(26, 26, 62)
                pdf.cell(25, 7, f.id[:20], border=1, fill=True)
                pdf.cell(100, 7, f.title[:60], border=1, fill=True)
                pdf.cell(33, 7, f.source_tool[:18], border=1, fill=True, ln=True)

        # --- Hallazgos detallados ---
        if not executive_only:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(26, 26, 62)
            pdf.cell(0, 12, "Hallazgos Técnicos", ln=True)
            pdf.set_draw_color(124, 58, 237)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)

            for f in self._findings_by_severity():
                r, g, b = sev_colors.get(f.severity, (107, 114, 128))

                # Cabecera del hallazgo
                pdf.set_fill_color(r, g, b)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 10)
                header_text = f"[{f.severity}] {f.id} — {f.title[:70]}"
                pdf.cell(0, 9, header_text, ln=True, fill=True)

                # Cuerpo
                pdf.set_fill_color(248, 249, 250)
                pdf.set_text_color(26, 26, 62)
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(35, 6, "Herramienta:", fill=True)
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 6, f.source_tool, ln=True, fill=True)

                if f.description:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(0, 6, "Descripción:", ln=True)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_x(15)
                    pdf.multi_cell(180, 5, f.description[:500])

                if f.remediation:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(0, 6, "Remediación:", ln=True)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_x(15)
                    pdf.multi_cell(180, 5, f.remediation[:400])

                pdf.ln(4)
                pdf.set_draw_color(200, 200, 220)
                pdf.set_line_width(0.3)
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(3)

        # --- Footer en todas las páginas ---
        pdf.output(filepath)
        cprint(f"  [+] PDF generado: {filepath}", Color.GREEN)

    # ------------------------------------------------------------------
    # Generación de Markdown
    # ------------------------------------------------------------------

    def to_markdown(self, filepath: str, executive_only: bool = False) -> None:
        """Genera el informe en formato Markdown."""
        counts = self._severity_counts()
        score  = self.risk_score()
        label  = self.risk_label()
        meta   = self.meta
        now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        lines = []

        # Cabecera
        lines += [
            f"# Informe de Auditoría de Seguridad",
            f"",
            f"> **CONFIDENCIAL** — {COPYRIGHT}",
            f"",
            f"| Campo | Valor |",
            f"|-------|-------|",
            f"| **Cliente** | {meta.client} |",
            f"| **Engagement** | {meta.engagement} |",
            f"| **Auditor** | {meta.auditor} |",
        ]
        if meta.scope:
            lines.append(f"| **Alcance** | {meta.scope} |")
        if meta.start_date or meta.end_date:
            lines.append(f"| **Período** | {meta.start_date} — {meta.end_date} |")
        lines += [
            f"| **Generado** | {now} |",
            f"",
        ]

        # Resumen ejecutivo
        lines += [
            f"---",
            f"",
            f"## 1. Resumen Ejecutivo",
            f"",
            f"**Puntuación de Riesgo Global: {score}/100 — {label}**",
            f"",
            f"### Hallazgos por Severidad",
            f"",
            f"| Severidad | Total |",
            f"|-----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {sev} | {counts[sev]} |")
        lines += [
            f"| **TOTAL** | **{len(self.findings)}** |",
            f"",
        ]

        # Top 5
        lines += [
            f"### Top 5 Hallazgos más Críticos",
            f"",
            f"| Severidad | ID | Título | Herramienta |",
            f"|-----------|-----|--------|-------------|",
        ]
        for f in self._top_findings(5):
            lines.append(f"| {f.severity} | `{f.id}` | {f.title} | {f.source_tool} |")
        lines.append("")

        # Distribución por herramienta
        lines += [
            f"### Distribución por Herramienta VSL",
            f"",
            f"| Herramienta | Hallazgos |",
            f"|-------------|-----------|",
        ]
        for tool, findings_list in self._findings_by_tool().items():
            lines.append(f"| {tool} | {len(findings_list)} |")
        lines.append("")

        # Roadmap
        lines += [
            f"---",
            f"",
            f"## 2. Roadmap de Remediación",
            f"",
        ]
        for phase_name, period, severities in REMEDIATION_PHASES:
            findings = self._findings_for_phase(severities)
            lines += [
                f"### {phase_name} ({period})",
                f"",
            ]
            if not findings:
                lines.append("_No hay hallazgos en esta fase._\n")
            else:
                for f in findings:
                    lines += [
                        f"- **[{f.severity}] `{f.id}` — {f.title}**  ",
                        f"  Herramienta: `{f.source_tool}` | Objetivo: `{f.target}`  ",
                        f"  _{f.remediation[:200]}_",
                        f"",
                    ]

        # Hallazgos técnicos
        if not executive_only:
            lines += [
                f"---",
                f"",
                f"## 3. Hallazgos Técnicos",
                f"",
                f"> CVSS estimado según severidad. No es una puntuación CVSS oficial.",
                f"",
            ]
            for f in self._findings_by_severity():
                lines += [
                    f"---",
                    f"",
                    f"### [{f.severity}] `{f.id}` — {f.title}",
                    f"",
                    f"| Campo | Valor |",
                    f"|-------|-------|",
                    f"| **Severidad** | {f.severity} |",
                    f"| **CVSS estimado** | {f.cvss_estimate} |",
                    f"| **Herramienta** | {f.source_tool} |",
                    f"| **Objetivo** | {f.target} |",
                    f"",
                ]
                if f.description:
                    lines += [f"**Descripción**", f"", f"{f.description}", f""]
                if f.evidence:
                    lines += [f"**Evidencia**", f"", f"```", f"{f.evidence}", f"```", f""]
                lines += [f"**Remediación**", f"", f"{f.remediation}", f""]
                if f.references:
                    lines += [f"**Referencias**", f""]
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")

        # Cobertura ATT&CK (si hay hallazgos FORA)
        attack_md = self._build_attack_md()
        if attack_md:
            lines += ["---", ""] + attack_md

        # Numeración de la sección Disclaimer según contexto
        _md_offset = 1 if attack_md else 0
        if not executive_only:
            sec_num = str(4 + _md_offset)
        else:
            sec_num = str(3 + _md_offset)
        lines += [
            f"---",
            f"",
            f"## {sec_num}. Disclaimer",
            f"",
            f"> {DISCLAIMER}",
            f"",
            f"---",
            f"",
            f"_{COPYRIGHT}_",
        ]

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        cprint(f"  [+] Markdown generado: {filepath}", Color.GREEN)

    # ------------------------------------------------------------------
    # Exportación JSON consolidado
    # ------------------------------------------------------------------

    def to_json(self, filepath: str) -> None:
        """Guarda el JSON consolidado de todos los hallazgos."""
        counts = self._severity_counts()
        data = {
            "penreport_version": VERSION,
            "generated_at": self.meta.generated_at,
            "meta": {
                "client":     self.meta.client,
                "engagement": self.meta.engagement,
                "auditor":    self.meta.auditor,
                "scope":      self.meta.scope,
                "start_date": self.meta.start_date,
                "end_date":   self.meta.end_date,
            },
            "risk": {
                "score": self.risk_score(),
                "label": self.risk_label(),
            },
            "summary": {
                "total":    len(self.findings),
                **counts,
            },
            "tools": [
                {
                    "tool":           tr.tool,
                    "version":        tr.version,
                    "target":         tr.target,
                    "timestamp":      tr.timestamp,
                    "findings_count": tr.findings_count,
                    "filepath":       tr.filepath,
                }
                for tr in self.tool_results
            ],
            "findings": [
                {
                    "id":          f.id,
                    "severity":    f.severity,
                    "title":       f.title,
                    "description": f.description,
                    "evidence":    f.evidence,
                    "remediation": f.remediation,
                    "references":  f.references,
                    "source_tool": f.source_tool,
                    "target":      f.target,
                    "cvss_estimate": f.cvss_estimate,
                }
                for f in self._findings_by_severity()
            ],
        }
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        cprint(f"  [+] JSON consolidado generado: {filepath}", Color.GREEN)


# ---------------------------------------------------------------------------
# Clase auxiliar FPDF con footer personalizado
# ---------------------------------------------------------------------------

class _PenReportPDF:
    """
    Wrapper ligero sobre FPDF que añade footer de copyright en cada página.
    Se instancia solo si fpdf2 está disponible.
    """

    def __init__(self, meta: ReportMeta) -> None:
        try:
            from fpdf import FPDF
        except ImportError:
            raise

        class _InnerPDF(FPDF):
            def __init__(inner_self, meta: ReportMeta) -> None:
                super().__init__(orientation="P", unit="mm", format="A4")
                inner_self._meta = meta

            def header(inner_self) -> None:
                if inner_self.page_no() == 1:
                    return
                inner_self.set_font("Helvetica", "I", 7)
                inner_self.set_text_color(150, 150, 150)
                inner_self.cell(
                    0, 5,
                    f"CONFIDENCIAL — {inner_self._meta.client} — {inner_self._meta.engagement}",
                    ln=True, align="R"
                )
                inner_self.ln(2)

            def footer(inner_self) -> None:
                inner_self.set_y(-15)
                inner_self.set_font("Helvetica", "I", 7)
                inner_self.set_text_color(150, 150, 150)
                inner_self.cell(0, 5, f"Página {inner_self.page_no()}", align="L")
                inner_self.cell(0, 5, COPYRIGHT, align="R")

        self._pdf = _InnerPDF(meta)

    def __getattr__(self, name: str) -> Any:
        """Delega todos los atributos al objeto FPDF interno."""
        return getattr(self._pdf, name)


# ---------------------------------------------------------------------------
# Punto de entrada CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="vamp-penreport",
        description=(
            "VampSecure Labs PenReport — Generador profesional de informes de auditoría.\n"
            "Agrega hallazgos JSON de múltiples herramientas VSL y genera informes\n"
            "HTML, PDF y Markdown para entrega al cliente."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"{COPYRIGHT}\nUso autorizado exclusivamente en entornos con permiso explícito.",
    )

    # Entradas
    parser.add_argument(
        "INPUT",
        nargs="+",
        metavar="INPUT",
        help="Uno o más ficheros JSON de salida VSL",
    )

    # Metadatos del informe
    parser.add_argument(
        "--client",
        required=True,
        metavar="NOMBRE",
        help="Nombre del cliente (obligatorio)",
    )
    parser.add_argument(
        "--engagement",
        default="Auditoría de seguridad",
        metavar="DESC",
        help='Descripción del engagement (ej: "Pentest externo Q3 2026")',
    )
    parser.add_argument(
        "--auditor",
        default="VampSecure Labs",
        metavar="NOMBRE",
        help="Nombre/equipo auditor (default: VampSecure Labs)",
    )
    parser.add_argument(
        "--scope",
        default="",
        metavar="TEXTO",
        help="Alcance del engagement",
    )
    parser.add_argument(
        "--start-date",
        default="",
        metavar="FECHA",
        dest="start_date",
        help="Fecha inicio (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--end-date",
        default="",
        metavar="FECHA",
        dest="end_date",
        help="Fecha fin (YYYY-MM-DD)",
    )

    # Salidas
    parser.add_argument(
        "--report-html",
        default="report.html",
        metavar="FILE",
        dest="report_html",
        help="Genera informe HTML en FILE (default: report.html)",
    )
    parser.add_argument(
        "--report-pdf",
        default=None,
        metavar="FILE",
        dest="report_pdf",
        help="Genera PDF en FILE (requiere fpdf2)",
    )
    parser.add_argument(
        "--report-md",
        default=None,
        metavar="FILE",
        dest="report_md",
        help="Genera Markdown en FILE",
    )
    parser.add_argument(
        "--report-json",
        default=None,
        metavar="FILE",
        dest="report_json",
        help="Guarda JSON consolidado en FILE",
    )
    parser.add_argument(
        "--logo-url",
        default="",
        metavar="URL",
        dest="logo_url",
        help="URL del logo del cliente (opcional, para HTML)",
    )
    parser.add_argument(
        "--logo-file",
        default="",
        metavar="FICHERO",
        dest="logo_file",
        help="Ruta local al logo del cliente; se embebe como base64 en el HTML (PNG/JPG/SVG)",
    )

    # Opciones de comportamiento
    parser.add_argument(
        "--executive-only",
        action="store_true",
        dest="executive_only",
        help="Genera solo el resumen ejecutivo (sin hallazgos técnicos detallados)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Modo detallado",
    )

    return parser


def main() -> int:
    """Función principal del CLI."""
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    # Procesar logo: --logo-file tiene prioridad sobre --logo-url
    logo_b64 = ""
    logo_url  = getattr(args, "logo_url",  "")
    logo_file = getattr(args, "logo_file", "")
    if logo_file:
        import base64
        import mimetypes
        logo_path = Path(logo_file)
        if not logo_path.exists():
            cprint(f"  [!] Fichero de logo no encontrado: {logo_file}", Color.YELLOW)
        else:
            mime, _ = mimetypes.guess_type(str(logo_path))
            if not mime:
                mime = "image/png"
            raw = logo_path.read_bytes()
            b64 = base64.b64encode(raw).decode("ascii")
            logo_b64 = f"data:{mime};base64,{b64}"
            cprint(f"  [i] Logo embebido como base64 ({len(raw)} bytes)", Color.GREY)

    # Construir metadatos
    meta = ReportMeta(
        client=args.client,
        engagement=args.engagement,
        auditor=args.auditor,
        scope=args.scope,
        start_date=args.start_date,
        end_date=args.end_date,
        logo_url=logo_url,
        logo_b64=logo_b64,
    )

    # Crear instancia de PenReport
    report = PenReport(meta=meta, verbose=args.verbose)

    # Cargar ficheros de entrada
    cprint(f"  Cargando {len(args.INPUT)} fichero(s)...", Color.CYAN)
    total_loaded = 0
    for filepath in args.INPUT:
        cprint(f"  → {filepath}", Color.GREY)
        n = report.load_vsl_json(filepath)
        total_loaded += n

    if total_loaded == 0:
        cprint("  [!] No se han cargado hallazgos. Verifica los ficheros de entrada.", Color.RED)
        return 1

    # Deduplicación
    removed = report.deduplicate()
    if removed > 0:
        cprint(f"  [i] {removed} hallazgo(s) duplicado(s) eliminado(s).", Color.YELLOW)

    # Resumen en consola
    report.print_summary()

    # Generar salidas
    cprint("  Generando informes...", Color.CYAN)

    if args.report_html:
        report.to_html(args.report_html, executive_only=args.executive_only)

    if args.report_pdf:
        report.to_pdf(args.report_pdf, executive_only=args.executive_only)

    if args.report_md:
        report.to_markdown(args.report_md, executive_only=args.executive_only)

    if args.report_json:
        report.to_json(args.report_json)

    print()
    cprint("  Proceso completado.", Color.GREEN, bold=True)
    cprint(f"  {COPYRIGHT}", Color.GREY)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
