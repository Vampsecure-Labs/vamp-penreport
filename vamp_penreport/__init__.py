# © VampSecure Studios — VampSecure Labs Security Research Division
# -*- coding: utf-8 -*-
"""
vamp_penreport — Generador profesional de informes de auditoría de seguridad.

Paquete importable: expone toda la API pública en el namespace raíz.
"""
from __future__ import annotations

# --- Modelos, constantes y dataclasses ---
from ._models import (
    VERSION,
    TOOL_NAME,
    COPYRIGHT,
    DISCLAIMER,
    Color,
    SEV_COLOR_HTML,
    SEV_WEIGHT,
    SEV_CVSS,
    REMEDIATION_PHASES,
    SECTOR_PROFILES,
    FORA_ATTACK_MAP,
    ATTACK_TACTICS_ORDER,
    SEV_ALIASES,
    BANNER,
    Finding,
    ReportMeta,
    ToolResult,
    normalize_severity,
)

# --- Lógica principal ---
from ._core import (
    cprint,
    cprint_sev,
    verbose_log,
    extract_findings_from_json,
    normalize_finding,
    PenReport,
    _PenReportPDF,
    calc_cvss31_base_score,
    _parse_vector_cvss31,
    _severidad_cvss,
    _color_severidad,
    _roundup,
    _CVSS31_AV,
    _CVSS31_AC,
    _CVSS31_PR,
    _CVSS31_UI,
    _CVSS31_CIA,
)

# --- Exportación PDF con plantillas ---
from ._report import (
    _get_default_pdf_template,
    export_to_pdf,
)

# --- CLI ---
from .cli import main

__all__ = [
    # Versión
    "VERSION",
    "TOOL_NAME",
    "COPYRIGHT",
    "DISCLAIMER",
    # Constantes
    "Color",
    "SEV_COLOR_HTML",
    "SEV_WEIGHT",
    "SEV_CVSS",
    "REMEDIATION_PHASES",
    "SECTOR_PROFILES",
    "FORA_ATTACK_MAP",
    "ATTACK_TACTICS_ORDER",
    "SEV_ALIASES",
    "BANNER",
    # Dataclasses
    "Finding",
    "ReportMeta",
    "ToolResult",
    # Funciones públicas
    "normalize_severity",
    "normalize_finding",
    "extract_findings_from_json",
    "cprint",
    "cprint_sev",
    "verbose_log",
    # Clase principal
    "PenReport",
    # Exportación PDF
    "export_to_pdf",
    # CVSS
    "calc_cvss31_base_score",
    # CLI
    "main",
]
