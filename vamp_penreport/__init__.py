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
    _PenReportPDF,  # noqa: F401
    calc_cvss31_base_score,
    _parse_vector_cvss31,  # noqa: F401
    _severidad_cvss,  # noqa: F401
    _color_severidad,  # noqa: F401
    _roundup,  # noqa: F401
    _CVSS31_AV,  # noqa: F401
    _CVSS31_AC,  # noqa: F401
    _CVSS31_PR,  # noqa: F401
    _CVSS31_UI,  # noqa: F401
    _CVSS31_CIA,  # noqa: F401
)

# --- Exportación PDF con plantillas ---
from ._report import (
    _get_default_pdf_template,  # noqa: F401
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
