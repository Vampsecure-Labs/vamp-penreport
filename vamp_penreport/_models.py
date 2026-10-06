# © VampSecure Studios — VampSecure Labs Security Research Division
# -*- coding: utf-8 -*-
"""
_models — Constantes, enumeraciones y dataclasses de vamp-penreport.
Sin I/O: este módulo no imprime ni escribe ficheros.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Versión y metadatos del paquete
# ---------------------------------------------------------------------------

VERSION   = "2.7.0"
TOOL_NAME = "vamp-penreport"
COPYRIGHT = "© VampSecure Studios — VampSecure Labs Security Research Division"
DISCLAIMER = (
    "Este informe es CONFIDENCIAL y está destinado exclusivamente al cliente indicado. "
    "Contiene información sensible sobre vulnerabilidades de seguridad. "
    "Su distribución o reproducción sin autorización expresa está prohibida. "
    "VampSecure Labs no se hace responsable del uso indebido de la información contenida "
    "en este documento."
)

# ---------------------------------------------------------------------------
# Colores ANSI para consola
# ---------------------------------------------------------------------------

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
SEV_COLOR_HTML: Dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

# Pesos para el cálculo de puntuación de riesgo
SEV_WEIGHT: Dict[str, int] = {
    "CRITICAL": 25,
    "HIGH":     10,
    "MEDIUM":    5,
    "LOW":       1,
    "INFO":      0,
}

# CVSS estimado por severidad (valor representativo, es estimación)
SEV_CVSS: Dict[str, str] = {
    "CRITICAL": "9.0–10.0",
    "HIGH":     "7.0–8.9",
    "MEDIUM":   "4.0–6.9",
    "LOW":      "1.0–3.9",
    "INFO":     "0.0",
}

# Fases de remediación
REMEDIATION_PHASES: List[Tuple[str, str, List[str]]] = [
    ("Fase 1 — Inmediata",       "0–7 días",    ["CRITICAL"]),
    ("Fase 2 — Urgente",         "7–30 días",   ["HIGH"]),
    ("Fase 3 — Planificada",     "30–90 días",  ["MEDIUM"]),
    ("Fase 4 — Mejora continua", "+90 días",    ["LOW", "INFO"]),
]

# Perfiles de sector para ajuste de lenguaje, marco regulatorio y priorización
SECTOR_PROFILES: Dict[str, Dict] = {
    "finanzas": {
        "nombre": "Sector Financiero",
        "resumen_ejecutivo": (
            "En el sector financiero, las vulnerabilidades identificadas deben evaluarse "
            "bajo el prisma del cumplimiento PCI-DSS y el riesgo financiero directo. "
            "Los hallazgos relativos a secretos expuestos, acceso no autorizado y cifrado "
            "deficiente tienen impacto inmediato sobre la integridad de los datos de pago "
            "y pueden derivar en sanciones regulatorias, pérdida de certificación PCI-DSS "
            "y daño reputacional severo."
        ),
        "marco_regulatorio": (
            "Marco normativo aplicable: <strong>PCI-DSS v4.0</strong> (protección de datos "
            "de tarjetas), <strong>ISO/IEC 27001</strong> (gestión de seguridad de la "
            "información), <strong>DORA</strong> (resiliencia digital para entidades "
            "financieras en la UE) y <strong>RGPD</strong>. Los hallazgos CRITICAL o HIGH "
            "que afecten a sistemas de pago, datos de tarjetas o credenciales de acceso "
            "pueden constituir una violación directa de los requisitos PCI-DSS 6.x y 8.x. "
            "La resolución de estos hallazgos debe priorizarse antes de la próxima evaluación "
            "QSA o ASV."
        ),
        "prioridad_extra_critica": ["secreto", "token", "clave", "api key", "acceso",
                                    "credencial", "auth", "contraseña", "password"],
    },
    "sanidad": {
        "nombre": "Sector Sanitario",
        "resumen_ejecutivo": (
            "En el sector sanitario, la protección de datos de salud y la disponibilidad "
            "de los sistemas son requisitos críticos. Los hallazgos identificados se evalúan "
            "bajo los principios del <strong>RGPD Art. 9</strong> (datos de salud como "
            "categoría especial) y la normativa HIPAA para entidades con actividad en "
            "EE.UU. Cualquier exposición de información de pacientes o interrupción de "
            "sistemas clínicos puede tener consecuencias directas sobre la seguridad de "
            "las personas y acarrear la obligación de notificación a la AEPD en 72 horas."
        ),
        "marco_regulatorio": (
            "Marco normativo aplicable: <strong>RGPD Art. 9</strong> (datos de salud como "
            "categoría especial de datos personales), <strong>HIPAA Security Rule</strong> "
            "(para entidades con actividad en EE.UU.), <strong>LOPD-GDD</strong> (Ley "
            "Orgánica 3/2018 en España), <strong>ENS</strong> (Esquema Nacional de "
            "Seguridad para entidades públicas sanitarias) y <strong>Directiva NIS2</strong> "
            "para infraestructuras críticas. Los hallazgos que expongan datos de pacientes "
            "(PII/PHI) requieren notificación a la <abbr title='Agencia Española de "
            "Protección de Datos'>AEPD</abbr> en un plazo máximo de 72 horas desde su "
            "detección."
        ),
        "prioridad_extra_critica": ["pii", "dato personal", "paciente", "historia clínica",
                                    "medical", "salud", "health"],
    },
    "admin-publica": {
        "nombre": "Administración Pública",
        "resumen_ejecutivo": (
            "En el ámbito de la administración pública, la auditoría se enmarca en los "
            "requisitos del <strong>Esquema Nacional de Seguridad (ENS)</strong> y la "
            "LOPD-GDD. Las vulnerabilidades críticas detectadas pueden comprometer "
            "servicios esenciales para los ciudadanos y exponer datos de carácter personal "
            "bajo custodia pública, con las correspondientes responsabilidades "
            "administrativas y penales."
        ),
        "marco_regulatorio": (
            "Marco normativo aplicable: <strong>Real Decreto 311/2022</strong> (Esquema "
            "Nacional de Seguridad — ENS), <strong>Ley Orgánica 3/2018</strong> (LOPD-GDD), "
            "<strong>RGPD</strong>, <strong>Directiva NIS2</strong> (en fase de transposición) "
            "y las guías técnicas <strong>CCN-STIC</strong> del Centro Criptológico Nacional. "
            "Las entidades con nivel ENS ALTO deben subsanar los hallazgos CRITICAL en un "
            "máximo de 30 días y notificar al <strong>CCN-CERT</strong> los incidentes de "
            "nivel 4 o superior. Los sistemas con nivel ENS MEDIO deben aplicar las medidas "
            "del Anexo II del RD 311/2022."
        ),
        "prioridad_extra_critica": ["ens", "administracion", "ciudadano", "gobierno",
                                    "lopd", "agencia"],
    },
    "ecommerce": {
        "nombre": "Comercio Electrónico",
        "resumen_ejecutivo": (
            "En plataformas de comercio electrónico, los hallazgos se evalúan bajo los "
            "estándares <strong>PCI-DSS</strong> (transacciones de pago), disponibilidad "
            "del servicio y protección de datos de clientes. Las vulnerabilidades en "
            "formularios de pago, inyecciones SQL y exposición de datos de tarjetas tienen "
            "impacto directo en la confianza del consumidor, las tasas de conversión y "
            "el cumplimiento regulatorio de pagos."
        ),
        "marco_regulatorio": (
            "Marco normativo aplicable: <strong>PCI-DSS v4.0</strong> (obligatorio para "
            "todo procesador de tarjetas), <strong>RGPD</strong> (datos de compradores), "
            "<strong>Directiva PSD2</strong> (servicios de pago en línea y autenticación "
            "reforzada SCA) y normativa de defensa del consumidor. Los hallazgos que "
            "afecten a formularios de pago, almacenamiento de datos de tarjetas o "
            "mecanismos de autenticación de compradores tienen carácter prioritario y "
            "pueden acarrear la revocación del servicio de procesamiento de pagos por "
            "parte de la entidad adquirente."
        ),
        "prioridad_extra_critica": ["pago", "tarjeta", "carrito", "checkout",
                                    "sqli", "inyección", "xss"],
    },
    "generic": {
        "nombre": "Sector Genérico",
        "resumen_ejecutivo": (
            "El presente informe recoge los hallazgos de seguridad identificados durante "
            "la auditoría. Se recomienda abordar los hallazgos CRITICAL y HIGH de forma "
            "inmediata (0–30 días), los MEDIUM en un plazo planificado (30–90 días) y "
            "los LOW como parte del programa de mejora continua."
        ),
        "marco_regulatorio": (
            "Marco normativo de referencia general: <strong>ISO/IEC 27001</strong> "
            "(gestión de seguridad de la información), <strong>RGPD</strong> (si se "
            "tratan datos personales de ciudadanos europeos), <strong>OWASP Top 10</strong> "
            "(para aplicaciones web) y las guías del <strong>CCN-CERT</strong>. Se "
            "recomienda revisar la aplicabilidad de normativas sectoriales específicas "
            "según la actividad y la jurisdicción de la organización auditada."
        ),
        "prioridad_extra_critica": [],
    },
}

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
ATTACK_TACTICS_ORDER: List[str] = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command & Control",
    "Exfiltration",
]

# Mapeo de alias de severidad a canónico
SEV_ALIASES: Dict[str, str] = {
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
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-penreport v2.7.0 · Penetration Testing Report Generator
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
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
    generated_at: str = field(
        default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds")
    )


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
# Función de normalización de severidad (pura, sin I/O)
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
