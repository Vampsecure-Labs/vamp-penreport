# © VampSecure Studios — VampSecure Labs Security Research Division
# -*- coding: utf-8 -*-
"""
cli — Interfaz de línea de comandos de vamp-penreport v2.7.0.
Punto de entrada principal: main().
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

from ._models import (
    VERSION,
    COPYRIGHT,
    BANNER,
    Color,
    SECTOR_PROFILES,
)
from ._core import (
    cprint,
    cprint_sev,
    PenReport,
    ReportMeta,
    calc_cvss31_base_score,
    _parse_vector_cvss31,
    _severidad_cvss,
    _color_severidad,
)
from ._report import export_to_pdf


# ---------------------------------------------------------------------------
# Banner y ayudas visuales
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Muestra el banner de inicio."""
    cprint(BANNER, Color.MAGENTA, bold=True)
    cprint(f"  PenReport v{VERSION} — Generador de Informes de Auditoría", Color.CYAN, bold=True)
    cprint(f"  {COPYRIGHT}", Color.GREY)
    print()


# ---------------------------------------------------------------------------
# Subcomando CVSS
# ---------------------------------------------------------------------------

def cmd_cvss(argv: list) -> int:
    """
    Subcomando 'cvss': calcula el CVSS 3.1 Base Score y muestra resultado detallado.

    Uso:
        vamp-penreport cvss --av N --ac L --pr N --ui N --s U --c H --i H --a H
        vamp-penreport cvss --vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    p = argparse.ArgumentParser(
        prog="vamp-penreport cvss",
        description="Calculadora CVSS 3.1 Base Score — VampSecure Labs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  vamp-penreport cvss --av N --ac L --pr N --ui N --s U --c H --i H --a H\n"
            "  vamp-penreport cvss --vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
            "\n"
            "Valores de métrica:\n"
            "  AV: N (Network) | A (Adjacent) | L (Local) | P (Physical)\n"
            "  AC: L (Low) | H (High)\n"
            "  PR: N (None) | L (Low) | H (High)\n"
            "  UI: N (None) | R (Required)\n"
            "  S:  U (Unchanged) | C (Changed)\n"
            "  C/I/A: N (None) | L (Low) | H (High)\n"
        ),
    )
    p.add_argument(
        "--vector",
        metavar="CVSS_VECTOR",
        help="Vector CVSS 3.1 completo, ej: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    p.add_argument("--av", metavar="METRIC", help="Attack Vector: N|A|L|P")
    p.add_argument("--ac", metavar="METRIC", help="Attack Complexity: L|H")
    p.add_argument("--pr", metavar="METRIC", help="Privileges Required: N|L|H")
    p.add_argument("--ui", metavar="METRIC", help="User Interaction: N|R")
    p.add_argument("--s",  metavar="METRIC", help="Scope: U|C")
    p.add_argument("--c",  metavar="METRIC", help="Confidentiality: N|L|H")
    p.add_argument("--i",  metavar="METRIC", help="Integrity: N|L|H")
    p.add_argument("--a",  metavar="METRIC", help="Availability: N|L|H")

    args = p.parse_args(argv)

    if args.vector:
        try:
            metricas = _parse_vector_cvss31(args.vector)
        except ValueError as exc:
            cprint(f"\n  [!] {exc}", Color.RED)
            return 1
    else:
        campos = ("av", "ac", "pr", "ui", "s", "c", "i", "a")
        faltantes = [f"--{f}" for f in campos if getattr(args, f) is None]
        if faltantes:
            cprint(
                f"\n  [!] Debes proporcionar --vector o todas las métricas individuales.\n"
                f"      Faltan: {', '.join(faltantes)}",
                Color.RED,
            )
            p.print_help()
            return 1
        metricas = {f: getattr(args, f) for f in campos}

    try:
        score = calc_cvss31_base_score(**metricas)
    except ValueError as exc:
        cprint(f"\n  [!] {exc}", Color.RED)
        return 1

    sev     = _severidad_cvss(score)
    col_sev = _color_severidad(sev)

    av, ac, pr, ui, s_, c_, i_, a_ = (
        metricas["av"].upper(), metricas["ac"].upper(), metricas["pr"].upper(),
        metricas["ui"].upper(), metricas["s"].upper(), metricas["c"].upper(),
        metricas["i"].upper(), metricas["a"].upper(),
    )
    vector_str = f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s_}/C:{c_}/I:{i_}/A:{a_}"

    _AV_NOMBRES  = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
    _AC_NOMBRES  = {"L": "Low", "H": "High"}
    _PR_NOMBRES  = {"N": "None", "L": "Low", "H": "High"}
    _UI_NOMBRES  = {"N": "None", "R": "Required"}
    _S_NOMBRES   = {"U": "Unchanged", "C": "Changed"}
    _CIA_NOMBRES = {"N": "None", "L": "Low", "H": "High"}

    SEP  = "  " + "─" * 62
    SEP2 = "  " + "═" * 62

    cprint(f"\n{SEP2}", Color.CYAN)
    cprint(f"  {'CVSS 3.1 Base Score':^62}", Color.CYAN, bold=True)
    cprint(f"{SEP2}", Color.CYAN)

    score_label = f"{score:.1f}"
    cprint(f"\n  {'Score:':<20}", Color.WHITE, bold=True)
    print(f"  {Color.BOLD}{col_sev}{score_label:>8}  /  10.0{Color.RESET}")
    cprint(f"  {'Severidad:':<20}{sev}", col_sev, bold=True)
    cprint(f"  {'Vector:':<20}{vector_str}", Color.GREY)

    cprint(f"\n{SEP}", Color.CYAN)
    cprint(f"  {'Métrica':<32} {'Valor':<12} {'Código'}", Color.WHITE, bold=True)
    cprint(SEP, Color.CYAN)

    filas = [
        ("Attack Vector (AV)",       _AV_NOMBRES.get(av, av),   av),
        ("Attack Complexity (AC)",    _AC_NOMBRES.get(ac, ac),   ac),
        ("Privileges Required (PR)",  _PR_NOMBRES.get(pr, pr),   pr),
        ("User Interaction (UI)",     _UI_NOMBRES.get(ui, ui),   ui),
        ("Scope (S)",                 _S_NOMBRES.get(s_, s_),    s_),
        ("Confidentiality (C)",       _CIA_NOMBRES.get(c_, c_),  c_),
        ("Integrity (I)",             _CIA_NOMBRES.get(i_, i_),  i_),
        ("Availability (A)",          _CIA_NOMBRES.get(a_, a_),  a_),
    ]
    for nombre, valor, codigo in filas:
        cprint(f"  {nombre:<32} {valor:<12} {codigo}", Color.WHITE)

    cprint(SEP, Color.CYAN)
    cprint("\n  Escala CVSS 3.1:", Color.GREY)
    escala = [
        ("None",     "0.0",      Color.GREY),
        ("Low",      "0.1-3.9",  Color.BLUE),
        ("Medium",   "4.0-6.9",  Color.YELLOW),
        ("High",     "7.0-8.9",  Color.ORANGE),
        ("Critical", "9.0-10.0", Color.RED),
    ]
    linea_escala = "  "
    for etiq, rango, col in escala:
        linea_escala += (
            f"{col}{Color.BOLD if etiq == sev else ''}"
            f"{etiq} ({rango}){Color.RESET}  "
        )
    print(linea_escala)
    cprint(f"\n{SEP2}\n", Color.CYAN)

    return 0


# ---------------------------------------------------------------------------
# Parser de argumentos
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

    parser.add_argument(
        "INPUT",
        nargs="+",
        metavar="INPUT",
        help="Uno o más ficheros JSON de salida VSL",
    )
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

    sectores = list(SECTOR_PROFILES.keys())
    parser.add_argument(
        "--sector",
        default="generic",
        choices=sectores,
        metavar="SECTOR",
        help=(
            f"Sector del cliente para ajustar el lenguaje ejecutivo, el marco "
            f"regulatorio y la priorización del roadmap. "
            f"Valores: {', '.join(sectores)} (default: generic)"
        ),
    )

    jira_grp = parser.add_argument_group("Exportación Jira (hallazgos HIGH/CRITICAL)")
    jira_grp.add_argument(
        "--export-jira",
        default="",
        metavar="URL",
        dest="export_jira",
        help="URL base de la instancia Jira. Activa la exportación de hallazgos HIGH/CRITICAL.",
    )
    jira_grp.add_argument(
        "--jira-project",
        default="SEC",
        metavar="KEY",
        dest="jira_project",
        help="Clave del proyecto Jira donde crear los issues (default: SEC)",
    )
    jira_grp.add_argument(
        "--jira-user",
        default="",
        metavar="EMAIL",
        dest="jira_user",
        help="Email del usuario Jira con permisos de creación de issues",
    )
    jira_grp.add_argument(
        "--jira-token",
        default="",
        metavar="TOKEN",
        dest="jira_token",
        help="Token API de Jira (generado en id.atlassian.com → API tokens)",
    )

    dojo_grp = parser.add_argument_group("Exportación DefectDojo")
    dojo_grp.add_argument(
        "--export-dojo",
        default="",
        metavar="URL",
        dest="export_dojo",
        help="URL base de la instancia DefectDojo. Activa la exportación de todos los hallazgos.",
    )
    dojo_grp.add_argument(
        "--dojo-token",
        default="",
        metavar="TOKEN",
        dest="dojo_token",
        help="Token API de DefectDojo (Profile → API v2 Key)",
    )
    dojo_grp.add_argument(
        "--dojo-engagement",
        default=0,
        type=int,
        metavar="ID",
        dest="dojo_engagement",
        help="ID del engagement en DefectDojo donde registrar los hallazgos",
    )

    parser.add_argument(
        "--pdf",
        default=None,
        metavar="FICHERO.pdf",
        dest="pdf",
        help=(
            "Genera un PDF a partir de una plantilla HTML personalizable "
            "(requiere weasyprint>=60.0). Distinto de --report-pdf: usa "
            "plantillas con variables {{cliente}}, {{fecha}}, {{hallazgos_table}}, "
            "{{num_critical}}, {{num_high}}, {{num_total}}."
        ),
    )
    parser.add_argument(
        "--pdf-template",
        default=None,
        metavar="PLANTILLA.html",
        dest="pdf_template",
        help=(
            "Plantilla HTML a usar con --pdf. Si se omite se aplica la "
            "plantilla corporativa VSL por defecto. "
            "Consulta template.example.html para la documentación de variables."
        ),
    )
    parser.add_argument(
        "--gpg-key",
        default="",
        metavar="KEY_ID",
        dest="gpg_key",
        help=(
            "ID de clave GPG para firmar el informe HTML. "
            "Genera report.html.asc contiguo al informe. "
            "Si gpg no está instalado emite warning y continúa. "
            "(Opcional; sin este flag no se firma)"
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Función principal
# ---------------------------------------------------------------------------

def main() -> int:
    """Función principal del CLI."""
    if len(sys.argv) > 1 and sys.argv[1] == "cvss":
        print_banner()
        return cmd_cvss(sys.argv[2:])

    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    logo_b64  = ""
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
            raw    = logo_path.read_bytes()
            b64    = base64.b64encode(raw).decode("ascii")
            logo_b64 = f"data:{mime};base64,{b64}"
            cprint(f"  [i] Logo embebido como base64 ({len(raw)} bytes)", Color.GREY)

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

    sector  = getattr(args, "sector",  "generic")
    gpg_key = getattr(args, "gpg_key", "")
    report  = PenReport(meta=meta, verbose=args.verbose, sector=sector, gpg_key=gpg_key)

    cprint(f"  Cargando {len(args.INPUT)} fichero(s)...", Color.CYAN)
    total_loaded = 0
    for filepath in args.INPUT:
        cprint(f"  → {filepath}", Color.GREY)
        n = report.load_vsl_json(filepath)
        total_loaded += n

    if total_loaded == 0:
        cprint(
            "  [!] No se han cargado hallazgos. Verifica los ficheros de entrada.",
            Color.RED,
        )
        return 1

    removed = report.deduplicate()
    if removed > 0:
        cprint(f"  [i] {removed} hallazgo(s) duplicado(s) eliminado(s).", Color.YELLOW)

    report.print_summary()

    cprint("  Generando informes...", Color.CYAN)

    if args.report_html:
        report.to_html(args.report_html, executive_only=args.executive_only)

    if args.report_pdf:
        report.to_pdf(args.report_pdf, executive_only=args.executive_only)

    if args.report_md:
        report.to_markdown(args.report_md, executive_only=args.executive_only)

    if args.report_json:
        report.to_json(args.report_json)

    pdf_output   = getattr(args, "pdf", None)
    pdf_template = getattr(args, "pdf_template", None)
    if pdf_output:
        cprint("\n  Generando PDF con plantilla personalizable...", Color.CYAN)
        report_data_pdf = {
            "client": report.meta.client,
            "date":   datetime.datetime.now().strftime("%Y-%m-%d"),
            "findings": [
                {
                    "severity":    f.severity,
                    "id":          f.id,
                    "title":       f.title,
                    "description": f.description,
                }
                for f in report.findings
            ],
        }
        try:
            export_to_pdf(report_data_pdf, pdf_template, pdf_output)
            cprint(f"  PDF generado: {pdf_output}", Color.GREEN)
        except RuntimeError as exc:
            cprint(f"  [!] PDF no generado: {exc}", Color.RED)

    export_jira_url = getattr(args, "export_jira", "")
    if export_jira_url:
        jira_user  = getattr(args, "jira_user", "")
        jira_token = getattr(args, "jira_token", "")
        jira_proj  = getattr(args, "jira_project", "SEC")
        if not jira_user or not jira_token:
            cprint("  [!] --export-jira requiere --jira-user y --jira-token.", Color.RED)
        else:
            cprint("\n  Exportando hallazgos a Jira...", Color.CYAN)
            issue_urls = report.export_to_jira(
                base_url=export_jira_url,
                project_key=jira_proj,
                jira_user=jira_user,
                jira_token=jira_token,
                verbose=args.verbose,
            )
            if issue_urls:
                cprint("  Issues Jira creados:", Color.GREEN)
                for url in issue_urls:
                    cprint(f"    · {url}", Color.CYAN)

    export_dojo_url = getattr(args, "export_dojo", "")
    if export_dojo_url:
        dojo_token      = getattr(args, "dojo_token", "")
        dojo_engagement = getattr(args, "dojo_engagement", 0)
        if not dojo_token or not dojo_engagement:
            cprint(
                "  [!] --export-dojo requiere --dojo-token y --dojo-engagement.",
                Color.RED,
            )
        else:
            cprint("\n  Exportando hallazgos a DefectDojo...", Color.CYAN)
            report.export_to_defectdojo(
                base_url=export_dojo_url,
                api_token=dojo_token,
                engagement_id=dojo_engagement,
                verbose=args.verbose,
            )

    print()
    cprint("  Proceso completado.", Color.GREEN, bold=True)
    cprint(f"  {COPYRIGHT}", Color.GREY)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
