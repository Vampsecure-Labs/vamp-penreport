# © VampSecure Studios — VampSecure Labs Security Research Division
# -*- coding: utf-8 -*-
"""
_report — Funciones de exportación independientes de vamp-penreport.
Exportación PDF via weasyprint con plantillas HTML personalizables.
"""
from __future__ import annotations

import json
from html import escape as html_escape
from typing import Dict, List, Optional

from ._models import VERSION, TOOL_NAME


def _get_default_pdf_template() -> str:
    """
    Devuelve la plantilla HTML corporativa por defecto para la exportación PDF.

    Variables soportadas:
      {{cliente}}         — Nombre del cliente
      {{fecha}}           — Fecha del informe (YYYY-MM-DD)
      {{hallazgos_table}} — Tabla HTML con los hallazgos (filas <tr>)
      {{num_critical}}    — Número de hallazgos CRITICAL
      {{num_high}}        — Número de hallazgos HIGH
      {{num_total}}       — Número total de hallazgos
    """
    return """\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Informe de Auditoría — {{cliente}}</title>
  <style>
    /* Plantilla corporativa VampSecure Labs — vamp-penreport """  + VERSION + """ */
    @page {
      margin: 2cm 1.5cm;
      @bottom-center {
        content: "© VampSecure Studios — VampSecure Labs Security Research Division · Página " counter(page);
        font-size: 8pt;
        color: #666;
      }
    }
    body {
      font-family: "DejaVu Sans", Arial, sans-serif;
      font-size: 10pt;
      color: #1a1a2e;
      background: #ffffff;
      margin: 0;
      padding: 0;
    }
    .portada {
      text-align: center;
      padding: 4cm 2cm 3cm;
      border-bottom: 3px solid #c00;
      margin-bottom: 2cm;
    }
    .portada h1 {
      font-size: 22pt;
      color: #c00;
      margin: 0 0 0.5cm;
    }
    .portada .subtitulo {
      font-size: 13pt;
      color: #333;
      margin: 0 0 1cm;
    }
    .portada .meta {
      font-size: 10pt;
      color: #555;
      line-height: 1.8;
    }
    .seccion { margin: 1cm 0 0.5cm; }
    .seccion h2 {
      font-size: 14pt;
      color: #c00;
      border-bottom: 1px solid #c00;
      padding-bottom: 2pt;
      margin-bottom: 0.4cm;
    }
    .resumen-grid {
      display: flex;
      gap: 1cm;
      margin: 0.5cm 0 1cm;
    }
    .resumen-caja {
      flex: 1;
      text-align: center;
      padding: 0.4cm;
      border-radius: 4pt;
      border: 1px solid #ddd;
    }
    .resumen-caja.critical { border-color: #c00; background: #fff5f5; }
    .resumen-caja.high     { border-color: #e65; background: #fff8f5; }
    .resumen-caja.total    { border-color: #336; background: #f5f5ff; }
    .resumen-caja .num {
      font-size: 24pt;
      font-weight: bold;
      display: block;
    }
    .resumen-caja .etiqueta { font-size: 9pt; color: #555; }
    table.hallazgos {
      width: 100%;
      border-collapse: collapse;
      font-size: 9pt;
      margin-top: 0.3cm;
    }
    table.hallazgos th {
      background: #1a1a2e;
      color: #fff;
      padding: 5pt 8pt;
      text-align: left;
    }
    table.hallazgos td {
      padding: 5pt 8pt;
      border-bottom: 1px solid #e0e0e0;
      vertical-align: top;
    }
    table.hallazgos tr:nth-child(even) td { background: #f9f9f9; }
    .sev-CRITICAL { color: #c00; font-weight: bold; }
    .sev-HIGH     { color: #e65; font-weight: bold; }
    .sev-MEDIUM   { color: #c80; font-weight: bold; }
    .sev-LOW      { color: #070; }
    .sev-INFO     { color: #007; }
    .disclaimer {
      margin-top: 1cm;
      font-size: 8pt;
      color: #888;
      border-top: 1px solid #ddd;
      padding-top: 0.3cm;
    }
  </style>
</head>
<body>
  <div class="portada">
    <h1>INFORME DE AUDITORÍA DE SEGURIDAD</h1>
    <div class="subtitulo">Confidencial — Solo para el cliente indicado</div>
    <div class="meta">
      <strong>Cliente:</strong> {{cliente}}<br>
      <strong>Fecha:</strong> {{fecha}}<br>
      <strong>Elaborado por:</strong> VampSecure Labs Security Research Division
    </div>
  </div>

  <div class="seccion">
    <h2>Resumen Ejecutivo</h2>
    <div class="resumen-grid">
      <div class="resumen-caja critical">
        <span class="num">{{num_critical}}</span>
        <span class="etiqueta">CRÍTICO</span>
      </div>
      <div class="resumen-caja high">
        <span class="num">{{num_high}}</span>
        <span class="etiqueta">ALTO</span>
      </div>
      <div class="resumen-caja total">
        <span class="num">{{num_total}}</span>
        <span class="etiqueta">TOTAL</span>
      </div>
    </div>
  </div>

  <div class="seccion">
    <h2>Hallazgos de Seguridad</h2>
    <table class="hallazgos">
      <thead>
        <tr>
          <th>ID</th>
          <th>Severidad</th>
          <th>Título</th>
          <th>Descripción</th>
        </tr>
      </thead>
      <tbody>
        {{hallazgos_table}}
      </tbody>
    </table>
  </div>

  <div class="disclaimer">
    © VampSecure Studios — VampSecure Labs Security Research Division.
    Este informe es CONFIDENCIAL y está destinado exclusivamente al cliente indicado.
    Su distribución o reproducción sin autorización expresa está prohibida.
  </div>
</body>
</html>
"""


def export_to_pdf(
    report_data: Dict,
    template_file: Optional[str],
    output_path: str,
) -> None:
    """
    Exporta el informe a PDF usando una plantilla HTML personalizable.

    Parámetros
    ----------
    report_data   : Diccionario con los datos del informe. Claves esperadas:
                      - "client"   (str)  — nombre del cliente
                      - "date"     (str)  — fecha del informe (YYYY-MM-DD)
                      - "findings" (list) — lista de dicts con campos:
                          severity, id, title, description
    template_file : Ruta a un fichero HTML de plantilla personalizado, o None
                    para usar la plantilla corporativa por defecto de VSL.
    output_path   : Ruta del fichero PDF de salida.

    Variables de plantilla soportadas:
      {{cliente}}         — Nombre del cliente
      {{fecha}}           — Fecha del informe
      {{hallazgos_table}} — Tabla HTML con los hallazgos
      {{num_critical}}    — Número de hallazgos CRITICAL
      {{num_high}}        — Número de hallazgos HIGH
      {{num_total}}       — Número total de hallazgos

    Lanza
    -----
    RuntimeError si weasyprint no está instalado o la generación falla.
    """
    if template_file:
        try:
            with open(template_file, "r", encoding="utf-8") as fh:
                plantilla = fh.read()
        except (OSError, IOError) as exc:
            raise RuntimeError(
                f"No se pudo leer la plantilla '{template_file}': {exc}"
            ) from exc
    else:
        plantilla = _get_default_pdf_template()

    findings = report_data.get("findings", [])

    filas_html: List[str] = []
    for h in findings:
        sev    = str(h.get("severity", "INFO"))
        hid    = html_escape(str(h.get("id", "")))
        titulo = html_escape(str(h.get("title", "")))
        desc   = html_escape(str(h.get("description", ""))[:400])
        filas_html.append(
            f'<tr><td>{hid}</td>'
            f'<td class="sev-{sev}">{sev}</td>'
            f'<td>{titulo}</td>'
            f'<td>{desc}</td></tr>'
        )
    hallazgos_table = "\n        ".join(filas_html) if filas_html else (
        '<tr><td colspan="4">Sin hallazgos</td></tr>'
    )

    num_critical = sum(1 for h in findings if h.get("severity") == "CRITICAL")
    num_high     = sum(1 for h in findings if h.get("severity") == "HIGH")
    num_total    = len(findings)

    html_content = (
        plantilla
        .replace("{{cliente}}",         html_escape(str(report_data.get("client", ""))))
        .replace("{{fecha}}",           html_escape(str(report_data.get("date", ""))))
        .replace("{{hallazgos_table}}", hallazgos_table)
        .replace("{{num_critical}}",    str(num_critical))
        .replace("{{num_high}}",        str(num_high))
        .replace("{{num_total}}",       str(num_total))
    )

    try:
        from weasyprint import HTML as WeasyHTML  # importación tardía — dependencia opcional
    except ImportError as exc:
        raise RuntimeError(
            "weasyprint no está instalado. Instálalo con: pip install 'weasyprint>=60.0'"
        ) from exc

    try:
        WeasyHTML(string=html_content).write_pdf(output_path)
    except Exception as exc:
        raise RuntimeError(f"Error generando PDF con weasyprint: {exc}") from exc
