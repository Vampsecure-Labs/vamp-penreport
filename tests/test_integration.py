# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests de integración para vamp-penreport.
Crean JSONs de entrada reales y generan HTML; no necesitan red.
Marcados con @pytest.mark.integration.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import vamp_penreport as pr


# =============================================================================
# Helpers
# =============================================================================

def _meta():
    return pr.ReportMeta(
        client="VampTest Corp",
        engagement="INT-001",
        auditor="VampSecure Labs",
        scope="Infraestructura de test",
    )


def _write_json(data):
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, fh)
    fh.close()
    return fh.name


def _ssl_json(target="target.local"):
    return {
        "tool": "vamp-ssl-audit",
        "version": "1.0",
        "target": target,
        "findings": [
            {"severity": "HIGH", "title": "TLS 1.0 habilitado",
             "description": "El servidor acepta negociaciones TLS 1.0",
             "remediation": "Desactivar TLS 1.0"},
            {"severity": "MEDIUM", "title": "HSTS no configurado",
             "description": "Falta la cabecera Strict-Transport-Security",
             "remediation": "Añadir HSTS"},
        ],
    }


def _fora_json():
    return {
        "tool": "vamp-fora-audit",
        "version": "1.0",
        "target": "app.local",
        "findings": [
            {"id": "FORA-001", "severity": "HIGH",
             "title": "Brute Force en login", "description": "Login sin rate-limit",
             "remediation": "Añadir rate-limiting"},
            {"id": "FORA-004", "severity": "CRITICAL",
             "title": "SQL Injection detectada", "description": "Inyección en /login",
             "remediation": "Usar prepared statements"},
        ],
    }


# =============================================================================
# Tests de integración
# =============================================================================

@pytest.mark.integration
class TestHtmlGeneration:
    """Prueba la generación de HTML completo con datos reales."""

    def test_html_generado_no_vacio(self):
        rpt = pr.PenReport(meta=_meta())
        path = _write_json(_ssl_json())
        try:
            rpt.load_vsl_json(path)
        finally:
            os.unlink(path)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            out_path = fh.name
        try:
            rpt.to_html(out_path)
            contenido = Path(out_path).read_text(encoding="utf-8")
            assert len(contenido) > 500, "El HTML debe tener contenido sustancial"
        finally:
            os.unlink(out_path)

    def test_html_contiene_nombre_cliente(self):
        rpt = pr.PenReport(meta=_meta())
        path = _write_json(_ssl_json())
        try:
            rpt.load_vsl_json(path)
        finally:
            os.unlink(path)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            out_path = fh.name
        try:
            rpt.to_html(out_path)
            contenido = Path(out_path).read_text(encoding="utf-8")
            assert "VampTest Corp" in contenido
        finally:
            os.unlink(out_path)

    def test_html_contiene_titulo_hallazgo(self):
        rpt = pr.PenReport(meta=_meta())
        path = _write_json(_ssl_json())
        try:
            rpt.load_vsl_json(path)
        finally:
            os.unlink(path)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            out_path = fh.name
        try:
            rpt.to_html(out_path)
            contenido = Path(out_path).read_text(encoding="utf-8")
            assert "TLS 1.0 habilitado" in contenido
        finally:
            os.unlink(out_path)

    def test_html_contiene_seccion_mitre(self):
        # Con hallazgos FORA debe aparecer la sección ATT&CK
        rpt = pr.PenReport(meta=_meta())
        path = _write_json(_fora_json())
        try:
            rpt.load_vsl_json(path)
        finally:
            os.unlink(path)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            out_path = fh.name
        try:
            rpt.to_html(out_path)
            contenido = Path(out_path).read_text(encoding="utf-8")
            # La sección ATT&CK debe aparecer
            assert "ATT&amp;CK" in contenido or "MITRE" in contenido or "Tactic" in contenido
        finally:
            os.unlink(out_path)

    def test_multifichero_agrega_todos_hallazgos(self):
        # Cargar dos JSONs y verificar que los hallazgos se acumulan
        rpt = pr.PenReport(meta=_meta())
        p1 = _write_json(_ssl_json())
        p2 = _write_json(_fora_json())
        try:
            n1 = rpt.load_vsl_json(p1)
            n2 = rpt.load_vsl_json(p2)
        finally:
            os.unlink(p1)
            os.unlink(p2)

        assert len(rpt.findings) == n1 + n2

    def test_sector_finanzas_html_menciona_pci(self):
        # El perfil 'finanzas' debe incluir referencia a PCI en el HTML
        rpt = pr.PenReport(meta=_meta(), sector="finanzas")
        path = _write_json(_ssl_json())
        try:
            rpt.load_vsl_json(path)
        finally:
            os.unlink(path)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            out_path = fh.name
        try:
            rpt.to_html(out_path)
            contenido = Path(out_path).read_text(encoding="utf-8")
            assert "PCI" in contenido
        finally:
            os.unlink(out_path)
