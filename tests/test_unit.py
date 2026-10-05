# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests unitarios para vamp-penreport.
Cobertura: Finding dataclass, normalización de severidad, risk score lineal,
deduplicación, FORA_ATTACK_MAP (25 entradas), perfiles de sector, firma GPG mock,
cabeceras HTML/PDF, distribución de severidades, parseo CVSS.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch


# ── Import del módulo bajo test ───────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))
import vamp_penreport as pr


# =============================================================================
# Helpers
# =============================================================================

def _make_finding(**kwargs):
    """Crea un Finding con campos mínimos."""
    defaults = dict(
        id="FORA-001",
        severity="HIGH",
        title="Hallazgo de test",
        description="Descripción de prueba",
        evidence="",
        remediation="Remediar X",
        references=[],
        source_tool="vamp-test",
        target="target.local",
    )
    defaults.update(kwargs)
    return pr.Finding(**defaults)


def _make_report(sector="generic", gpg_key=""):
    """Crea un PenReport vacío para tests."""
    meta = pr.ReportMeta(
        client="VampTest Corp",
        engagement="test-001",
        auditor="VampSecure Labs",
    )
    return pr.PenReport(meta=meta, verbose=False, sector=sector, gpg_key=gpg_key)


# =============================================================================
# Grupo 1 — Finding dataclass
# =============================================================================

class TestFindingDataclass:
    """Prueba propiedades y comportamiento de la clase Finding."""

    def test_cvss_estimate_critical(self):
        f = _make_finding(severity="CRITICAL")
        assert f.cvss_estimate == "9.0–10.0"

    def test_cvss_estimate_high(self):
        f = _make_finding(severity="HIGH")
        assert f.cvss_estimate == "7.0–8.9"

    def test_cvss_estimate_medium(self):
        f = _make_finding(severity="MEDIUM")
        assert f.cvss_estimate == "4.0–6.9"

    def test_cvss_estimate_low(self):
        f = _make_finding(severity="LOW")
        assert f.cvss_estimate == "1.0–3.9"

    def test_cvss_estimate_info(self):
        f = _make_finding(severity="INFO")
        assert f.cvss_estimate == "0.0"

    def test_color_html_critical_es_rojo(self):
        f = _make_finding(severity="CRITICAL")
        assert f.color_html == "#dc2626"

    def test_color_html_info_es_gris(self):
        f = _make_finding(severity="INFO")
        assert f.color_html == "#6b7280"


# =============================================================================
# Grupo 2 — normalize_severity (SEV_ALIASES)
# =============================================================================

class TestNormalizeSeverity:
    """Prueba el mapeo de aliases a severidades canónicas."""

    def test_crit_a_critical(self):
        assert pr.normalize_severity("CRIT") == "CRITICAL"

    def test_med_a_medium(self):
        assert pr.normalize_severity("MED") == "MEDIUM"

    def test_moderate_a_medium(self):
        assert pr.normalize_severity("MODERATE") == "MEDIUM"

    def test_informational_a_info(self):
        assert pr.normalize_severity("INFORMATIONAL") == "INFO"

    def test_none_a_info(self):
        assert pr.normalize_severity("NONE") == "INFO"

    def test_high_sin_cambio(self):
        assert pr.normalize_severity("HIGH") == "HIGH"

    def test_minusculas_se_normalizan(self):
        # La función debe aceptar minúsculas
        assert pr.normalize_severity("critical") == "CRITICAL"

    def test_desconocido_a_info(self):
        assert pr.normalize_severity("SUPER_GRAVE") == "INFO"


# =============================================================================
# Grupo 3 — FORA_ATTACK_MAP completeness
# =============================================================================

class TestForaAttackMap:
    """Verifica que el mapa FORA tiene exactamente 25 entradas."""

    def test_tiene_25_entradas(self):
        assert len(pr.FORA_ATTACK_MAP) == 25

    def test_rango_001_025(self):
        for i in range(1, 26):
            key = f"FORA-{i:03d}"
            assert key in pr.FORA_ATTACK_MAP, f"{key} falta en FORA_ATTACK_MAP"

    def test_tupla_tactica_tecnica(self):
        # Cada entrada debe ser (táctica, técnica) — dos strings no vacíos
        for k, v in pr.FORA_ATTACK_MAP.items():
            assert isinstance(v, tuple), f"{k}: el valor debe ser tupla"
            assert len(v) == 2, f"{k}: la tupla debe tener 2 elementos"
            assert v[0] and v[1], f"{k}: táctica o técnica vacía"

    def test_fora_001_credential_access(self):
        tactic, _ = pr.FORA_ATTACK_MAP["FORA-001"]
        assert tactic == "Credential Access"

    def test_fora_004_initial_access(self):
        tactic, _ = pr.FORA_ATTACK_MAP["FORA-004"]
        assert tactic == "Initial Access"

    def test_fora_025_exfiltration(self):
        tactic, _ = pr.FORA_ATTACK_MAP["FORA-025"]
        assert tactic == "Exfiltration"


# =============================================================================
# Grupo 4 — SECTOR_PROFILES
# =============================================================================

class TestSectorProfiles:
    """Verifica que todos los sectores tienen las claves requeridas."""

    SECTORES_REQUERIDOS = ["finanzas", "sanidad", "admin-publica", "ecommerce", "generic"]
    CLAVES_REQUERIDAS = ["nombre", "resumen_ejecutivo", "marco_regulatorio"]

    def test_sectores_existen(self):
        for s in self.SECTORES_REQUERIDOS:
            assert s in pr.SECTOR_PROFILES, f"Sector '{s}' no encontrado"

    def test_claves_completas_en_cada_sector(self):
        for s, perfil in pr.SECTOR_PROFILES.items():
            for clave in self.CLAVES_REQUERIDAS:
                assert clave in perfil, f"Sector '{s}' no tiene clave '{clave}'"

    def test_sector_finanzas_menciona_pci(self):
        perfil = pr.SECTOR_PROFILES["finanzas"]
        assert "PCI" in perfil["marco_regulatorio"] or "pci" in perfil["marco_regulatorio"].lower()

    def test_sector_sanidad_menciona_rgpd(self):
        perfil = pr.SECTOR_PROFILES["sanidad"]
        texto = (perfil["marco_regulatorio"] + perfil["resumen_ejecutivo"]).upper()
        assert "RGPD" in texto or "GDPR" in texto or "SALUD" in texto


# =============================================================================
# Grupo 5 — PenReport.risk_score() — fórmula lineal
# =============================================================================

class TestRiskScoreLineal:
    """Prueba la fórmula lineal: min(100, CRIT×25 + HIGH×10 + MED×5 + LOW×1)."""

    def _report_with_findings(self, *sev_list):
        rpt = _make_report()
        for s in sev_list:
            rpt.findings.append(_make_finding(severity=s))
        return rpt

    def test_sin_hallazgos_es_cero(self):
        rpt = _make_report()
        assert rpt.risk_score() == 0

    def test_un_critical_es_25(self):
        rpt = self._report_with_findings("CRITICAL")
        assert rpt.risk_score() == 25

    def test_cuatro_criticals_es_100(self):
        rpt = self._report_with_findings(*["CRITICAL"] * 4)
        assert rpt.risk_score() == 100

    def test_saturacion_en_100(self):
        # Muchos hallazgos no superan 100
        rpt = self._report_with_findings(*["CRITICAL"] * 100)
        assert rpt.risk_score() == 100

    def test_mix_hallazgos(self):
        # 1 CRITICAL(25) + 2 HIGH(20) + 2 MEDIUM(10) + 1 LOW(1) = 56
        rpt = self._report_with_findings(
            "CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"
        )
        assert rpt.risk_score() == 56

    def test_solo_info_es_cero(self):
        # INFO tiene peso 0
        rpt = self._report_with_findings(*["INFO"] * 50)
        assert rpt.risk_score() == 0

    def test_risk_label_critico(self):
        rpt = self._report_with_findings(*["CRITICAL"] * 4)
        assert rpt.risk_label() == "Crítico"

    def test_risk_label_bajo(self):
        rpt = self._report_with_findings("LOW")
        assert rpt.risk_label() == "Bajo"


# =============================================================================
# Grupo 6 — PenReport.deduplicate()
# =============================================================================

class TestPenReportDeduplicate:
    """Prueba la deduplicación por ID y por (título, severidad)."""

    def test_mismo_id_se_elimina(self):
        rpt = _make_report()
        rpt.findings.append(_make_finding(id="FORA-001", title="Brute Force", severity="HIGH"))
        rpt.findings.append(_make_finding(id="FORA-001", title="Brute Force diferente", severity="HIGH"))
        eliminados = rpt.deduplicate()
        assert eliminados == 1
        assert len(rpt.findings) == 1

    def test_mismo_titulo_sev_se_elimina(self):
        rpt = _make_report()
        rpt.findings.append(_make_finding(id="TST-001", title="TLS 1.0", severity="HIGH"))
        rpt.findings.append(_make_finding(id="TST-002", title="TLS 1.0", severity="HIGH"))
        eliminados = rpt.deduplicate()
        assert eliminados == 1
        assert len(rpt.findings) == 1

    def test_diferente_titulo_se_conserva(self):
        rpt = _make_report()
        rpt.findings.append(_make_finding(id="TST-001", title="TLS 1.0", severity="HIGH"))
        rpt.findings.append(_make_finding(id="TST-002", title="TLS 1.1", severity="HIGH"))
        eliminados = rpt.deduplicate()
        assert eliminados == 0
        assert len(rpt.findings) == 2

    def test_mismo_titulo_diferente_sev_no_duplicado(self):
        rpt = _make_report()
        rpt.findings.append(_make_finding(id="TST-001", title="Error config", severity="HIGH"))
        rpt.findings.append(_make_finding(id="TST-002", title="Error config", severity="LOW"))
        eliminados = rpt.deduplicate()
        assert eliminados == 0

    def test_lista_vacia(self):
        rpt = _make_report()
        assert rpt.deduplicate() == 0


# =============================================================================
# Grupo 7 — _fora_attack_coverage
# =============================================================================

class TestForaAttackCoverage:
    """Prueba el agrupamiento de hallazgos FORA por táctica ATT&CK."""

    def test_hallazgo_fora_mapea_a_tactica(self):
        rpt = _make_report()
        rpt.findings.append(_make_finding(id="FORA-001", severity="HIGH"))
        cobertura = rpt._fora_attack_coverage()
        assert "Credential Access" in cobertura
        assert len(cobertura["Credential Access"]) == 1

    def test_hallazgo_no_fora_ignorado(self):
        rpt = _make_report()
        rpt.findings.append(_make_finding(id="SSL-001", severity="HIGH"))
        cobertura = rpt._fora_attack_coverage()
        assert cobertura == {}

    def test_multiple_taticas(self):
        rpt = _make_report()
        rpt.findings.append(_make_finding(id="FORA-001", severity="HIGH"))   # Credential Access
        rpt.findings.append(_make_finding(id="FORA-004", severity="CRITICAL")) # Initial Access
        cobertura = rpt._fora_attack_coverage()
        assert "Credential Access" in cobertura
        assert "Initial Access" in cobertura

    def test_fora_desconocido_mapea_unknown(self):
        rpt = _make_report()
        rpt.findings.append(_make_finding(id="FORA-999", severity="MEDIUM"))
        cobertura = rpt._fora_attack_coverage()
        assert "Unknown" in cobertura


# =============================================================================
# Grupo 8 — Firma GPG (mock)
# =============================================================================

class TestGpgSign:
    """Prueba la firma GPG con subprocess mockeado."""

    def test_firma_gpg_llamada_cuando_gpg_key_configurado(self):
        rpt = _make_report(gpg_key="test@vampsecure.local")
        mock_proc = MagicMock()
        mock_proc.returncode = 0

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            fh.write("<html>test</html>")
            html_path = fh.name

        try:
            with patch("shutil.which", return_value="/usr/bin/gpg"):
                with patch("subprocess.run", return_value=mock_proc) as mock_sub:
                    rpt._sign_gpg(html_path)
            mock_sub.assert_called_once()
            cmd = mock_sub.call_args[0][0]
            assert "gpg" in cmd
            assert "--detach-sign" in cmd
            assert "--armor" in cmd
            assert "test@vampsecure.local" in cmd
        finally:
            os.unlink(html_path)

    def test_sin_gpg_instalado_no_aborta(self):
        rpt = _make_report(gpg_key="test@vampsecure.local")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            fh.write("<html>test</html>")
            html_path = fh.name
        try:
            with patch("shutil.which", return_value=None):
                # No debe lanzar excepción
                rpt._sign_gpg(html_path)
        finally:
            os.unlink(html_path)

    def test_sin_gpg_key_no_se_llama_sign(self):
        rpt = _make_report(gpg_key="")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            fh.write("<html>test</html>")
            html_path = fh.name
        try:
            with patch("subprocess.run") as mock_sub:
                rpt.to_html(html_path)
            # No debe haber llamado a subprocess (sin gpg_key)
            mock_sub.assert_not_called()
        finally:
            for p in [html_path, html_path + ".asc"]:
                if os.path.exists(p):
                    os.unlink(p)


# =============================================================================
# Grupo 9 — load_vsl_json y normalización
# =============================================================================

class TestLoadVslJson:
    """Prueba la carga de JSON VSL y la normalización de hallazgos."""

    def _write_json(self, data, suffix=".json"):
        """Escribe un JSON temporal y devuelve la ruta."""
        fh = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
        json.dump(data, fh)
        fh.close()
        return fh.name

    def test_carga_hallazgos_desde_json(self):
        data = {
            "tool": "vamp-ssl-audit",
            "version": "1.0",
            "target": "target.local",
            "findings": [
                {"severity": "HIGH", "title": "TLS 1.0", "description": "desc",
                 "remediation": "fix"},
            ],
        }
        path = self._write_json(data)
        try:
            rpt = _make_report()
            cargados = rpt.load_vsl_json(path)
            assert cargados == 1
            assert len(rpt.findings) == 1
        finally:
            os.unlink(path)

    def test_fichero_inexistente_devuelve_cero(self):
        rpt = _make_report()
        cargados = rpt.load_vsl_json("/ruta/que/no/existe.json")
        assert cargados == 0

    def test_alias_severidad_normalizado(self):
        # 'CRIT' debe normalizarse a 'CRITICAL'
        data = {
            "tool": "test", "version": "1.0", "target": "h.local",
            "findings": [{"severity": "CRIT", "title": "Test", "description": ""}],
        }
        path = self._write_json(data)
        try:
            rpt = _make_report()
            rpt.load_vsl_json(path)
            assert rpt.findings[0].severity == "CRITICAL"
        finally:
            os.unlink(path)

    def test_json_invalido_devuelve_cero(self):
        fh = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        fh.write("{esto no es json}")
        fh.close()
        try:
            rpt = _make_report()
            cargados = rpt.load_vsl_json(fh.name)
            assert cargados == 0
        finally:
            os.unlink(fh.name)


# =============================================================================
# Grupo 10 — PenReport.sector
# =============================================================================

class TestSectorProfile:
    """Prueba que el sector inválido cae en 'generic'."""

    def test_sector_invalido_usa_generic(self):
        rpt = _make_report(sector="sector_inventado")
        assert rpt.sector == "generic"

    def test_sector_finanzas_persiste(self):
        rpt = _make_report(sector="finanzas")
        assert rpt.sector == "finanzas"

    def test_sector_sanidad_persiste(self):
        rpt = _make_report(sector="sanidad")
        assert rpt.sector == "sanidad"
