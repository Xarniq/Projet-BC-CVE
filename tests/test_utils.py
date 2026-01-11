"""
Tests unitaires pour le module secu_audit.
"""
import pytest
import sys
import os

# Ajouter src au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from secu_audit import (
    sanitize_cpe_token,
    build_software_cpe,
    Colors,
)


class TestSanitizeCpeToken:
    """Tests pour la fonction sanitize_cpe_token."""

    def test_lowercase_conversion(self):
        """Doit convertir en minuscules."""
        assert sanitize_cpe_token("Apache") == "apache"
        assert sanitize_cpe_token("NGINX") == "nginx"

    def test_space_replacement(self):
        """Doit remplacer les espaces par des underscores."""
        assert sanitize_cpe_token("Microsoft Office") == "microsoft_office"

    def test_empty_string(self):
        """Doit retourner '*' pour une chaîne vide."""
        assert sanitize_cpe_token("") == "*"
        assert sanitize_cpe_token(None) == "*"

    def test_strip_whitespace(self):
        """Doit supprimer les espaces de début et fin."""
        assert sanitize_cpe_token("  apache  ") == "apache"


class TestBuildSoftwareCpe:
    """Tests pour la fonction build_software_cpe."""

    def test_basic_cpe(self):
        """Doit construire un CPE basique."""
        cpe = build_software_cpe("Apache", "2.4.57", "apache")
        assert cpe.startswith("cpe:2.3:a:")
        assert "apache" in cpe.lower()
        assert "2.4.57" in cpe


class TestColors:
    """Tests pour la classe Colors."""

    def test_colors_defined(self):
        """Doit avoir les codes couleur définis."""
        assert hasattr(Colors, 'GREEN')
        assert hasattr(Colors, 'RED') or hasattr(Colors, 'FAIL')
        assert hasattr(Colors, 'ENDC')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
