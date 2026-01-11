"""
Module secu_audit - Audit de sécurité hybride.

Ce package fournit des outils pour:
- Scanner le réseau avec Nmap
- Récupérer l'inventaire GLPI
- Corréler les vulnérabilités CVE
- Générer des rapports

Modules:
    config: Configuration centrale
    nmap_module: Scan réseau Nmap
    glpi_module: Intégration GLPI
    cti_module: Recherche CVE via CTI
    utils: Utilitaires divers
"""

from .config import (
    GLPI_URL,
    GLPI_APP_TOKEN,
    GLPI_USER_TOKEN,
    CTI_API_URL,
    DEFAULT_TARGET,
    NMAP_OUTPUT,
    REPORT_OUTPUT,
    REPORTS_DIR,
    Colors,
)

from .nmap_module import (
    run_nmap_scan,
    parse_nmap_results,
    run_discovery_scan,
)

from .glpi_module import (
    get_glpi_inventory,
    kill_session,
)

from .cti_module import (
    check_software_cves,
    check_service_cves,
    check_os_cves,
    check_hardware_cves,
)

from .utils import (
    save_report,
    build_software_cpe,
    build_os_cpe,
    build_hardware_cpe,
    sanitize_cpe_token,
)

__version__ = "1.0.0"
__author__ = "Groupe : Elias, Mattéo B, Lucas, Daniel, Martial"
__all__ = [
    # Config
    "GLPI_URL",
    "GLPI_APP_TOKEN",
    "GLPI_USER_TOKEN",
    "CTI_API_URL",
    "DEFAULT_TARGET",
    "NMAP_OUTPUT",
    "REPORT_OUTPUT",
    "Colors",
    # Nmap
    "run_nmap_scan",
    "parse_nmap_results",
    "run_discovery_scan",
    # GLPI
    "get_glpi_inventory",
    "kill_session",
    # CTI
    "check_software_cves",
    "check_service_cves",
    "check_os_cves",
    "check_hardware_cves",
    # Utils
    "save_report",
    "build_software_cpe",
    "build_os_cpe",
    "build_hardware_cpe",
    "sanitize_cpe_token",
]
