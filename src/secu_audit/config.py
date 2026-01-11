"""
Configuration centrale du projet d'audit de sécurité.

Ce module centralise tous les paramètres de configuration:
- URLs des APIs (GLPI, CVE-Search)
- Tokens d'authentification
- Chemins des fichiers de sortie
- Codes couleur pour l'affichage terminal

Variables d'environnement (fichier .env):
    GLPI_API_URL: URL de l'instance GLPI
    GLPI_APP_TOKEN: Token applicatif GLPI
    GLPI_USER_TOKEN: Token utilisateur GLPI
    CTI_API_URL: URL de l'API CVE-Search
    IP_TARGET: IP cible par défaut

Exemple:
    >>> from config import GLPI_URL, Colors
    >>> print(f"{Colors.GREEN}Connexion à {GLPI_URL}{Colors.ENDC}")
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

## @defgroup config Configuration
#  @brief Configuration centrale du projet d'audit de sécurité.
#  @{

# === Configuration GLPI ===

## URL de l'API REST GLPI (ex: http://192.168.1.100/apirest.php)
GLPI_URL = os.getenv('GLPI_API_URL')

## Token applicatif GLPI pour l'authentification API
GLPI_APP_TOKEN = os.getenv('GLPI_APP_TOKEN')

## Token utilisateur GLPI pour l'authentification API
GLPI_USER_TOKEN = os.getenv('GLPI_USER_TOKEN')

# === Configuration CVE-Search (CTI) ===

## URL de l'API CVE-Search locale (ex: http://localhost:5000/api)
CTI_API_URL = os.getenv('CTI_API_URL')

# === IP cible par défaut ===

## Adresse IP cible par défaut pour les scans (depuis .env)
DEFAULT_TARGET = os.getenv('IP_TARGET')

# === Chemin racine du projet ===

## Chemin absolu vers la racine du projet
PROJECT_ROOT = Path(__file__).parent.parent.parent

# === Fichiers de sortie ===

## Répertoire principal des données générées
DATA_DIR = PROJECT_ROOT / "data"

## Répertoire des fichiers XML Nmap
SCANS_DIR = DATA_DIR / "scans"

## Répertoire des rapports JSON d'audit
REPORTS_DIR = DATA_DIR / "reports"

## Chemin du fichier de sortie XML Nmap
NMAP_OUTPUT = str(SCANS_DIR / "nmap_scan.xml")

## Chemin du fichier de rapport JSON par défaut
REPORT_OUTPUT = str(REPORTS_DIR / "audit_report.json")

## @}

# === Codes couleur terminal ===
class Colors:
    """
    Codes ANSI pour l'affichage coloré dans le terminal.
    
    Permet d'afficher des messages colorés en console pour améliorer
    la lisibilité des résultats d'audit.
    
    Example:
        >>> print(f"{Colors.GREEN}Succès{Colors.ENDC}")
        >>> print(f"{Colors.FAIL}Erreur{Colors.ENDC}")
    """
    
    ## Couleur magenta pour les en-têtes de section
    HEADER = '\033[95m'
    
    ## Couleur bleue pour les informations
    BLUE = '\033[94m'
    
    ## Couleur cyan pour les détails
    CYAN = '\033[96m'
    
    ## Couleur verte pour les succès
    GREEN = '\033[92m'
    
    ## Couleur jaune pour les avertissements
    WARNING = '\033[93m'
    
    ## Couleur rouge pour les erreurs
    FAIL = '\033[91m'
    
    ## Reset des couleurs (retour au défaut)
    ENDC = '\033[0m'
    
    ## Style gras
    BOLD = '\033[1m'
    
    ## Style souligné
    UNDERLINE = '\033[4m'
