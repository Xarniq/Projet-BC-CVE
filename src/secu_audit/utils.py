"""
Utilitaires - Fonctions de support pour l'audit de sécurité.

Ce module fournit des fonctions utilitaires:
- Construction de CPE (Common Platform Enumeration)
- Sanitization des tokens CPE
- Sauvegarde des rapports JSON

Les CPE suivent le format CPE 2.3:
    cpe:2.3:<part>:<vendor>:<product>:<version>:*:*:*:*:*:*:*

Parts:
    a = application
    o = operating system
    h = hardware

Exemple:
    >>> from utils import build_software_cpe
    >>> cpe = build_software_cpe("Apache", "2.4.57", "apache")
    >>> print(cpe)
    cpe:2.3:a:apache:apache:2.4.57:*:*:*:*:*:*:*
"""
import json
import re
from .config import Colors


def sanitize_cpe_token(token):
    """
    @brief Nettoie un token pour l'inclure dans un CPE 2.3.
    @param token Chaîne brute à normaliser.
    @return str Token nettoyé (lowercase, espaces -> underscores, chars spéciaux retirés) ou "*" si vide.
    """
    if not token:
        return "*"
    
    # Lowercase et remplacement espaces
    token = token.lower().strip()
    token = token.replace(" ", "_")
    
    # Garder seulement alphanum, underscore, point, tiret
    token = re.sub(r'[^a-z0-9._-]', '', token)
    
    return token if token else "*"


def build_software_cpe(name, version=None, vendor=None):
    """
    @brief Construit un CPE 2.3 pour une application.
    @param name Nom du logiciel.
    @param version Version optionnelle du logiciel.
    @param vendor Vendor optionnel (fallback: name normalisé).
    @return str CPE au format "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*".
    """
    vendor = sanitize_cpe_token(vendor or name)
    product = sanitize_cpe_token(name)
    version = sanitize_cpe_token(version)
    
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def build_os_cpe(os_name, os_version=None):
    """
    @brief Construit un CPE 2.3 pour un système d'exploitation.
    @param os_name Nom de l'OS (ex: "Ubuntu", "Windows").
    @param os_version Version optionnelle.
    @return str CPE au format "cpe:2.3:o:vendor:product:version:*:*:*:*:*:*:*".
    """
    os_lower = os_name.lower() if os_name else ""
    
    # Mapping OS -> vendor
    vendor_map = {
        'ubuntu': 'canonical',
        'debian': 'debian',
        'centos': 'centos',
        'red hat': 'redhat',
        'rhel': 'redhat',
        'fedora': 'fedoraproject',
        'windows': 'microsoft',
        'linux': 'linux',
    }
    
    vendor = 'unknown'
    for key, v in vendor_map.items():
        if key in os_lower:
            vendor = v
            break
    
    product = sanitize_cpe_token(os_name)
    version = sanitize_cpe_token(os_version)
    
    return f"cpe:2.3:o:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def build_hardware_cpe(hw_name):
    """
    @brief Construit un CPE 2.3 pour un matériel (CPU).
    @param hw_name Désignation CPU (ex: "Intel Core i7").
    @return str CPE au format "cpe:2.3:h:vendor:product:*:*:*:*:*:*:*:*".
    """
    hw_lower = hw_name.lower() if hw_name else ""
    
    # Déterminer le vendor
    if 'intel' in hw_lower:
        vendor = 'intel'
    elif 'amd' in hw_lower or 'ryzen' in hw_lower or 'epyc' in hw_lower:
        vendor = 'amd'
    elif 'arm' in hw_lower:
        vendor = 'arm'
    else:
        vendor = 'unknown'
    
    product = sanitize_cpe_token(hw_name)
    
    return f"cpe:2.3:h:{vendor}:{product}:*:*:*:*:*:*:*:*"


def save_report(data, filename):
    """
    @brief Sérialise et écrit un rapport JSON.
    @param data Données à persister (dict ou list).
    @param filename Chemin complet du fichier de sortie.
    @return bool True si la sauvegarde réussit, False sinon.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"{Colors.GREEN}[+] Rapport sauvegardé: {filename}{Colors.ENDC}")
        return True
    except IOError as e:
        print(f"{Colors.FAIL}[!] Erreur sauvegarde: {e}{Colors.ENDC}")
        return False


    
