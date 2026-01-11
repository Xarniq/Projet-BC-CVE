"""
Module CTI - Recherche de CVE via CVE-Search-Docker API.

Ce module interroge l'API CVE-Search (v6.0.0) pour:
- Rechercher des CVE par vendor:product (regex)
- Corréler les logiciels GLPI avec les vulnérabilités
- Corréler les services Nmap avec les CVE
- Rechercher CVE pour l'OS et le hardware
- Recherche dynamique de vendor/product

L'API CVE-Search utilise MongoDB en backend, d'où les
filtres avec $regex et $options.

Stratégie de recherche (comme vulners.nse):
1. Utiliser les CPE fournis par Nmap si disponibles
2. Utiliser les mappings connus vendor:product
3. Recherche dynamique via /api/browse/{vendor}
4. Fallback sur recherche directe par nom

Prérequis:
    - CVE-Search-Docker lancé (docker-compose up)
    - Base CVE chargée (~10min au premier lancement)

Endpoints utilisés:
    - POST /api/query : Recherche avec filtres MongoDB
    - GET /api/browse/{vendor} : Lister produits d'un vendor

Exemple:
    >>> from cti_module import check_software_cves
    >>> softwares = [{"name": "apache2", "version": "2.4.57"}]
    >>> cves = check_software_cves(softwares)
    >>> print(f"CVE trouvées: {len(cves)}")
"""
import re
import requests
from .config import CTI_API_URL, Colors
from .utils import build_software_cpe, build_os_cpe, build_hardware_cpe, sanitize_cpe_token


# Désactiver les warnings SSL pour les appels locaux
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# === Caches pour optimisation ===
_vendor_products_cache = {}
_cve_cache = {}
_vendor_search_cache = {}


# ==============================================================================
# Fonction helper pour extraire le score CVSS
# ==============================================================================

def extract_cvss_score(cve_data):
    """
    @brief Extrait le score CVSS d'une CVE (priorité CVSS v3 > v2).
    
    L'API CVE-Search peut retourner le score sous différentes clés:
    - cvss3, cvss (niveau racine)
    - impact.baseMetricV3.cvssV3.baseScore (format NVD)
    - impact.baseMetricV2.cvssV2.baseScore (format NVD)
    
    @param cve_data Dict contenant les données CVE de l'API.
    @return float Score CVSS ou None si non disponible.
    """
    if not cve_data:
        return None
    
    # 1. Essayer les clés directes (priorité CVSS v3)
    if cve_data.get("cvss3") is not None:
        try:
            return float(cve_data["cvss3"])
        except (ValueError, TypeError):
            pass
    
    if cve_data.get("cvss") is not None:
        try:
            return float(cve_data["cvss"])
        except (ValueError, TypeError):
            pass
    
    # 2. Essayer le format NVD (impact.baseMetricV3/V2)
    impact = cve_data.get("impact", {})
    if isinstance(impact, dict):
        # CVSS v3
        base_metric_v3 = impact.get("baseMetricV3", {})
        if isinstance(base_metric_v3, dict):
            cvss_v3 = base_metric_v3.get("cvssV3", {})
            if isinstance(cvss_v3, dict) and cvss_v3.get("baseScore") is not None:
                try:
                    return float(cvss_v3["baseScore"])
                except (ValueError, TypeError):
                    pass
        
        # CVSS v2 (fallback)
        base_metric_v2 = impact.get("baseMetricV2", {})
        if isinstance(base_metric_v2, dict):
            cvss_v2 = base_metric_v2.get("cvssV2", {})
            if isinstance(cvss_v2, dict) and cvss_v2.get("baseScore") is not None:
                try:
                    return float(cvss_v2["baseScore"])
                except (ValueError, TypeError):
                    pass
    
    # 3. Essayer d'autres variantes de clés
    for key in ["cvssScore", "cvss_score", "baseScore", "base_score", "score"]:
        if cve_data.get(key) is not None:
            try:
                return float(cve_data[key])
            except (ValueError, TypeError):
                pass
    
    return None


# ==============================================================================
# Fonctions de normalisation et recherche dynamique
# ==============================================================================

def normalize_software_name(name):
    """
    @brief Normalise un nom logiciel avant recherche CVE.
    @param name Nom brut (package ou binaire).
    @return str Nom épuré (lowercase, sans suffixes packaging ni numéros finaux).
    """
    if not name:
        return ""
    
    name = name.lower().strip()
    
    # === Nettoyage spécifique Windows ===
    # Retirer les architectures
    name = re.sub(r'\s*\(?(x64|x86|amd64|win64|win32|64-bit|32-bit)\)?', '', name)
    
    # Retirer les mentions inutiles
    noise = [
        r'\s+corporation', r'\s+inc\.?', r'\s+ltd\.?', r'\s+llc',
        r'\s+gmbh', r'\s+s\.a\.r\.l', r'\s+software',
        r'\s+edition', r'\s+professional', r'\s+enterprise', r'\s+ultimate', r'\s+home',
        r'\s+standard', r'\s+update', r'\s+service pack \d+',
        r'\s+install(er)?', r'\s+setup',
        r'^\s*microsoft\s+',  # On enlève Microsoft du nom du produit (géré par vendor)
        r'^\s*adobe\s+',
        r'^\s*google\s+',
    ]
    for pattern in noise:
        name = re.sub(pattern, '', name)

    # Retirer les suffixes de packaging courants (Linux)
    suffixes_to_remove = [
        '-common', '-bin', '-dev', '-lib', '-libs', '-utils', '-tools',
        '-data', '-doc', '-core', '-base', '-server', '-client',
        '-runtime', '-modules', '-extra', '-plugins', '-daemon'
    ]
    for suffix in suffixes_to_remove:
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    
    # Retirer les préfixes de lib
    if name.startswith('lib') and len(name) > 4:
        potential = name[3:]
        if not potential[0].isdigit():
            name = potential
    
    # Retirer les numéros de version à la fin
    name = re.sub(r'\s+v?\d+(\.\d+)*(\.\d+)*\s*$', '', name)
    name = re.sub(r'_?v?\d+(\.\d+)*$', '', name)
    
    # Nettoyer les caractères spéciaux restants
    name = re.sub(r'[^a-z0-9\-\.\_\s]', '', name)
    name = re.sub(r'\s+', ' ', name).strip()
    
    return name


def search_vendor_dynamically(software_name):
    """
    @brief Tente de déduire vendor/product en interrogeant /browse/{vendor}.
    @param software_name Nom normalisé du logiciel.
    @return tuple (vendor, product) ou (None, None) si non trouvé.
    """
    if not software_name or not CTI_API_URL:
        return None, None
    
    # Vérifier le cache
    if software_name in _vendor_search_cache:
        return _vendor_search_cache[software_name]
    
    # Variantes à essayer
    variants = [software_name]
    
    # Ajouter des variantes (ex: openssh -> openbsd pour le vendor)
    if '_' in software_name:
        parts = software_name.split('_')
        variants.extend(parts)
    
    for variant in variants:
        if len(variant) < 3:
            continue
        
        # Essayer variant comme vendor
        products = get_vendor_products(variant)
        if products:
            # Chercher un produit qui correspond
            for product in products:
                if variant in product.lower() or product.lower() in variant:
                    _vendor_search_cache[software_name] = (variant, product)
                    return variant, product
            
            # Sinon prendre le premier produit similaire
            if products:
                _vendor_search_cache[software_name] = (variant, products[0])
                return variant, products[0]
    
    _vendor_search_cache[software_name] = (None, None)
    return None, None


def search_cve_by_name_direct(software_name, limit=15):
    """
    @brief Fallback: recherche de CVE par regex sur vulnerable_product.
    @param software_name Nom du logiciel à rechercher.
    @param limit Nombre max de résultats retournés.
    @return list CVE correspondantes.
    """
    if not software_name or len(software_name) < 3:
        return []
    
    # Construire un pattern regex flexible
    pattern = f".*{re.escape(software_name)}.*"
    
    return query_cves(pattern, limit=limit)


# ==============================================================================
# Fonctions de base pour interroger CVE-Search
# ==============================================================================

def query_cves(regex_pattern, limit=30):
    """
    @brief Envoie une requête POST /api/query filtrée par regex.
    @param regex_pattern Expression régulière sur vulnerable_product.
    @param limit Maximum de résultats retournés.
    @return list CVE renvoyées par l'API (liste vide en cas d'erreur).
    """
    if not regex_pattern or not CTI_API_URL:
        return []
    
    # Vérifier le cache
    if regex_pattern in _cve_cache:
        return _cve_cache[regex_pattern]
    
    try:
        payload = {
            "retrieve": "cves",
            "dict_filter": {
                "vulnerable_product": {"$regex": regex_pattern, "$options": "i"}
            },
            "limit": limit,
            "sort": "cvss3",
            "sort_dir": "DESC"
        }
        
        resp = requests.post(
            f"{CTI_API_URL}/query",
            json=payload,
            timeout=30,
            verify=False
        )
        resp.raise_for_status()
        data = resp.json()
        
        cves = data.get("data", [])
        _cve_cache[regex_pattern] = cves
        return cves
        
    except requests.exceptions.RequestException as e:
        print(f"{Colors.WARNING}[!] Erreur query CVE: {e}{Colors.ENDC}")
        return []


def get_vendor_products(vendor):
    """
    @brief Récupère les produits exposés pour un vendor.
    @param vendor Nom du vendor (ex: "apache").
    @return list Produits listés par /api/browse/{vendor}.
    """
    if not vendor or not CTI_API_URL:
        return []
    
    if vendor in _vendor_products_cache:
        return _vendor_products_cache[vendor]
    
    try:
        resp = requests.get(
            f"{CTI_API_URL}/browse/{vendor}",
            timeout=10,
            verify=False
        )
        resp.raise_for_status()
        data = resp.json()
        products = data.get("product", [])
        _vendor_products_cache[vendor] = products
        return products
    except requests.exceptions.RequestException:
        return []


def search_cve_by_cpe(vendor, product, version=None):
    """
    @brief Recherche des CVE via regex vendor/product.
    @param vendor Vendor (ex: "apache").
    @param product Produit (ex: "http_server").
    @param version Version optionnelle (actuellement non utilisée dans la regex).
    @return list CVE correspondantes.
    """
    if not vendor or not product or not CTI_API_URL:
        return []
    
    # Construire le pattern regex pour CPE
    regex_pattern = f"{vendor}.*{product}"
    
    return query_cves(regex_pattern, limit=30)


def search_cve_by_cpe_string(cpe_string, limit=30):
    """
    @brief Recherche des CVE à partir d'un CPE fourni (ex: Nmap).
    @param cpe_string Chaîne CPE (cpe:/a:vendor:product:version).
    @param limit Nombre max de CVE.
    @return list CVE trouvées ou liste vide.
    """
    if not cpe_string or not CTI_API_URL:
        return []
    
    # Extraire vendor:product du CPE
    # Format: cpe:/a:vendor:product:version ou cpe:2.3:a:vendor:product:version:...
    match = re.search(r'cpe:/?(?:2\.3:)?[aoh]:([^:]+):([^:]+)', cpe_string)
    if match:
        vendor = match.group(1)
        product = match.group(2)
        return search_cve_by_cpe(vendor, product)
    
    return []


# ==============================================================================
# Fonctions principales de corrélation
# ==============================================================================

def check_software_cves(softwares):
    """
    @brief Recherche des CVE pour les logiciels d'inventaire GLPI.
    @param softwares Liste de dicts {"name", "version"}.
    @return list CVE enrichies (source, cpe, méthode de recherche).
    """
    cves_found = []
    checked = set()
    
    # Mapping des noms de packages vers vendor:product CVE-Search
    known_mappings = {
        'apache2': ('apache', 'http_server'),
        'apache': ('apache', 'http_server'),
        'httpd': ('apache', 'http_server'),
        'openssh': ('openbsd', 'openssh'),
        'ssh': ('openbsd', 'openssh'),
        'nginx': ('nginx', 'nginx'),
        'mysql': ('oracle', 'mysql'),
        'mariadb': ('mariadb', 'mariadb_server'),
        'postgresql': ('postgresql', 'postgresql'),
        'php': ('php', 'php'),
        'python': ('python', 'python'),
        'python3': ('python', 'python'),
        'perl': ('perl', 'perl'),
        'bash': ('gnu', 'bash'),
        'openssl': ('openssl', 'openssl'),
        'curl': ('haxx', 'curl'),
        'libcurl': ('haxx', 'libcurl'),
        'wget': ('gnu', 'wget'),
        'git': ('git-scm', 'git'),
        'vim': ('vim', 'vim'),
        'sudo': ('todd_miller', 'sudo'),
        'bind9': ('isc', 'bind'),
        'bind': ('isc', 'bind'),
        'systemd': ('systemd_project', 'systemd'),
        'linux': ('linux', 'linux_kernel'),
        'kernel': ('linux', 'linux_kernel'),
        'samba': ('samba', 'samba'),
        'redis': ('redis', 'redis'),
        'docker': ('docker', 'docker'),
        'tomcat': ('apache', 'tomcat'),
        'jenkins': ('jenkins', 'jenkins'),
        'wordpress': ('wordpress', 'wordpress'),
        'proftpd': ('proftpd_project', 'proftpd'),
        'vsftpd': ('vsftpd_project', 'vsftpd'),
        'postfix': ('postfix', 'postfix'),
        'exim': ('exim', 'exim'),
        'dovecot': ('dovecot', 'dovecot'),
        'cups': ('apple', 'cups'),
        'squid': ('squid-cache', 'squid'),
        'haproxy': ('haproxy', 'haproxy'),
        'grafana': ('grafana', 'grafana'),
        'prometheus': ('prometheus', 'prometheus'),
        'elasticsearch': ('elastic', 'elasticsearch'),
        'kibana': ('elastic', 'kibana'),
        'logstash': ('elastic', 'logstash'),
        'mongodb': ('mongodb', 'mongodb'),
        'couchdb': ('apache', 'couchdb'),
        'rabbitmq': ('pivotal_software', 'rabbitmq'),
        'memcached': ('memcached', 'memcached'),
        'zabbix': ('zabbix', 'zabbix'),
        'nagios': ('nagios', 'nagios'),
        'ansible': ('redhat', 'ansible'),
        'terraform': ('hashicorp', 'terraform'),
        'vault': ('hashicorp', 'vault'),
        'consul': ('hashicorp', 'consul'),
        'kubernetes': ('kubernetes', 'kubernetes'),
        'node': ('nodejs', 'node.js'),
        'nodejs': ('nodejs', 'node.js'),
        'ruby': ('ruby-lang', 'ruby'),
        'java': ('oracle', 'jdk'),
        'openjdk': ('oracle', 'openjdk'),
        'golang': ('golang', 'go'),
        'rust': ('rust-lang', 'rust'),
        'dotnet': ('microsoft', '.net'),
        # Windows specifics
        'microsoft edge': ('microsoft', 'edge'),
        'edge': ('microsoft', 'edge'),
        'google chrome': ('google', 'chrome'),
        'chrome': ('google', 'chrome'),
        'firefox': ('mozilla', 'firefox'),
        'mozilla firefox': ('mozilla', 'firefox'),
        'vlc': ('videolan', 'vlc_media_player'),
        'vlc media player': ('videolan', 'vlc_media_player'),
        'adobe acrobat': ('adobe', 'acrobat_reader'),
        'acrobat reader': ('adobe', 'acrobat_reader'),
        '7-zip': ('7-zip', '7-zip'),
        'notepad++': ('notepad-plus-plus', 'notepad++'),
        'winrar': ('rarlab', 'winrar'),
        'teamviewer': ('teamviewer', 'teamviewer'),
        'anydesk': ('anydesk', 'anydesk'),
        'skype': ('microsoft', 'skype'),
        'office': ('microsoft', 'office'),
        'libreoffice': ('libreoffice', 'libreoffice'),
        'virtualbox': ('oracle', 'vm_virtualbox'),
        'vmware workstation': ('vmware', 'workstation'),
        'wireshark': ('wireshark', 'wireshark'),
        'putty': ('putty', 'putty'),
        'filezilla': ('filezilla', 'filezilla_client'),
        'winscp': ('winscp', 'winscp'),
        'paint.net': ('dotpdn', 'paint.net'),
        'gimp': ('gimp', 'gimp'),
        'inkscape': ('inkscape', 'inkscape'),
        'audacity': ('audacity', 'audacity'),
        'obs studio': ('obsproject', 'obs_studio'),
        'dell command': ('dell', 'command_update'),
        'hp support assistant': ('hp', 'support_assistant'),
        'lenovo vantage': ('lenovo', 'vantage'),
        'intel graphics': ('intel', 'graphics_driver'),
        'nvidia geforce': ('nvidia', 'geforce_experience'),
        'onedrive': ('microsoft', 'onedrive'),
        'teams': ('microsoft', 'teams'),
        'outlook': ('microsoft', 'outlook'),
        'word': ('microsoft', 'word'),
        'excel': ('microsoft', 'excel'),
        'powerpoint': ('microsoft', 'powerpoint'),
        'visio': ('microsoft', 'visio'),
        'project': ('microsoft', 'project'),
    }
    
    for sw in softwares:
        name = sw.get("name", "").lower().strip()
        version = sw.get("version", "")
        
        if not name:
            continue
        
        vendor, product = None, None
        search_method = "mapping"
        
        # 1. Chercher dans les mappings connus
        for key, (v, p) in known_mappings.items():
            if key in name or name.startswith(key):
                vendor, product = v, p
                break
        
        # 2. Si pas de mapping, essayer la recherche dynamique
        if not vendor or not product:
            normalized = normalize_software_name(name)
            if normalized and len(normalized) >= 3:
                vendor, product = search_vendor_dynamically(normalized)
                if vendor and product:
                    search_method = "dynamic"
        
        # 3. Si toujours rien, recherche directe par nom
        if not vendor or not product:
            normalized = normalize_software_name(name)
            if normalized and len(normalized) >= 3:
                search_key = f"direct:{normalized}"
                if search_key not in checked:
                    checked.add(search_key)
                    
                    print(f"{Colors.BLUE}[*] Recherche CVE directe (regex) pour '{normalized}'...{Colors.ENDC}")
                    results = search_cve_by_name_direct(normalized, limit=15)
                    
                    # Tentative de déduction du vendor depuis les résultats (Feature "Bulletproof")
                    guessed_vendor = normalized # Valeur par défaut
                    if results:
                        for cve in results:
                            # Analyser les configs vulnérables pour trouver le vrai vendor
                            configs = cve.get('vulnerable_configuration', [])
                            found_vendor = False
                            for cfg in configs:
                                # Format CPE: cpe:2.3:a:vendor:product:...
                                # Chercher si notre produit est dedans
                                if normalized in cfg:
                                    parts = cfg.split(':')
                                    if len(parts) >= 5:
                                        # parts[3] est le vendor dans cpe:2.3:a:vendor:product
                                        # parts[2] est le vendor dans cpe:/a:vendor:product
                                        idx_vendor = 3 if parts[1] == '2.3' else 2
                                        if len(parts) > idx_vendor:
                                            guessed_vendor = parts[idx_vendor]
                                            found_vendor = True
                                            break
                            if found_vendor:
                                # print(f"{Colors.GREEN}[+] Vendor 'cached' détecté pour {normalized}: {guessed_vendor}{Colors.ENDC}")
                                # Ajouter au mapping pour les prochains
                                known_mappings[normalized] = (guessed_vendor, normalized)
                                break

                    cpe = build_software_cpe(name, version, guessed_vendor)
                    
                    for cve in results:
                        cve_id = cve.get("id") or cve.get("cve_id") or cve.get("cve")
                        if cve_id:
                            cves_found.append({
                                "source": "cti/software",
                                "cve_id": cve_id,
                                "cvss": extract_cvss_score(cve),
                                "software": sw.get("name"),
                                "version": version,
                                "cpe": cpe,
                                "search_method": "direct",
                                "description": cve.get("summary", cve.get("description", ""))[:200]
                            })
            continue
        
        # Éviter les recherches en double
        search_key = f"{vendor}:{product}"
        if search_key in checked:
            continue
        checked.add(search_key)
        
        # Construire le CPE
        cpe = build_software_cpe(name, version, vendor)
        
        # Rechercher via CVE-Search
        if search_method == "dynamic":
            print(f"{Colors.BLUE}[*] Recherche CVE pour {vendor}:{product} (auto-détecté)...{Colors.ENDC}")
        else:
            print(f"{Colors.BLUE}[*] Recherche CVE pour {vendor}:{product}...{Colors.ENDC}")
        
        results = search_cve_by_cpe(vendor, product, version)
        
        for cve in results:
            cve_id = cve.get("id") or cve.get("cve_id") or cve.get("cve")
            if cve_id:
                cves_found.append({
                    "source": "cti/software",
                    "cve_id": cve_id,
                    "cvss": extract_cvss_score(cve),
                    "software": sw.get("name"),
                    "version": version,
                    "cpe": cpe,
                    "search_method": search_method,
                    "description": cve.get("summary", cve.get("description", ""))[:200]
                })
    
    return cves_found


def check_service_cves(services):
    """
    @brief Corrèle les services Nmap avec des CVE (priorité aux CPE Nmap).
    @param services Liste des services Nmap (port, protocol, service, product, version, cpes).
    @return list CVE associées aux services.
    """
    cves_found = []
    checked = set()
    
    # Mapping services Nmap vers vendor:product
    service_mappings = {
        'apache': ('apache', 'http_server'),
        'httpd': ('apache', 'http_server'),
        'openssh': ('openbsd', 'openssh'),
        'ssh': ('openbsd', 'openssh'),
        'nginx': ('nginx', 'nginx'),
        'mysql': ('oracle', 'mysql'),
        'mariadb': ('mariadb', 'mariadb_server'),
        'postgresql': ('postgresql', 'postgresql'),
        'postgres': ('postgresql', 'postgresql'),
        'proftpd': ('proftpd_project', 'proftpd'),
        'vsftpd': ('vsftpd_project', 'vsftpd'),
        'pure-ftpd': ('pureftpd', 'pure-ftpd'),
        'bind': ('isc', 'bind'),
        'named': ('isc', 'bind'),
        'samba': ('samba', 'samba'),
        'smbd': ('samba', 'samba'),
        'redis': ('redis', 'redis'),
        'memcached': ('memcached', 'memcached'),
        'mongodb': ('mongodb', 'mongodb'),
        'elasticsearch': ('elastic', 'elasticsearch'),
        'tomcat': ('apache', 'tomcat'),
        'jetty': ('eclipse', 'jetty'),
        'lighttpd': ('lighttpd', 'lighttpd'),
        'iis': ('microsoft', 'iis'),
        'exchange': ('microsoft', 'exchange_server'),
        'dovecot': ('dovecot', 'dovecot'),
        'postfix': ('postfix', 'postfix'),
        'exim': ('exim', 'exim'),
        'sendmail': ('sendmail', 'sendmail'),
        'cups': ('apple', 'cups'),
        'snmp': ('net-snmp', 'net-snmp'),
        'ldap': ('openldap', 'openldap'),
        'openldap': ('openldap', 'openldap'),
        'squid': ('squid-cache', 'squid'),
        'haproxy': ('haproxy', 'haproxy'),
        'varnish': ('varnish-software', 'varnish'),
        'docker': ('docker', 'docker'),
    }
    
    for svc in services:
        product = svc.get("product", "").lower()
        version = svc.get("version", "")
        service_name = svc.get("service", "")
        cpes = svc.get("cpes", [])
        
        # 1. PRIORITÉ: Utiliser les CPE fournis par Nmap (comme vulners.nse)
        if cpes:
            for cpe_string in cpes:
                if cpe_string in checked:
                    continue
                checked.add(cpe_string)
                
                print(f"{Colors.BLUE}[*] Recherche CVE via CPE Nmap: {cpe_string}...{Colors.ENDC}")
                results = search_cve_by_cpe_string(cpe_string)
                
                for cve in results:
                    cve_id = cve.get("id") or cve.get("cve_id") or cve.get("cve")
                    if cve_id:
                        cves_found.append({
                            "source": "cti/service",
                            "cve_id": cve_id,
                            "cvss": extract_cvss_score(cve),
                            "service": service_name,
                            "product": product or service_name,
                            "version": version,
                            "port": svc.get("port"),
                            "cpe": cpe_string,
                            "search_method": "nmap_cpe",
                            "description": cve.get("summary", cve.get("description", ""))[:200]
                        })
            continue  # Si on a des CPE Nmap, pas besoin des autres méthodes
        
        # Terme de recherche : privilégier product si disponible
        search_term = product if product else service_name
        if not search_term:
            continue
        
        vendor, cve_product = None, None
        search_method = "mapping"
        
        # 2. Chercher dans les mappings connus
        for key, (v, p) in service_mappings.items():
            if key in search_term.lower():
                vendor, cve_product = v, p
                break
        
        # 3. Si pas de mapping, essayer la recherche dynamique
        if not vendor or not cve_product:
            normalized = normalize_software_name(search_term)
            if normalized and len(normalized) >= 3:
                vendor, cve_product = search_vendor_dynamically(normalized)
                if vendor and cve_product:
                    search_method = "dynamic"
        
        # 4. Si toujours rien, recherche directe par nom
        if not vendor or not cve_product:
            normalized = normalize_software_name(search_term)
            if normalized and len(normalized) >= 3:
                search_key = f"direct:{normalized}"
                if search_key not in checked:
                    checked.add(search_key)
                    
                    results = search_cve_by_name_direct(normalized, limit=10)
                    
                    # Tentative de déduction du vendor depuis les résultats
                    guessed_vendor = normalized # Valeur par défaut
                    for cve in results:
                        # Analyser les configs vulnérables pour trouver le vrai vendor
                        configs = cve.get('vulnerable_configuration', [])
                        found_vendor = False
                        for cfg in configs:
                            # Format CPE: cpe:2.3:a:vendor:product:...
                            # Chercher si notre produit est dedans
                            if normalized in cfg:
                                parts = cfg.split(':')
                                if len(parts) >= 5:
                                    # parts[3] est le vendor dans cpe:2.3:a:vendor:product
                                    # parts[2] est le vendor dans cpe:/a:vendor:product
                                    idx_vendor = 3 if parts[1] == '2.3' else 2
                                    if len(parts) > idx_vendor:
                                        guessed_vendor = parts[idx_vendor]
                                        found_vendor = True
                                        break
                        if found_vendor:
                            break
                    
                    cpe = build_software_cpe(name, version, guessed_vendor)
                    
                    for cve in results:
                        cve_id = cve.get("id") or cve.get("cve_id") or cve.get("cve")
                        if cve_id:
                            cves_found.append({
                                "source": "cti/service",
                                "cve_id": cve_id,
                                "cvss": extract_cvss_score(cve),
                                "service": service_name,
                                "product": product or search_term,
                                "version": version,
                                "port": svc.get("port"),
                                "cpe": cpe,
                                "search_method": "direct",
                                "description": cve.get("summary", cve.get("description", ""))[:200]
                            })
            continue
        
        search_key = f"{vendor}:{cve_product}"
        if search_key in checked:
            continue
        checked.add(search_key)
        
        cpe = build_software_cpe(search_term, version, vendor)
        
        if search_method == "dynamic":
            print(f"{Colors.BLUE}[*] Recherche CVE pour service {vendor}:{cve_product} (auto-détecté)...{Colors.ENDC}")
        else:
            print(f"{Colors.BLUE}[*] Recherche CVE pour service {vendor}:{cve_product}...{Colors.ENDC}")
        
        results = search_cve_by_cpe(vendor, cve_product, version)
        
        for cve in results:
            cve_id = cve.get("id") or cve.get("cve_id") or cve.get("cve")
            if cve_id:
                cves_found.append({
                    "source": "cti/service",
                    "cve_id": cve_id,
                    "cvss": extract_cvss_score(cve),
                    "service": service_name,
                    "product": product or search_term,
                    "version": version,
                    "port": svc.get("port"),
                    "cpe": cpe,
                    "search_method": search_method,
                    "description": cve.get("summary", cve.get("description", ""))[:200]
                })
    
    return cves_found


def check_os_cves(os_name, os_version):
    """
    @brief Recherche des CVE pour un OS détecté.
    @param os_name Nom de l'OS.
    @param os_version Version optionnelle.
    @return list CVE liées à l'OS.
    """
    if not os_name:
        return []
    
    cves_found = []
    cpe = build_os_cpe(os_name, os_version)
    
    # Mapping OS vers vendor:product
    os_lower = os_name.lower()
    vendor, product = None, None
    
    if 'ubuntu' in os_lower:
        vendor, product = 'canonical', 'ubuntu_linux'
    elif 'debian' in os_lower:
        vendor, product = 'debian', 'debian_linux'
    elif 'centos' in os_lower:
        vendor, product = 'centos', 'centos'
    elif 'red hat' in os_lower or 'rhel' in os_lower:
        vendor, product = 'redhat', 'enterprise_linux'
    elif 'fedora' in os_lower:
        vendor, product = 'fedoraproject', 'fedora'
    elif 'rocky' in os_lower:
        vendor, product = 'rockylinux', 'rocky_linux'
    elif 'alma' in os_lower:
        vendor, product = 'almalinux', 'almalinux'
    elif 'linux' in os_lower:
        vendor, product = 'linux', 'linux_kernel'
    # Ajout du support Windows
    elif 'windows' in os_lower:
        vendor, product = 'microsoft', 'windows'
        # Tenter d'affiner si version connue: windows_10, windows_11, windows_server_2019 etc.
        if '11' in os_lower:
            product = 'windows_11'
        elif '10' in os_lower:
            product = 'windows_10'
        elif 'server' in os_lower:
            if '2022' in os_lower:
                product = 'windows_server_2022'
            elif '2019' in os_lower:
                product = 'windows_server_2019'
            elif '2016' in os_lower:
                product = 'windows_server_2016'
            else:
                product = 'windows_server' # Fallback générique
    
    if vendor and product:
        print(f"{Colors.BLUE}[*] Recherche CVE pour OS {vendor}:{product}...{Colors.ENDC}")
        results = search_cve_by_cpe(vendor, product, os_version)
        
        for cve in results:
            cve_id = cve.get("id") or cve.get("cve_id") or cve.get("cve")
            if cve_id:
                cves_found.append({
                    "source": "cti/os",
                    "cve_id": cve_id,
                    "cvss": extract_cvss_score(cve),
                    "os": os_name,
                    "version": os_version,
                    "cpe": cpe,
                    "description": cve.get("summary", cve.get("description", ""))[:200]
                })
    
    return cves_found


def check_hardware_cves(cpus):
    """
    @brief Recherche des CVE pour les CPU inventoriés.
    @param cpus Liste de dicts CPU (champ "name").
    @return list CVE matérielles trouvées.
    """
    cves_found = []
    checked = set()
    
    for cpu in cpus:
        cpu_name = cpu.get("name", "")
        if not cpu_name:
            continue
        
        cpe = build_hardware_cpe(cpu_name)
        cpu_lower = cpu_name.lower()
        
        # Déterminer le vendor et les termes de recherche
        vendor = None
        search_terms = []
        
        if 'intel' in cpu_lower:
            vendor = 'intel'
            if 'xeon' in cpu_lower:
                search_terms = ['xeon']
            elif 'core' in cpu_lower:
                search_terms = ['core']
            else:
                search_terms = ['microcode', 'processor']
                
        elif 'amd' in cpu_lower or 'ryzen' in cpu_lower or 'epyc' in cpu_lower:
            vendor = 'amd'
            if 'ryzen' in cpu_lower:
                search_terms = ['ryzen']
            elif 'epyc' in cpu_lower:
                search_terms = ['epyc']
            else:
                search_terms = ['processor']
        
        if not vendor:
            continue
        
        for term in search_terms:
            search_key = f"{vendor}:{term}"
            if search_key in checked:
                continue
            checked.add(search_key)
            
            print(f"{Colors.BLUE}[*] Recherche CVE pour CPU {vendor}:{term}...{Colors.ENDC}")
            results = search_cve_by_cpe(vendor, term)
            
            for cve in results[:10]:
                cve_id = cve.get("id") or cve.get("cve_id") or cve.get("cve")
                if cve_id:
                    cves_found.append({
                        "source": "cti/hardware",
                        "cve_id": cve_id,
                        "hardware": cpu_name,
                        "cpe": cpe,
                        "cvss": extract_cvss_score(cve),
                        "description": cve.get("summary", cve.get("description", ""))[:200]
                    })
    
    return cves_found
