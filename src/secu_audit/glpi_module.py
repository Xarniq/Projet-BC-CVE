"""
Module GLPI - Récupération de l'inventaire logiciel.

Ce module interroge l'API REST GLPI pour:
- Trouver un ordinateur par son adresse IP
- Récupérer la liste des logiciels installés
- Récupérer les informations CPU
- Récupérer les informations OS (nom et version)

L'authentification utilise deux tokens:
    - App-Token: Identifie l'application
    - User-Token: Authentifie l'utilisateur (dans initSession)

Workflow:
    1. initSession -> Obtenir Session-Token
    2. Rechercher l'ordinateur par IP
    3. Vérifier l'IP exacte via NetworkPort/NetworkName/IPAddress
    4. Récupérer les logiciels, CPU et OS
    5. killSession

Exemple:
    >>> from glpi_module import get_glpi_inventory
    >>> inventory = get_glpi_inventory("192.168.1.100")
    >>> if inventory:
    ...     print(f"Logiciels: {len(inventory['softwares'])}")
    ...     print(f"OS: {inventory['os']}")
"""
import re
import requests
from .config import GLPI_URL, GLPI_APP_TOKEN, GLPI_USER_TOKEN, Colors


# Session token global (réutilisé pendant l'exécution)
_session_token = None


def init_session():
    """
    @brief Initialise une session GLPI et récupère le session token.
    @return str Session token ou None si l'init échoue.
    """
    global _session_token
    
    if _session_token:
        return _session_token
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"user_token {GLPI_USER_TOKEN}",
        "App-Token": GLPI_APP_TOKEN
    }
    
    try:
        resp = requests.get(
            f"{GLPI_URL}/initSession",
            headers=headers,
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
        _session_token = data.get("session_token")
        
        if _session_token:
            print(f"{Colors.GREEN}[+] Session GLPI initialisée{Colors.ENDC}")
        return _session_token
        
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}[!] Erreur initSession GLPI: {e}{Colors.ENDC}")
        return None


def kill_session():
    """
    @brief Ferme la session GLPI active si présente.
    """
    global _session_token
    
    if not _session_token:
        return
    
    headers = {
        "Content-Type": "application/json",
        "Session-Token": _session_token,
        "App-Token": GLPI_APP_TOKEN
    }
    
    try:
        requests.get(f"{GLPI_URL}/killSession", headers=headers, timeout=5)
    except requests.exceptions.RequestException:
        pass
    
    _session_token = None


def _get_headers():
    """
    @brief Construit les en-têtes GLPI incluant Session-Token.
    @return dict Headers prêts pour l'API GLPI.
    """
    return {
        "Content-Type": "application/json",
        "Session-Token": _session_token,
        "App-Token": GLPI_APP_TOKEN
    }


def _verify_computer_ip(computer_id, target_ip):
    """
    @brief Confirme qu'un ordinateur possède l'IP cible.
    @param computer_id ID de l'ordinateur GLPI.
    @param target_ip IP recherchée.
    @return bool True si l'IP exacte est trouvée via NetworkPort/NetworkName/IPAddress.
    """
    headers = _get_headers()
    
    try:
        # 1. Récupérer les NetworkPorts de l'ordinateur
        resp = requests.get(
            f"{GLPI_URL}/Computer/{computer_id}/NetworkPort",
            headers=headers,
            timeout=10
        )
        
        if resp.status_code != 200:
            return False
        
        ports = resp.json()
        if not ports:
            return False
        
        # 2. Pour chaque port, chercher les NetworkNames
        for port in ports:
            port_id = port.get('id')
            if not port_id:
                continue
            
            # Récupérer les NetworkNames liés au port
            resp = requests.get(
                f"{GLPI_URL}/NetworkPort/{port_id}/NetworkName",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code != 200:
                continue
            
            network_names = resp.json()
            if not network_names:
                continue
            
            # 3. Pour chaque NetworkName, chercher les IPAddresses
            for nn in network_names:
                nn_id = nn.get('id')
                if not nn_id:
                    continue
                
                resp = requests.get(
                    f"{GLPI_URL}/NetworkName/{nn_id}/IPAddress",
                    headers=headers,
                    timeout=10
                )
                
                if resp.status_code != 200:
                    continue
                
                ip_addresses = resp.json()
                if not ip_addresses:
                    continue
                
                # 4. Vérifier si une IP correspond exactement
                for ip_entry in ip_addresses:
                    ip_name = ip_entry.get('name', '')
                    if ip_name == target_ip:
                        return True
        
        return False
        
    except requests.exceptions.RequestException:
        return False


def find_computer_by_ip(ip_address):
    """
    @brief Recherche un ordinateur GLPI correspondant à une IP (Recherche EXACTE uniquement).
    @param ip_address IP cible.
    @return dict Informations ordinateur (id, name, ip) ou None si introuvable.
    """
    if not _session_token:
        if not init_session():
            return None
    
    headers = _get_headers()
    
    # === Stratégie 1: Recherche directe dans la table IPAddress (la plus fiable) ===
    # Remonter IPAddress -> NetworkName -> NetworkPort -> Computer
    computer = _search_in_ip_addresses(ip_address, headers)
    if computer:
        return computer
    
    # === Stratégie 2: Recherche par champ 126 (IP) ===
    params = {
        "criteria[0][field]": "126",
        "criteria[0][searchtype]": "contains",
        "criteria[0][value]": ip_address,
        "forcedisplay[0]": "1",   # ID
        "forcedisplay[1]": "2",   # Nom
        "forcedisplay[2]": "126", # IP
    }
    
    try:
        resp = requests.get(
            f"{GLPI_URL}/search/Computer",
            headers=headers,
            params=params,
            timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get('data', [])
        
        if results:
            for result in results:
                raw_id = result.get('1') or result.get('id')
                raw_name = result.get('2') or 'Unknown'
                
                # Correction d'inversion potentielle ID/Nom (fix pour certains environnements)
                # Si raw_id n'est pas numérique (ex: "PC-ELIAS") et raw_name l'est (ex: "2"), on inverse
                if raw_id and not str(raw_id).isdigit() and raw_name and str(raw_name).isdigit():
                    computer_id = raw_name
                    computer_name = raw_id
                else:
                    computer_id = raw_id
                    computer_name = raw_name

                if not computer_id:
                    continue
                
                # Vérifier d'abord si l'IP du résultat correspond exactement
                result_ip = result.get('126', '')
                
                is_match = False
                if isinstance(result_ip, str):
                     # Le champ peut contenir brute (ex: "192.168.1.1")
                     if result_ip.strip() == ip_address:
                         is_match = True
                     # Ou liste (ex: "192.168.1.1 10.0.0.1")
                     elif ip_address in result_ip.split():
                         is_match = True
                
                if is_match:
                    print(f"{Colors.GREEN}[+] Ordinateur GLPI trouvé (champ 126): {computer_name} (ID: {computer_id}){Colors.ENDC}")
                    return {
                        'id': computer_id,
                        'name': computer_name,
                        'ip': ip_address
                    }
        
        print(f"{Colors.WARNING}[!] Aucun ordinateur trouvé pour IP {ip_address} dans GLPI{Colors.ENDC}")
        return None
        
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}[!] Erreur recherche GLPI: {e}{Colors.ENDC}")
        return None


def _search_in_ip_addresses(ip_address, headers):
    """
    @brief Recherche exacte via IPAddress -> NetworkName -> NetworkPort -> Computer.
    @param ip_address IP à localiser.
    @param headers Headers d'authentification GLPI.
    @return dict Infos ordinateur ou None si rien trouvé.
    """
    try:
        # Chercher l'IP exacte dans la table IPAddress
        params = {
            "criteria[0][field]": "1",  # name (l'IP elle-même)
            "criteria[0][searchtype]": "equals",  # Recherche EXACTE
            "criteria[0][value]": ip_address,
            "forcedisplay[0]": "1",  # ID
            "forcedisplay[1]": "2",  # name
        }
        
        resp = requests.get(
            f"{GLPI_URL}/search/IPAddress",
            headers=headers,
            params=params,
            timeout=15
        )
        
        if resp.status_code != 200:
            print(f"{Colors.WARNING}[!] Recherche IPAddress échouée (HTTP {resp.status_code}){Colors.ENDC}")
            return None
        
        data = resp.json()
        results = data.get('data', [])
        
        if not results:
            # IP non trouvée dans table IPAddress
            return None
        
        # Remonter la chaîne: IPAddress -> NetworkName -> NetworkPort -> Computer
        for ip_result in results:
            ip_id = ip_result.get('1') or ip_result.get('id')
            if not ip_id:
                continue
            
            # Récupérer l'IPAddress pour avoir le NetworkName lié
            resp = requests.get(
                f"{GLPI_URL}/IPAddress/{ip_id}",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code != 200:
                continue
            
            ip_data = resp.json()
            
            # L'IPAddress est liée à un NetworkName via items_id
            nn_id = ip_data.get('items_id')
            if not nn_id:
                continue
            
            # Récupérer le NetworkName pour avoir le NetworkPort lié
            resp = requests.get(
                f"{GLPI_URL}/NetworkName/{nn_id}",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code != 200:
                continue
            
            nn_data = resp.json()
            port_id = nn_data.get('items_id')
            
            if not port_id:
                continue
            
            # Récupérer le NetworkPort pour avoir le Computer lié
            resp = requests.get(
                f"{GLPI_URL}/NetworkPort/{port_id}",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code != 200:
                continue
            
            port_data = resp.json()
            
            # Vérifier que c'est bien un Computer
            if port_data.get('itemtype') != 'Computer':
                continue
            
            computer_id = port_data.get('items_id')
            if not computer_id:
                continue
            
            # Récupérer le nom de l'ordinateur
            resp = requests.get(
                f"{GLPI_URL}/Computer/{computer_id}",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code != 200:
                continue
            
            computer_data = resp.json()
            computer_name = computer_data.get('name', 'Unknown')
            
            print(f"{Colors.GREEN}[+] Ordinateur GLPI trouvé via IPAddress: {computer_name} (ID: {computer_id}){Colors.ENDC}")
            return {
                'id': computer_id,
                'name': computer_name,
                'ip': ip_address
            }
        
        return None
        
    except requests.exceptions.RequestException:
        return None


def get_computer_softwares(computer_id):
    """
    @brief Récupère les logiciels d'un ordinateur GLPI.
    @param computer_id ID de l'ordinateur GLPI.
    @return list Liste de dicts {"name", "version"}.
    """
    if not _session_token:
        return []
    
    headers = _get_headers()
    softwares = []
    
    try:
        # ÉTAPE 0: Découverte dynamique du lien via HATEOAS (plus robuste)
        target_url = None
        
        # print(f"{Colors.BLUE}[*] GLPI: Récupération des métadonnées Computer...{Colors.ENDC}")
        resp_comp = requests.get(
            f"{GLPI_URL}/Computer/{computer_id}",
            headers=headers,
            timeout=10
        )
        
        if resp_comp.status_code == 200:
            comp_data = resp_comp.json()
            
            # L'API GLPI retourne parfois une liste même pour un ID unique
            if isinstance(comp_data, list):
                comp_data = comp_data[0] if comp_data else {}
            
            # Récupérer directement l'ID valide depuis l'objet retourné (plus sûr que le paramètre)
            correct_id = comp_data.get('id')
            if correct_id:
                computer_id = correct_id
                
            links = comp_data.get('links', [])
            
            # Chercher le lien pour les logiciels et forcer l'usage de l'ID dans l'URL
            for link in links:
                rel = link.get('rel', '')
                if rel == 'Item_SoftwareVersion':
                    target_url = f"{GLPI_URL}/Computer/{computer_id}/Item_SoftwareVersion?range=0-100000"
                    print(f"{Colors.GREEN}[+] Endpoint détecté: {rel} (URL forcée avec ID){Colors.ENDC}")
                    break
                elif rel == 'Software':
                    target_url = f"{GLPI_URL}/Computer/{computer_id}/Software?range=0-100000"
                    print(f"{Colors.GREEN}[+] Endpoint détecté: {rel} (URL forcée avec ID){Colors.ENDC}")
                    break
        
        # Si pas trouvé dynamiquement, on utilise les defaults
        if not target_url:
            target_url = f"{GLPI_URL}/Computer/{computer_id}/Item_SoftwareVersion?range=0-999999"

        # ÉTAPE 1: Interrogation
        resp = requests.get(target_url, headers=headers, timeout=15)
        
        # Gestion Fallback manuel si l'URL standard/dynamique échoue
        if resp.status_code == 404 and "Software" not in target_url:
             fallback_url = f"{GLPI_URL}/Computer/{computer_id}/Software?range=0-999999"
             print(f"{Colors.BLUE}[*] Fallback 404 -> Essai {fallback_url}{Colors.ENDC}")
             resp = requests.get(fallback_url, headers=headers, timeout=15)
        
        # Accepter 200 OK et 206 Partial Content (pagination GLPI)
        if resp.status_code not in [200, 206]:
            print(f"{Colors.WARNING}[!] GLPI: Impossible de récupérer les logiciels sur {target_url} (HTTP {resp.status_code}). {Colors.ENDC}")
            return []
        
        # Gestion du contenu partiel
        if resp.status_code == 206:
             total_count = resp.headers.get('X-Total-Count', 'Inconnu')
             content_range = resp.headers.get('Content-Range', 'Inconnu')
             print(f"{Colors.BLUE}[*] GLPI: Réception partielle ({content_range}, Total: {total_count}). Utilisation du lot reçu.{Colors.ENDC}")

        items = resp.json()
        
        # Vérification si la liste est vide (peut arriver si aucun soft n'est inventorié)
        if not items:
            print(f"{Colors.WARNING}[!] GLPI: Aucun logiciel inventorié pour cet ordinateur.{Colors.ENDC}")
            return []
        
        print(f"{Colors.BLUE}[*] GLPI: Récupération des détails pour {len(items)} entrées logicielle(s)...{Colors.ENDC}")

        for item in items:
            # Gestion des différents formats de réponse (Item_SoftwareVersion vs Software)
            sw_version_id = item.get('softwareversions_id')
            software_id = item.get('softwares_id')
            
            # CAS 1: Lien via une version (Standard)
            if sw_version_id:
                # Récupérer les détails de la version
                resp = requests.get(
                    f"{GLPI_URL}/SoftwareVersion/{sw_version_id}",
                    headers=headers,
                    timeout=10
                )
                
                if resp.status_code != 200:
                    continue
                
                version_info = resp.json()
                software_id = version_info.get('softwares_id')
                version_name = version_info.get('name', '')
                
                if software_id:
                    # Récupérer le nom du logiciel
                    resp = requests.get(
                        f"{GLPI_URL}/Software/{software_id}",
                        headers=headers,
                        timeout=10
                    )
                    
                    if resp.status_code == 200:
                        sw_info = resp.json()
                        softwares.append({
                            'name': sw_info.get('name', 'Unknown'),
                            'version': version_name
                        })
            
            # CAS 2: Lien direct vers le logiciel (Fallback sans ID de version explicite)
            elif software_id:
                 resp = requests.get(
                    f"{GLPI_URL}/Software/{software_id}",
                    headers=headers,
                    timeout=10
                 )
                 if resp.status_code == 200:
                     sw_info = resp.json()
                     # Essayer de trouver la version dans les champs de liaison si présente
                     version_name = item.get('version', '') 
                     softwares.append({
                        'name': sw_info.get('name', 'Unknown'),
                        'version': version_name
                     })
            if not sw_version_id:
                continue
            
            # Récupérer les détails de la version
            resp = requests.get(
                f"{GLPI_URL}/SoftwareVersion/{sw_version_id}",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code != 200:
                continue
            
            version_info = resp.json()
            software_id = version_info.get('softwares_id')
            version_name = version_info.get('name', '')
            
            if software_id:
                # Récupérer le nom du logiciel
                resp = requests.get(
                    f"{GLPI_URL}/Software/{software_id}",
                    headers=headers,
                    timeout=10
                )
                
                if resp.status_code == 200:
                    sw_info = resp.json()
                    softwares.append({
                        'name': sw_info.get('name', 'Unknown'),
                        'version': version_name
                    })
        
        print(f"{Colors.BLUE}[*] GLPI: {len(softwares)} logiciel(s) trouvé(s){Colors.ENDC}")
        return softwares
        
    except requests.exceptions.RequestException as e:
        print(f"{Colors.WARNING}[!] Erreur récupération logiciels: {e}{Colors.ENDC}")
        return []


def get_computer_cpus(computer_id):
    """
    @brief Récupère la liste des CPUs d'un ordinateur GLPI.
    @param computer_id ID de l'ordinateur.
    @return list Dicts contenant la désignation CPU.
    """
    if not _session_token:
        return []
    
    headers = _get_headers()
    cpus = []
    
    try:
        resp = requests.get(
            f"{GLPI_URL}/Computer/{computer_id}/Item_DeviceProcessor",
            headers=headers,
            timeout=10
        )
        
        if resp.status_code != 200:
            return []
        
        items = resp.json()
        
        for item in items:
            processor_id = item.get('deviceprocessors_id')
            if not processor_id:
                continue
            
            resp = requests.get(
                f"{GLPI_URL}/DeviceProcessor/{processor_id}",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code == 200:
                cpu_info = resp.json()
                cpus.append({
                    'name': cpu_info.get('designation', 'Unknown CPU')
                })
        
        return cpus
        
    except requests.exceptions.RequestException:
        return []


def _sanitize_os_version(version_str):
    """
    @brief Extrait une version propre depuis une chaîne GLPI.
    @param version_str Chaîne de version brute (ex: "24.04.3 LTS (Noble)").
    @return str Version épurée ou chaîne originale si aucun pattern ne matche.
    """
    if not version_str:
        return ""
    
    version_str = version_str.strip()
    
    # Pattern pour extraire un numéro de version (ex: 24.04.3, 10.0.19045, 22H2)
    # Cherche les patterns communs de version
    patterns = [
        r'^(\d+\.\d+(?:\.\d+)?)',           # 24.04.3, 10.0.19045
        r'^(\d+H\d+)',                        # 22H2 (Windows)
        r'^(\d+(?:\.\d+)*)',                  # Numéro générique
    ]
    
    for pattern in patterns:
        match = re.match(pattern, version_str)
        if match:
            return match.group(1)
    
    # Fallback: prendre tout avant le premier espace ou parenthèse
    clean = re.split(r'[\s(]', version_str)[0]
    return clean if clean else version_str


def get_computer_os(computer_id):
    """
    @brief Récupère le nom et la version d'OS pour un ordinateur.
    @param computer_id ID GLPI de l'ordinateur.
    @return dict {"name", "version"} ou None si non trouvé.
    """
    if not _session_token:
        return None
    
    headers = _get_headers()
    os_info = {'name': '', 'version': ''}
    
    try:
        # Recherche avec les champs OS (45 = nom, 46 = version)
        params = {
            "criteria[0][field]": "2",      # ID du computer
            "criteria[0][searchtype]": "equals",
            "criteria[0][value]": computer_id,
            "forcedisplay[0]": "1",         # ID
            "forcedisplay[1]": "45",        # OS name
            "forcedisplay[2]": "46",        # OS version
        }
        
        resp = requests.get(
            f"{GLPI_URL}/search/Computer",
            headers=headers,
            params=params,
            timeout=15
        )
        
        if resp.status_code == 200:
            data = resp.json()
            results = data.get('data', [])
            
            if results:
                result = results[0]
                os_name = result.get('45', '')
                os_version_raw = result.get('46', '')
                
                os_info['name'] = os_name if os_name else ''
                os_info['version'] = _sanitize_os_version(os_version_raw)
                
                if os_info['name']:
                    print(f"{Colors.BLUE}[*] GLPI OS: {os_info['name']} {os_info['version']}{Colors.ENDC}")
                    return os_info
        
        # Fallback: récupérer directement depuis l'objet Computer
        resp = requests.get(
            f"{GLPI_URL}/Computer/{computer_id}",
            headers=headers,
            timeout=10
        )
        
        if resp.status_code == 200:
            computer_data = resp.json()
            
            # L'API peut retourner une liste ou un dict
            if isinstance(computer_data, list):
                computer_data = computer_data[0] if computer_data else {}
            
            # Essayer de récupérer l'OS via operatingsystems_id
            os_id = computer_data.get('operatingsystems_id')
            if os_id:
                resp = requests.get(
                    f"{GLPI_URL}/OperatingSystem/{os_id}",
                    headers=headers,
                    timeout=10
                )
                if resp.status_code == 200:
                    os_data = resp.json()
                    if isinstance(os_data, list):
                        os_data = os_data[0] if os_data else {}
                    os_info['name'] = os_data.get('name', '')
            
            # Récupérer la version via operatingsystemversions_id
            osv_id = computer_data.get('operatingsystemversions_id')
            if osv_id:
                resp = requests.get(
                    f"{GLPI_URL}/OperatingSystemVersion/{osv_id}",
                    headers=headers,
                    timeout=10
                )
                if resp.status_code == 200:
                    osv_data = resp.json()
                    if isinstance(osv_data, list):
                        osv_data = osv_data[0] if osv_data else {}
                    os_info['version'] = _sanitize_os_version(osv_data.get('name', ''))
            
            if os_info['name']:
                print(f"{Colors.BLUE}[*] GLPI OS (fallback): {os_info['name']} {os_info['version']}{Colors.ENDC}")
                return os_info
        
        return None
        
    except requests.exceptions.RequestException as e:
        print(f"{Colors.WARNING}[!] Erreur récupération OS: {e}{Colors.ENDC}")
        return None


def get_glpi_inventory(ip_address):
    """
    @brief Récupère l'inventaire GLPI complet pour une IP.
    @param ip_address Adresse IP à inventorier.
    @return dict Inventaire (computer, softwares, cpus, os) ou None si non trouvé.
    """
    # Initialiser la session si nécessaire
    if not init_session():
        return None
    
    # Trouver l'ordinateur
    computer = find_computer_by_ip(ip_address)
    if not computer:
        return None
    
    # Récupérer l'inventaire
    softwares = get_computer_softwares(computer['id'])
    cpus = get_computer_cpus(computer['id'])
    os_info = get_computer_os(computer['id'])
    
    return {
        'computer': computer,
        'softwares': softwares,
        'cpus': cpus,
        'os': os_info
    }
