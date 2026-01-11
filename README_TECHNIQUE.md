# 📖 Documentation Technique - Audit Hybride

Documentation technique détaillée pour comprendre l'architecture et le fonctionnement du code.

## 📋 Table des matières

- [Architecture des fichiers](#-architecture-des-fichiers)
- [Stacks Docker fournies](#-stacks-docker-fournies)
- [Dashboard / visualisation](#-dashboard--visualisation)
- [Flux d'exécution](#-flux-dexécution)
- [Description des modules](#-description-des-modules)
- [Structure des données](#-structure-des-données)
- [APIs externes](#-apis-externes)
- [Tests et debug](#-tests-et-debug)
- [Sécurité](#-sécurité)
- [Performances](#-performances)

---

## 📁 Architecture des fichiers

```
secu-audit/
├── src/                          # Code source
│   ├── __init__.py
│   └── secu_audit/               # Package principal
│       ├── __init__.py           # Exports publics
│       ├── config.py             # Configuration et constantes
│       ├── nmap_module.py        # Module scan Nmap
│       ├── glpi_module.py        # Module API GLPI
│       ├── cti_module.py         # Module recherche CVE
│       └── utils.py              # Fonctions utilitaires
├── data/                         # Données générées
│   ├── reports/                  # Rapports JSON
│   └── scans/                    # Fichiers XML Nmap
├── tests/                        # Tests unitaires
├── docs/                         # Documentation
│   └── doxygen/                  # Documentation Doxygen générée
│       ├── html/                 # Pages HTML
│       └── latex/                # Export LaTeX
├── web/                          # Interface web
│   ├── web-server.py             # Serveur Python
│   └── shadcn-dashboard/         # Dashboard React/Vite
│       ├── src/                  # Code source React
│       ├── package.json          # Dépendances Node.js
│       └── vite.config.ts        # Configuration Vite
├── docker/                       # Stacks Docker (CVE-Search, GLPI)
│   ├── cve_search-docker-compose.yml
│   └── glpi-docker-compose.yml
├── main.py                       # Point d'entrée CLI
├── pyproject.toml                # Configuration projet
├── Makefile                      # Commandes utiles
├── requirements.txt              # Dépendances Python
├── .env                          # Variables d'environnement (secrets)
└── .env.example                  # Template de configuration
```

---

## 🐳 Stacks Docker fournies

Deux stacks Docker sont fournies dans le dossier `docker/` :

| Fichier | Description |
|---------|-------------|
| `cve_search-docker-compose.yml` | API CVE-Search + Redis + MongoDB |
| `glpi-docker-compose.yml` | GLPI + base MariaDB prête pour FusionInventory |

### Démarrage des services

```bash
cd docker
docker compose -f cve_search-docker-compose.yml up -d
docker compose -f glpi-docker-compose.yml up -d
```

> ⏳ Attendre quelques minutes pour le chargement initial de la base CVE.

---

## 🌐 Dashboard / visualisation

Le projet inclut un dashboard moderne construit avec **React**, **Vite** et **Shadcn UI** dans `web/shadcn-dashboard/`.

### Lancement local

```bash
cd web/shadcn-dashboard
npm install
npm run dev
```

### Instance hébergée

Utilisez **https://cyber.sumbo.fr** pour glisser-déposer vos rapports `audit_*.json` sans installation locale.

### Fonctionnalités

- Import par drag & drop des fichiers JSON
- Vue consolidée multi-hôtes
- Filtrage par sévérité CVSS
- Liens directs vers NVD pour chaque CVE

---

## 🔄 Flux d'exécution

```
┌─────────────────┐
│   main.py       │
│   (Entry Point) │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  1. Parse arguments (IP ou CIDR)                    │
│  2. Si CIDR: discover_active_hosts() puis boucle   │
│  3. Pour chaque IP: audit_single_host()            │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  nmap_module    │────▶│   glpi_module    │────▶│   cti_module    │
│  - run_scan()   │     │  - get_inventory │     │  - check_cves() │
│  - parse_xml()  │     │  - get_softwares │     │  - query_api()  │
└────────┬────────┘     └────────┬─────────┘     └────────┬────────┘
         │                       │                        │
         └───────────────────────┼────────────────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │  Merge & Deduplicate   │
                    │  CVEs                  │
                    └────────────┬───────────┘
                                 │
                    ┌────────────▼───────────┐
                    │  save_report()         │
                    │  -> data/reports/      │
                    └────────────────────────┘
```

---

## 📝 Description des modules

### 1. `main.py` - Orchestrateur principal

**Fonctions clés :**

```python
def main():
    """
    Point d'entrée. Parse les arguments et dispatch:
    - IP simple -> audit_single_host()
    - CIDR -> audit_network_range()
    """

def audit_network_range(cidr_target):
    """
    Mode scan réseau:
    1. Valide le CIDR avec ipaddress.ip_network()
    2. Découvre les hôtes actifs (nmap -sn)
    3. Boucle sur chaque hôte pour audit complet
    4. Génère rapport consolidé
    
    Args:
        cidr_target: str - Ex: "192.168.1.0/24"
    """

def discover_active_hosts(cidr_target):
    """
    Scan de découverte rapide (ping scan).
    
    Commande Nmap: nmap -sn --min-rate 500 -oX discovery.xml <cidr>
    
    Returns:
        list[str]: Liste des IPs actives
    """

def audit_single_host(target_ip, generate_console_report=True):
    """
    Audit complet d'une machine:
    1. Scan Nmap (ports, services, OS, vulners)
    2. Récup GLPI (softwares, CPU, OS)
    3. Recherche CVE (CTI)
    4. Génération rapport
    
    Args:
        target_ip: str - Adresse IP cible
        generate_console_report: bool - Afficher en console
    
    Returns:
        dict: Données pour consolidation
    """

def merge_and_deduplicate_cves(all_cves):
    """
    Fusionne les CVE de différentes sources.
    Utilise un dict avec cve_id comme clé pour dédupliquer.
    Conserve toutes les sources pour traçabilité.
    
    Returns:
        list[dict]: CVE uniques avec sources multiples
    """

def save_json_report(target_ip, nmap_data, glpi_data, all_cves):
    """
    Structure le rapport JSON par catégorie:
    - services: ports avec leurs CVE
    - softwares_with_cves: logiciels vulnérables uniquement
    - hardware: CPU/composants avec CVE
    - machine.os_cves: CVE liées à l'OS
    
    Output: audit_<IP>.json
    """
```

---

### 2. `config.py` - Configuration

```python
"""
Variables d'environnement chargées depuis .env:
- GLPI_API_URL: URL de l'API GLPI
- GLPI_APP_TOKEN: Token application
- GLPI_USER_TOKEN: Token utilisateur
- CTI_API_URL: URL CVE-Search API
- IP_TARGET: IP cible par défaut

Constantes:
- PROJECT_ROOT: Chemin racine du projet
- DATA_DIR: Dossier data/
- SCANS_DIR: Dossier data/scans/
- REPORTS_DIR: Dossier data/reports/
- NMAP_OUTPUT: Chemin fichier XML Nmap
- REPORT_OUTPUT: Chemin rapport JSON
- Colors: Codes ANSI pour affichage console
"""

class Colors:
    """Codes couleur ANSI pour terminal"""
    HEADER = '\033[95m'   # Magenta
    BOLD = '\033[1m'      # Gras
    BLUE = '\033[94m'     # Bleu info
    GREEN = '\033[92m'    # Vert succès
    WARNING = '\033[93m'  # Jaune warning
    FAIL = '\033[91m'     # Rouge erreur
    ENDC = '\033[0m'      # Reset
```

---

### 3. `nmap_module.py` - Scanner réseau

```python
def run_nmap_scan(target_ip):
    """
    Exécute le scan Nmap.
    
    Commande: nmap -sS -sV -O --min-rate 1000 --script=vulners -oX nmap_final.xml <ip>
    
    Options:
        -sS: Scan SYN (stealth, nécessite root)
        -sV: Détection versions services
        -O: Détection OS
        --script=vulners: Script NSE pour CVE
        --min-rate 1000: Vitesse minimum
    
    Returns:
        bool: True si succès
    """

def parse_nmap_results():
    """
    Parse le fichier XML Nmap.
    
    Extrait:
        - services: port, protocol, service, product, version
        - os_guess: Meilleur match OS
        - os_accuracy: Précision en %
        - cves: CVE du script vulners (regex CVE-\d{4}-\d+)
    
    Returns:
        dict: Résultats structurés
    """
```

---

### 4. `glpi_module.py` - Inventaire GLPI

```python
class GLPIClient:
    """
    Client pour l'API REST GLPI.
    
    Workflow:
        1. init_session() - Obtient session_token
        2. find_computer_by_ip() - Recherche par IP (champ 126)
        3. get_inventory() - Récupère OS, CPU, logiciels
    """
    
    def init_session(self):
        """
        GET /initSession avec Authorization: user_token <token>
        Stocke session_token dans headers
        """
    
    def find_computer_by_ip(self, ip_address):
        """
        GET /search/Computer avec critère sur champ 126 (IP)
        
        Params:
            criteria[0][field]: 126
            criteria[0][searchtype]: contains
            criteria[0][value]: <ip>
        
        Returns:
            int: Computer ID ou None
        """
    
    def get_inventory(self, computer_id):
        """
        GET /Computer/<id>?with_softwares=true&expand_dropdowns=true
        
        Parse _softwares et appelle get_software_name() pour chaque
        logiciel dont softwares_id est numérique.
        
        Returns:
            dict: {computer_name, os, os_version, cpus, softwares}
        """
    
    def get_software_name(self, software_id):
        """
        GET /Software/<id>
        Récupère le vrai nom du logiciel (pas l'ID)
        """

def glpi_get_full_inventory(target_ip):
    """
    Fonction wrapper pour récupérer l'inventaire complet.
    Instancie GLPIClient, init session, cherche computer, get inventory.
    """
```

---

### 5. `cti_module.py` - Recherche CVE

```python
def query_cves(regex_pattern, limit=50):
    """
    Recherche CVE via POST /api/query.
    
    Payload:
        {
            "retrieve": "cves",
            "dict_filter": {
                "vulnerable_product": {"$regex": "<pattern>", "$options": "i"}
            },
            "limit": 50,
            "sort": "cvss3",
            "sort_dir": "DESC"
        }
    
    Utilise un cache (_cve_cache) pour éviter requêtes répétées.
    
    Returns:
        list[dict]: CVE trouvées
    """

def search_cve_by_cpe(vendor, product, version=None):
    """
    Construit regex vendor.*product et appelle query_cves()
    
    Ex: "apache.*http_server" pour Apache HTTP Server
    """

def check_software_cves(softwares):
    """
    Pour chaque logiciel, cherche dans known_mappings.
    
    known_mappings = {
        'apache2': ('apache', 'http_server'),
        'openssh': ('openbsd', 'openssh'),
        'nginx': ('nginx', 'nginx'),
        ...
    }
    
    Si match trouvé, appelle search_cve_by_cpe()
    
    Returns:
        list[dict]: CVE avec context {source, cve_id, software, version, cpe}
    """

def check_service_cves(services):
    """
    Pour chaque service Nmap, extrait product/version.
    Cherche dans service_mappings pour vendor:product.
    
    Returns:
        list[dict]: CVE avec context {source, cve_id, service, port, product}
    """

def check_hardware_cves(cpus):
    """
    Recherche CVE pour le matériel (CPU principalement).
    
    Détecte le vendor (intel/amd) et construit le pattern.
    Ex: "amd:ryzen" pour AMD Ryzen
    """

def check_os_cves(os_name, os_version):
    """
    Recherche CVE pour l'OS.
    Utilise os_mappings pour le pattern regex.
    
    os_mappings = {
        'debian': 'debian:debian_linux',
        'ubuntu': 'canonical:ubuntu_linux',
        ...
    }
    """
```

---

### 6. `utils.py` - Utilitaires

```python
def is_numeric_id(value):
    """Vérifie si value est un ID numérique (int, float, ou str digit)"""

def pick_label(value):
    """
    Extrait un label lisible d'une valeur GLPI polymorphe.
    Gère: str, dict (cherche name/completename/label), int
    """

def normalize_name(name):
    """
    Normalise pour comparaison fuzzy:
    - Lowercase
    - Retire les numéros de version
    - Retire mots communs (server, daemon, etc.)
    """

def sanitize_cpe_token(token):
    """
    Nettoie un token pour format CPE:
    - Lowercase
    - Remplace caractères spéciaux par _
    - Retire _ multiples
    """

def build_software_cpe(name, version, vendor=None):
    """
    Construit un CPE 2.3 pour logiciel:
    cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
    """

def build_os_cpe(os_name, version=None):
    """Construit CPE pour OS"""

def build_hardware_cpe(hw_name):
    """Construit CPE pour hardware"""
```

---

## 📊 Structure des données

### Rapport JSON (`data/reports/audit_<IP>.json`)

```json
{
  "target": "192.168.1.100",
  "date": "2024-12-25T14:30:00",
  "summary": {
    "total_unique_cves": 434,
    "cves_from_services": 45,
    "cves_from_softwares": 350,
    "cves_from_hardware": 27,
    "cves_from_os": 12,
    "total_services": 8,
    "total_softwares": 744
  },
  "machine": {
    "name": "serveur",
    "os_glpi": "Debian GNU/Linux",
    "os_version": "12.8",
    "os_nmap": "Linux 5.x",
    "os_accuracy": "95",
    "os_cves": [...]
  },
  "services": [
    {
      "port": "22",
      "protocol": "tcp",
      "service": "ssh",
      "product": "OpenSSH",
      "version": "9.2p1",
      "cves": [
        {
          "cve_id": "CVE-2023-51385",
          "source": "cti/service",
          "cvss": 6.5,
          "description": "...",
          "cpe": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*"
        }
      ]
    }
  ],
  "hardware": [
    {
      "type": "cpu",
      "name": "AMD Ryzen 7 5700X",
      "frequency": 3400,
      "cves": [...]
    }
  ],
  "softwares_with_cves": [
    {
      "name": "apache2",
      "version": "2.4.57",
      "cve_count": 45,
      "cves": [...]
    }
  ],
  "all_softwares_count": 744
}
```

### Rapport réseau (`data/reports/network_audit_<timestamp>.json`)

```json
{
  "network_range": "192.168.1.0/24",
  "timestamp": "2024-12-25T14:30:00",
  "hosts_scanned": 3,
  "network_summary": {
    "total_hosts": 3,
    "total_cves": 512,
    "total_services": 15,
    "hosts_with_cves": 2
  },
  "hosts": [
    {
      "ip": "192.168.1.100",
      "machine_name": "serveur",
      "os": "Linux 5.x",
      "services_count": 8,
      "cve_count": 434,
      "report_file": "audit_192.168.1.100.json"
    }
  ]
}
```

---

## 🔌 APIs externes

### API GLPI

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/initSession` | GET | Obtenir session token |
| `/search/Computer` | GET | Rechercher par critères |
| `/Computer/{id}` | GET | Détails ordinateur |
| `/Software/{id}` | GET | Nom du logiciel |
| `/SoftwareVersion/{id}` | GET | Version du logiciel |

### API CVE-Search

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/query` | POST | Recherche avec filtres MongoDB |
| `/api/browse/{vendor}` | GET | Lister produits d'un vendor |
| `/api/cve/{cve_id}` | GET | Détails d'une CVE |

**Payload query (POST /api/query):**
```json
{
  "retrieve": "cves",
  "dict_filter": {
    "vulnerable_product": {"$regex": "apache.*http_server", "$options": "i"}
  },
  "limit": 50,
  "sort": "cvss3",
  "sort_dir": "DESC"
}
```

**Mise à jour de la base CVE-Search :**

La base de données CVE doit être mise à jour régulièrement pour inclure les dernières vulnérabilités. Pour forcer une mise à jour :

```bash
# Récupérer l'ID du conteneur CVE-Search
docker ps | grep cve-search

# Forcer la mise à jour de la base de données
docker exec -it <id_conteneur_cve_search> python3 /app/sbin/db_updater.py -f
```

> ⚠️ **Note** : La mise à jour peut prendre plusieurs minutes selon la connexion internet. Il est recommandé de planifier cette tâche en cron (ex: hebdomadaire).

---

## 🧪 Tests et debug

### Mode verbose

Ajouter des prints de debug dans les modules :

```python
# Dans cti_module.py
print(f"DEBUG: Searching CVE for {vendor}:{product}")
print(f"DEBUG: Regex pattern: {regex_pattern}")
print(f"DEBUG: Found {len(cves)} CVEs")
```

### Tester l'API CVE-Search

```bash
curl -X POST http://localhost:5000/api/query \
  -H "Content-Type: application/json" \
  -d '{"retrieve":"cves","dict_filter":{"vulnerable_product":{"$regex":"apache.*http_server"}},"limit":5}'
```

### Tester l'API GLPI

```bash
# Init session
curl -X GET "http://192.168.181.143/apirest.php/initSession" \
  -H "App-Token: <token>" \
  -H "Authorization: user_token <token>"

# Search computer
curl -X GET "http://192.168.181.143/apirest.php/search/Computer?criteria[0][field]=126&criteria[0][value]=192.168.181.137" \
  -H "App-Token: <token>" \
  -H "Session-Token: <session>"
```

---

## 🔒 Sécurité

### Permissions requises

- **Root/sudo** : Nécessaire pour scan Nmap SYN (-sS)
- **Tokens GLPI** : Stocker dans `.env`, ne pas commiter

### Fichier .gitignore

Le projet inclut un `.gitignore` complet. Éléments clés :

```gitignore
# Secrets
.env

# Données générées
data/reports/*.json
data/scans/*.xml

# Python
__pycache__/
*.pyc
*.egg-info/
.venv/
```

---

## 📈 Performances

### Optimisations implémentées

1. **Cache CVE** : `_cve_cache` évite requêtes répétées
2. **Cache GLPI** : `software_name_cache` pour noms logiciels
3. **Scan rapide** : `--min-rate 1000` pour Nmap
4. **Découverte CIDR** : `nmap -sn` avant scan complet

### Temps d'exécution typiques

| Opération | Durée |
|-----------|-------|
| Scan IP unique | 30s - 2min |
| Découverte /24 | 10-30s |
| Scan /24 complet | 5-15min |
| Recherche CVE (par logiciel) | 200-500ms |

---

## 🔄 Évolutions futures

- [ ] Support parallèle pour scan CIDR (ThreadPoolExecutor)
- [ ] Export PDF du rapport
- [ ] Intégration CVSS scoring local
- [ ] Support Shodan/Censys pour OSINT
- [ ] Dashboard avec graphiques (Chart.js)
- [ ] Alertes email pour CVE critiques

---

## 🛠️ Commandes Makefile

Le projet inclut un `Makefile` pour simplifier les tâches courantes :

```bash
make help          # Affiche l'aide
make install       # Installe les dépendances
make install-dev   # Installe les dépendances dev
make test          # Lance les tests
make test-cov      # Tests avec couverture
make lint          # Vérifie le code (flake8)
make format        # Formate le code (black)
make clean         # Nettoie les fichiers temporaires
make run           # Lance l'audit sur IP par défaut
make scan IP=x.x.x.x        # Audit d'une IP
make scan-network CIDR=x.x.x.x/24  # Audit réseau
```
