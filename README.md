# 🛡️ Audit Hybride - Scanner de Vulnérabilités

Outil d'audit de sécurité combinant **Nmap**, **GLPI** et **CVE-Search** pour détecter les vulnérabilités sur vos machines et réseaux.

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Structure du projet](#-structure-du-projet)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Utilisation](#-utilisation)
- [Dashboard Web](#-dashboard-web)
- [Exemples](#-exemples)

---

## ✨ Fonctionnalités

- **Scan réseau Nmap** : Détection des services, versions et OS
- **Inventaire GLPI** : Récupération des logiciels installés via FusionInventory
- **Recherche CVE** : Corrélation avec la base CVE-Search locale
- **Support CIDR** : Scan de plages réseau entières (ex: 192.168.1.0/24)
- **Dashboard HTML** : Visualisation interactive des résultats
- **Rapports JSON** : Export structuré pour intégration

---

## 📂 Structure du projet

```
secu-audit/
├── src/                          # Code source
│   └── secu_audit/               # Package Python principal
│       ├── __init__.py           # Exports du package
│       ├── config.py             # Configuration centrale
│       ├── nmap_module.py        # Scan réseau Nmap
│       ├── glpi_module.py        # Intégration API GLPI
│       ├── cti_module.py         # Recherche CVE via CTI
│       └── utils.py              # Fonctions utilitaires
├── data/                         # Données générées
│   ├── reports/                  # Rapports JSON d'audit
│   └── scans/                    # Fichiers XML Nmap
├── tests/                        # Tests unitaires
├── docs/                         # Documentation
│   └── doxygen/                  # Documentation Doxygen générée
├── web/                          # Interface web
│   ├── web-server.py             # Serveur Python pour le dashboard
│   └── shadcn-dashboard/         # Dashboard React/Vite avec Shadcn UI
│       ├── src/                  # Code source React
│       ├── package.json          # Dépendances Node.js
│       └── vite.config.ts        # Configuration Vite
├── docker/                       # Stacks Docker
│   ├── cve_search-docker-compose.yml
│   └── glpi-docker-compose.yml
├── main.py                       # Point d'entrée CLI
├── pyproject.toml                # Configuration projet (PEP 517)
├── Makefile                      # Commandes utiles
├── requirements.txt              # Dépendances Python
├── .env.example                  # Template de configuration
└── README.md                     # Ce fichier
```

---

## 📦 Prérequis

### Logiciels requis

| Composant | Version | Description |
|-----------|---------|-------------|
| Python | 3.8+ | Langage principal |
| Nmap | 7.x+ | Scanner réseau |
| Docker | 20.x+ | Pour CVE-Search et GLPI |
| Node.js | 18.x+ | Pour le dashboard web (optionnel) |
| GLPI | 10.x | Inventaire IT |
| FusionInventory | - | Agent d'inventaire |

### Services requis (Docker)

1. **CVE-Search-Docker** : Base de données CVE locale
2. **GLPI + MariaDB** : Gestion d'inventaire
3. **FusionInventory Agent** : Sur les machines à inventorier

---

## 🚀 Installation

### 1. Cloner et installer les dépendances Python

```bash
git clone https://github.com/egarach/secu-audit.git
cd secu-audit
pip install -r requirements.txt

# Ou avec les dépendances de développement
pip install -e ".[dev]"
```

### 2. Installer Nmap avec le script vulners

```bash
# Fedora/RHEL
sudo dnf install nmap nmap-scripts

# Debian/Ubuntu  
sudo apt install nmap
```

### 3. Démarrer les services Docker (CVE-Search + GLPI)

Des compose prêts à l'emploi sont fournis dans le dossier `docker/` :

- [docker/cve_search-docker-compose.yml](docker/cve_search-docker-compose.yml)
- [docker/glpi-docker-compose.yml](docker/glpi-docker-compose.yml)

```bash
# Depuis la racine du projet
cd docker

# Lancer la stack CVE-Search
docker compose -f cve_search-docker-compose.yml up -d

# Lancer la stack GLPI (MariaDB incluse)
docker compose -f glpi-docker-compose.yml up -d

# Attendre ~10 min pour le chargement initial des CVE
```

### 4. Configurer GLPI avec FusionInventory

Voir [GLPI Documentation](https://help.glpi-project.org/documentation/fr)
Voir [FusionInventory Documentation](https://documentation.fusioninventory.org/)

---

## ⚙️ Configuration

### Fichier `.env`

Créez un fichier `.env` à la racine du projet :

```env
# API GLPI
GLPI_API_URL=http://192.168.181.143/apirest.php
GLPI_APP_TOKEN=votre_app_token_glpi
GLPI_USER_TOKEN=votre_user_token_glpi

# API CVE-Search
CTI_API_URL=http://localhost:5000/api

# IP cible par défaut (optionnel)
IP_TARGET=192.168.1.100
```

### Obtenir les tokens GLPI

1. **App-Token** : Configuration > Générale > API > Ajouter un client API
2. **User-Token** : Préférences utilisateur > Accès distant > Regénérer

---

## 💻 Utilisation

### Scan d'une IP unique

```bash
sudo python main.py 192.168.1.100

# Ou avec le Makefile
make scan IP=192.168.1.100
```

### Scan d'une plage réseau (CIDR)

```bash
# Scanner tout un /24 (254 hôtes max)
sudo python main.py 192.168.1.0/24

# Ou avec le Makefile
make scan-network CIDR=192.168.1.0/24
```

### Utilisation avec variable d'environnement

```bash
# Utilise IP_TARGET du fichier .env
sudo python main.py

# Ou avec le Makefile
make run
```

### Commandes Makefile disponibles

```bash
make help          # Affiche toutes les commandes
make install       # Installe les dépendances
make test          # Lance les tests unitaires
make lint          # Vérifie le code
make clean         # Nettoie les fichiers temporaires
```

### Fichiers générés

| Fichier | Description |
|---------|-------------|
| `data/reports/audit_<IP>.json` | Rapport détaillé par machine |
| `data/reports/network_audit_<timestamp>.json` | Rapport consolidé (mode réseau) |
| `data/scans/nmap_scan.xml` | Sortie brute Nmap |

---

## 🌐 Dashboard Web

Le projet inclut un dashboard moderne construit avec **React**, **Vite** et **Shadcn UI**.

### Option 1 : Utiliser l'instance hébergée

Accédez directement à **https://cyber.sumbo.fr** pour glisser-déposer vos rapports `audit_*.json` sans installation.

### Option 2 : Lancer le dashboard localement

```bash
# Se placer dans le dossier du dashboard
cd web/shadcn-dashboard

# Installer les dépendances Node.js
npm install

# Lancer le serveur de développement
npm run dev
```

Puis ouvrir `http://localhost:5173` dans votre navigateur.

### Option 3 : Serveur Python simple (pour les rapports JSON uniquement)

```bash
# Depuis la racine du projet
python3 web/web-server.py
```

### Fonctionnalités du dashboard

- **Vue résumé** : IP, OS, nombre de CVE
- **Onglet Services** : Ports ouverts et leurs CVE
- **Onglet Logiciels** : Softwares vulnérables
- **Onglet Hardware** : CPU et composants
- **Onglet OS** : Vulnérabilités système
- **Liens NVD** : Clic sur une CVE ouvre la page officielle

---

## 📝 Exemples

### Exemple 1 : Audit simple

```bash
$ sudo python main.py 192.168.181.137

============================================================
       AUDIT HYBRIDE - Nmap + GLPI + CTI
============================================================
Cible: 192.168.181.137

[ÉTAPE 1/4] Scan Nmap...
[+] Scan Nmap terminé
[+] 12 CVE depuis Nmap/Vulners

[ÉTAPE 2/4] Récupération inventaire GLPI...
[+] Session GLPI initialisée
[+] Ordinateur trouvé: serveur (ID: 5)
[+] 744 logiciels récupérés

[ÉTAPE 3/4] Recherche CVE services...
[+] 45 CVE depuis services

[ÉTAPE 4/4] Recherche CVE logiciels...
[+] 350 CVE depuis logiciels GLPI

Total: 434 CVE uniques trouvées
[+] Rapport JSON sauvegardé: audit_192.168.181.137.json
```

### Exemple 2 : Scan réseau

```bash
$ sudo python main.py 192.168.181.0/24

============================================================
       AUDIT RÉSEAU - Mode Plage CIDR
============================================================
Cible: 192.168.181.0/24
[*] Plage: 192.168.181.0 - 192.168.181.255
[*] Nombre d'hôtes potentiels: 254

[ÉTAPE 1] Découverte des hôtes actifs...
[+] 3 hôtes actifs découverts
    • 192.168.181.1
    • 192.168.181.137
    • 192.168.181.143

[ÉTAPE 2] Audit détaillé de chaque hôte...
--- Hôte 1/3: 192.168.181.1 ---
...

[ÉTAPE 3] Génération du rapport consolidé...
============================================================
       RAPPORT CONSOLIDÉ - 192.168.181.0/24
============================================================
Hôtes scannés: 3
CVE totales: 512
Services détectés: 15

Top 5 hôtes les plus vulnérables:
  • 192.168.181.137 (serveur): 434 CVE
  • 192.168.181.143 (glpi): 65 CVE
  • 192.168.181.1 (routeur): 13 CVE

[+] Rapport consolidé: audit_network_192.168.181.0_24.json
```

---

## 🔧 Dépannage

### Erreur "Nmap n'est pas installé"
```bash
sudo dnf install nmap  # ou apt install nmap
```

### Erreur "Session GLPI"
- Vérifier les tokens dans `.env`
- Vérifier que l'API est activée dans GLPI

### Pas de CVE trouvées
- Vérifier que CVE-Search-Docker est lancé : `docker ps`
- Attendre le chargement initial (~10min)

### Permission denied (scan Nmap)
Le scan SYN (-sS) nécessite les droits root :
```bash
sudo python main.py <IP>
```

---

## 📄 Licence

MIT License - Voir fichier LICENSE

---
