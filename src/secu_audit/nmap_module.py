"""
Module Nmap - Scan réseau et parsing des résultats.

Ce module gère l'interaction avec Nmap pour:
- Exécuter des scans de ports et services
- Détecter l'OS de la cible
- Extraire les CVE via le script vulners
- Extraire les CPE fournis par Nmap
- Parser les résultats XML

Prérequis:
    - Nmap installé (avec nmap-scripts pour vulners)
    - Droits root pour le scan SYN (-sS)

Le script vulners.nse utilise l'API vulners.com pour:
1. Chercher les CVE par CPE (prioritaire)
2. Fallback sur product+version si pas de résultats

Exemple:
    >>> from nmap_module import run_nmap_scan, parse_nmap_results
    >>> if run_nmap_scan("192.168.1.100"):
    ...     results = parse_nmap_results()
    ...     print(f"Services: {len(results['services'])}")
"""
import subprocess
import xml.etree.ElementTree as ET
import re
from .config import NMAP_OUTPUT, Colors


def run_nmap_scan(target_ip):
    """
    @brief Exécute Nmap (services, OS, script vulners) et écrit l'XML.
    @param target_ip Adresse IP cible.
    @return bool True si le scan se termine sans erreur.
    """
    print(f"\n{Colors.HEADER}[*] Lancement du scan Nmap sur {target_ip}...{Colors.ENDC}")
    
    cmd = [
        "nmap", "-sS", "-sV", "-O", "-Pn",
        "--min-rate", "1000",
        "--script=vulners",
        "-oX", NMAP_OUTPUT,
        target_ip
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"{Colors.GREEN}[+] Scan Nmap terminé{Colors.ENDC}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] Erreur Nmap: {e}{Colors.ENDC}")
        return False
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] Nmap n'est pas installé{Colors.ENDC}")
        return False


def parse_nmap_results(xml_file=None):
    """
    @brief Parse l'XML Nmap et structure services, OS et CVE vulners.
    @param xml_file Chemin du fichier XML (défaut: sortie Nmap).
    @return dict Résultats normalisés (services, os_guess, os_accuracy, os_cpe, cves).
    """
    xml_file = xml_file or NMAP_OUTPUT
    
    results = {
        'services': [],
        'os_guess': None,
        'os_accuracy': None,
        'os_cpe': None,
        'cves': []
    }
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except (FileNotFoundError, ET.ParseError) as e:
        print(f"{Colors.WARNING}[!] Impossible de lire {xml_file}: {e}{Colors.ENDC}")
        return results
    
    for host in root.findall(".//host"):
        # Parser les services/ports
        for port in host.findall(".//port"):
            service = port.find("service")
            state = port.find("state")
            
            if state is not None and state.get("state") == "open":
                # Extraire les CPE du service
                cpes = []
                if service is not None:
                    for cpe_elem in service.findall("cpe"):
                        if cpe_elem.text:
                            cpes.append(cpe_elem.text)
                
                svc_info = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else "unknown",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                    "extrainfo": service.get("extrainfo", "") if service is not None else "",
                    "cpes": cpes,  # CPE fournis par Nmap
                }
                results['services'].append(svc_info)
                
                # Parser les CVE du script vulners (format XML structuré)
                for script in port.findall(".//script[@id='vulners']"):
                    # Parser les tables XML du script vulners
                    for table in script.findall(".//table"):
                        cpe_key = table.get("key", "")
                        
                        for vuln_table in table.findall("table"):
                            vuln_id = None
                            vuln_cvss = None
                            vuln_type = None
                            is_exploit = False
                            
                            for elem in vuln_table.findall("elem"):
                                key = elem.get("key")
                                if key == "id":
                                    vuln_id = elem.text
                                elif key == "cvss":
                                    try:
                                        vuln_cvss = float(elem.text) if elem.text else None
                                    except ValueError:
                                        vuln_cvss = None
                                elif key == "type":
                                    vuln_type = elem.text
                                elif key == "is_exploit":
                                    is_exploit = elem.text == "true"
                            
                            # Filtrer pour garder seulement les CVE
                            if vuln_id and vuln_id.startswith("CVE-"):
                                results['cves'].append({
                                    "source": "nmap/vulners",
                                    "cve_id": vuln_id,
                                    "cvss": vuln_cvss,
                                    "type": vuln_type,
                                    "is_exploit": is_exploit,
                                    "cpe": cpe_key,
                                    "service": svc_info['service'],
                                    "port": svc_info['port'],
                                    "product": svc_info['product'],
                                    "version": svc_info['version']
                                })
                    
                    # Fallback: parser aussi l'output texte pour les CVE manquées
                    output = script.get("output", "")
                    existing_cves = {c['cve_id'] for c in results['cves']}
                    
                    for line in output.splitlines():
                        for match in re.findall(r'(CVE-\d{4}-\d+)\s+(\d+\.?\d*)?', line):
                            cve_id = match[0]
                            if cve_id not in existing_cves:
                                try:
                                    cvss = float(match[1]) if match[1] else None
                                except ValueError:
                                    cvss = None
                                
                                results['cves'].append({
                                    "source": "nmap/vulners",
                                    "cve_id": cve_id,
                                    "cvss": cvss,
                                    "service": svc_info['service'],
                                    "port": svc_info['port'],
                                    "product": svc_info['product'],
                                    "version": svc_info['version']
                                })
                                existing_cves.add(cve_id)
        
        # Parser la détection OS
        for osmatch in host.findall(".//osmatch"):
            name = osmatch.get("name", "")
            accuracy = osmatch.get("accuracy", "")
            
            if name:
                results['os_guess'] = name
                results['os_accuracy'] = accuracy
                
                # Extraire le CPE de l'OS
                for osclass in osmatch.findall(".//osclass"):
                    for cpe_elem in osclass.findall("cpe"):
                        if cpe_elem.text:
                            results['os_cpe'] = cpe_elem.text
                            break
                break  # Prendre le premier (meilleur match)
    
    # Dédupliquer les CVE
    seen_cves = set()
    unique_cves = []
    for cve in results['cves']:
        key = (cve['cve_id'], cve.get('port'))
        if key not in seen_cves:
            seen_cves.add(key)
            unique_cves.append(cve)
    results['cves'] = unique_cves
    
    print(f"{Colors.BLUE}[*] Nmap: {len(results['services'])} services, {len(results['cves'])} CVE(s){Colors.ENDC}")
    return results


def run_discovery_scan(network_range):
    """
    @brief Exécute un balayage nmap -sn pour trouver les hôtes actifs.
    @param network_range Plage CIDR (ex: "192.168.1.0/24").
    @return list IPs actives détectées.
    """
    print(f"\n{Colors.HEADER}[*] Découverte des hôtes sur {network_range}...{Colors.ENDC}")
    
    cmd = ["nmap", "-sn", network_range]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Parser la sortie pour extraire les IPs
        active_hosts = []
        for line in result.stdout.splitlines():
            # Format: "Nmap scan report for <hostname> (<ip>)" ou "Nmap scan report for <ip>"
            match = re.search(r'Nmap scan report for (?:[\w.-]+ \()?(\d+\.\d+\.\d+\.\d+)\)?', line)
            if match:
                active_hosts.append(match.group(1))
        
        print(f"{Colors.GREEN}[+] {len(active_hosts)} hôte(s) actif(s) trouvé(s){Colors.ENDC}")
        return active_hosts
        
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] Erreur découverte: {e}{Colors.ENDC}")
        return []
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] Nmap n'est pas installé{Colors.ENDC}")
        return []
