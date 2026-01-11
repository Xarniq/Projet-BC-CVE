#!/usr/bin/env python3
"""
Script principal d'audit de sécurité hybride.

Ce script combine:
- Nmap: Scan réseau, détection services/OS, CVE via vulners
- GLPI: Inventaire logiciel de la cible
- CVE-Search: Corrélation avec la base de vulnérabilités

Supporte:
- Scan d'une IP unique
- Scan d'une plage réseau CIDR (ex: 192.168.1.0/24)

Usage:
    python main.py                    # IP par défaut
    python main.py 192.168.1.100      # IP unique
    python main.py 192.168.1.0/24     # Plage CIDR

Prérequis:
    - Nmap installé avec script vulners
    - GLPI configuré avec API REST
    - CVE-Search-Docker lancé

Exemple:
    $ sudo python main.py 192.168.181.0/24
    [*] Découverte des hôtes sur 192.168.181.0/24...
    [+] 5 hôte(s) actif(s) trouvé(s)
    ...
"""
import sys
import os
import ipaddress
from datetime import datetime

# Ajouter src au path pour les imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from secu_audit import (
    Colors,
    REPORT_OUTPUT,
    REPORTS_DIR,
    DEFAULT_TARGET,
    run_nmap_scan,
    parse_nmap_results,
    run_discovery_scan,
    get_glpi_inventory,
    kill_session,
    check_software_cves,
    check_service_cves,
    check_os_cves,
    check_hardware_cves,
    save_report,
)


def audit_single_host(target_ip):
    """
    @brief Exécute l'audit complet sur une IP unique.
    @param target_ip Adresse IP cible.
    @return dict Rapport d'audit structuré (nmap, glpi, cves, summary).
    """
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}  AUDIT DE SÉCURITÉ - {target_ip}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    report = {
        "target": target_ip,
        "timestamp": datetime.now().isoformat(),
        "nmap": {},
        "glpi": {},
        "cves": {
            "nmap_vulners": [],
            "cti_software": [],
            "cti_services": [],
            "cti_os": [],
            "cti_hardware": []
        },
        "summary": {}
    }
    
    # === ÉTAPE 1: Scan Nmap ===
    print(f"\n{Colors.CYAN}[ÉTAPE 1/4] Scan Nmap{Colors.ENDC}")
    if run_nmap_scan(target_ip):
        nmap_results = parse_nmap_results()
        report["nmap"] = {
            "services": nmap_results.get("services", []),
            "os_guess": nmap_results.get("os_guess"),
            "os_accuracy": nmap_results.get("os_accuracy"),
            "os_cpe": nmap_results.get("os_cpe")
        }
        report["cves"]["nmap_vulners"] = nmap_results.get("cves", [])
    
    # === ÉTAPE 2: Inventaire GLPI ===
    print(f"\n{Colors.CYAN}[ÉTAPE 2/4] Inventaire GLPI{Colors.ENDC}")
    glpi_data = get_glpi_inventory(target_ip)
    if glpi_data:
        report["glpi"] = {
            "computer": glpi_data.get("computer"),
            "softwares": glpi_data.get("softwares", []),
            "cpus": glpi_data.get("cpus", []),
            "os": glpi_data.get("os")
        }
    
    # === ÉTAPE 3: Corrélation CTI ===
    print(f"\n{Colors.CYAN}[ÉTAPE 3/4] Corrélation CVE (CTI){Colors.ENDC}")
    
    # CVE pour les logiciels GLPI
    if glpi_data and glpi_data.get("softwares"):
        print(f"{Colors.BLUE}[*] Analyse des logiciels GLPI...{Colors.ENDC}")
        sw_cves = check_software_cves(glpi_data["softwares"])
        report["cves"]["cti_software"] = sw_cves
    
    # CVE pour les services Nmap
    if report["nmap"].get("services"):
        print(f"{Colors.BLUE}[*] Analyse des services Nmap...{Colors.ENDC}")
        svc_cves = check_service_cves(report["nmap"]["services"])
        report["cves"]["cti_services"] = svc_cves
    
    # CVE pour l'OS - Préférer GLPI si disponible, sinon Nmap
    os_name = None
    os_version = None
    os_source = None
    
    if glpi_data and glpi_data.get("os") and glpi_data["os"].get("name"):
        os_name = glpi_data["os"]["name"]
        os_version = glpi_data["os"].get("version", "")
        os_source = "GLPI"
    elif report["nmap"].get("os_guess"):
        os_name = report["nmap"]["os_guess"]
        os_version = None
        os_source = "Nmap"
    
    if os_name:
        print(f"{Colors.BLUE}[*] Analyse de l'OS ({os_source}: {os_name} {os_version or ''})...{Colors.ENDC}")
        os_cves = check_os_cves(os_name, os_version)
        report["cves"]["cti_os"] = os_cves
    
    # CVE pour le hardware
    if glpi_data and glpi_data.get("cpus"):
        print(f"{Colors.BLUE}[*] Analyse du hardware...{Colors.ENDC}")
        hw_cves = check_hardware_cves(glpi_data["cpus"])
        report["cves"]["cti_hardware"] = hw_cves
    
    # === ÉTAPE 4: Résumé ===
    print(f"\n{Colors.CYAN}[ÉTAPE 4/4] Génération du résumé{Colors.ENDC}")
    
    # Compter les CVE uniques
    all_cve_ids = set()
    for category in report["cves"].values():
        for cve in category:
            all_cve_ids.add(cve.get("cve_id"))
    
    # Compter par sévérité (basé sur CVSS si disponible)
    critical = high = medium = low = 0
    for category in report["cves"].values():
        for cve in category:
            cvss = cve.get("cvss")
            if cvss:
                if cvss >= 9.0:
                    critical += 1
                elif cvss >= 7.0:
                    high += 1
                elif cvss >= 4.0:
                    medium += 1
                else:
                    low += 1
    
    report["summary"] = {
        "total_unique_cves": len(all_cve_ids),
        "cves_by_source": {
            "nmap_vulners": len(report["cves"]["nmap_vulners"]),
            "cti_software": len(report["cves"]["cti_software"]),
            "cti_services": len(report["cves"]["cti_services"]),
            "cti_os": len(report["cves"]["cti_os"]),
            "cti_hardware": len(report["cves"]["cti_hardware"])
        },
        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "services_count": len(report["nmap"].get("services", [])),
        "softwares_count": len(report["glpi"].get("softwares", []))
    }
    
    # Afficher le résumé
    print_summary(report)
    
    return report


def print_summary(report):
    """
    @brief Affiche le résumé synthétique d'un rapport d'audit.
    @param report Rapport complet calculé par audit_single_host.
    """
    summary = report.get("summary", {})
    
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}  RÉSUMÉ DE L'AUDIT{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}Cible:{Colors.ENDC} {report.get('target')}")
    print(f"{Colors.BOLD}OS détecté:{Colors.ENDC} {report['nmap'].get('os_guess', 'Inconnu')}")
    
    print(f"\n{Colors.BOLD}Services détectés:{Colors.ENDC} {summary.get('services_count', 0)}")
    print(f"{Colors.BOLD}Logiciels GLPI:{Colors.ENDC} {summary.get('softwares_count', 0)}")
    
    print(f"\n{Colors.BOLD}CVE trouvées:{Colors.ENDC} {summary.get('total_unique_cves', 0)} unique(s)")
    
    by_source = summary.get("cves_by_source", {})
    print(f"  - Nmap/Vulners: {by_source.get('nmap_vulners', 0)}")
    print(f"  - CTI/Logiciels: {by_source.get('cti_software', 0)}")
    print(f"  - CTI/Services: {by_source.get('cti_services', 0)}")
    print(f"  - CTI/OS: {by_source.get('cti_os', 0)}")
    print(f"  - CTI/Hardware: {by_source.get('cti_hardware', 0)}")
    
    severity = summary.get("severity", {})
    if any(severity.values()):
        print(f"\n{Colors.BOLD}Sévérité (CVSS):{Colors.ENDC}")
        if severity.get("critical"):
            print(f"  {Colors.FAIL}● Critique (9+): {severity['critical']}{Colors.ENDC}")
        if severity.get("high"):
            print(f"  {Colors.WARNING}● Haute (7-8.9): {severity['high']}{Colors.ENDC}")
        if severity.get("medium"):
            print(f"  {Colors.BLUE}● Moyenne (4-6.9): {severity['medium']}{Colors.ENDC}")
        if severity.get("low"):
            print(f"  {Colors.GREEN}● Basse (<4): {severity['low']}{Colors.ENDC}")


def discover_active_hosts(network_range):
    """
    @brief Lance un ping scan nmap pour trouver les hôtes actifs.
    @param network_range Plage CIDR à scanner.
    @return list IPs actives détectées.
    """
    return run_discovery_scan(network_range)


def audit_network_range(network_range):
    """
    @brief Réalise un audit sur l'ensemble d'une plage CIDR.
    @param network_range Plage réseau au format CIDR.
    @return dict Rapport consolidé (hosts, cves, stats réseau).
    """
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}  AUDIT RÉSEAU - {network_range}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    # Découverte des hôtes
    active_hosts = discover_active_hosts(network_range)
    
    if not active_hosts:
        print(f"{Colors.WARNING}[!] Aucun hôte actif trouvé{Colors.ENDC}")
        return None
    
    print(f"\n{Colors.GREEN}[+] Hôtes actifs:{Colors.ENDC}")
    for ip in active_hosts:
        print(f"    - {ip}")
    
    # Audit de chaque hôte
    all_reports = []
    for i, ip in enumerate(active_hosts, 1):
        print(f"\n{Colors.HEADER}[{i}/{len(active_hosts)}] Audit de {ip}{Colors.ENDC}")
        
        report = audit_single_host(ip)
        all_reports.append(report)
        
        # Sauvegarder le rapport individuel
        individual_file = REPORTS_DIR / f"audit_{ip.replace('.', '_')}.json"
        save_report(report, str(individual_file))
    
    # Rapport consolidé
    consolidated = {
        "network_range": network_range,
        "timestamp": datetime.now().isoformat(),
        "hosts_scanned": len(active_hosts),
        "hosts": all_reports,
        "network_summary": {
            "total_hosts": len(active_hosts),
            "total_cves": sum(r["summary"].get("total_unique_cves", 0) for r in all_reports),
            "total_services": sum(r["summary"].get("services_count", 0) for r in all_reports),
            "hosts_with_cves": sum(1 for r in all_reports if r["summary"].get("total_unique_cves", 0) > 0)
        }
    }
    
    return consolidated


def save_consolidated_report(report, filename=None):
    """
    @brief Sauvegarde un rapport réseau consolidé dans data/reports.
    @param report Rapport à écrire.
    @param filename Nom du fichier (optionnel, par défaut network_audit_<date>.json).
    """
    if not filename:
        timestamp = datetime.now().strftime("%Y-%m-%d")
        filename = f"network_audit_{timestamp}.json"
    
    filepath = REPORTS_DIR / filename
    save_report(report, str(filepath))


def main():
    """
    @brief Point d'entrée CLI: sélectionne IP ou plage et lance l'audit.
    """
    # Récupérer la cible depuis les arguments ou .env
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = DEFAULT_TARGET  # Depuis .env ou valeur par défaut
    
    try:
        # Vérifier si c'est une plage CIDR ou une IP unique
        if '/' in target:
            # Valider le format CIDR
            network = ipaddress.ip_network(target, strict=False)
            print(f"{Colors.BLUE}[*] Mode scan réseau: {network}{Colors.ENDC}")
            
            report = audit_network_range(target)
            if report:
                save_consolidated_report(report)
                
                # Résumé réseau
                print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
                print(f"{Colors.HEADER}  RÉSUMÉ RÉSEAU{Colors.ENDC}")
                print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
                ns = report.get("network_summary", {})
                print(f"Hôtes scannés: {ns.get('total_hosts', 0)}")
                print(f"Hôtes avec CVE: {ns.get('hosts_with_cves', 0)}")
                print(f"Total CVE uniques: {ns.get('total_cves', 0)}")
                print(f"Total services: {ns.get('total_services', 0)}")
        else:
            # Valider l'IP unique
            ipaddress.ip_address(target)
            print(f"{Colors.BLUE}[*] Mode scan IP unique: {target}{Colors.ENDC}")
            
            host_report = audit_single_host(target)
            
            # Créer un rapport réseau même pour une seule IP
            report = {
                "network_range": target,
                "timestamp": datetime.now().isoformat(),
                "hosts_scanned": 1,
                "hosts": [host_report],
                "network_summary": {
                    "total_hosts": 1,
                    "total_cves": host_report["summary"].get("total_unique_cves", 0),
                    "total_services": host_report["summary"].get("services_count", 0),
                    "hosts_with_cves": 1 if host_report["summary"].get("total_unique_cves", 0) > 0 else 0
                }
            }
            save_consolidated_report(report)
    
    except ValueError as e:
        print(f"{Colors.FAIL}[!] Adresse invalide: {e}{Colors.ENDC}")
        print(f"Usage: {sys.argv[0]} <IP ou CIDR>")
        print(f"  Exemples: {sys.argv[0]} 192.168.1.100")
        print(f"            {sys.argv[0]} 192.168.1.0/24")
        sys.exit(1)
    
    finally:
        # Toujours fermer la session GLPI
        kill_session()
    
    print(f"\n{Colors.GREEN}[+] Audit terminé !{Colors.ENDC}")


if __name__ == "__main__":
    main()
