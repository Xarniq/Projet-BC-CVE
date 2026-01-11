// Types pour les données d'audit CVE

export interface CVE {
  cve_id: string
  cvss?: number
  source?: string
  description?: string
  port?: string
  service?: string
  product?: string
  version?: string
  cpe?: string
  type?: string
  is_exploit?: boolean
  search_method?: string
}

export interface Service {
  port: string
  protocol: string
  service: string
  product?: string
  version?: string
  extrainfo?: string
  cpes?: string[]
}

export interface HostSummary {
  total_unique_cves: number
  services_count: number
  severity?: {
    critical: number
    high: number
    medium: number
    low: number
  }
  by_source?: {
    nmap_vulners?: number
    cti_services?: number
    cti_software?: number
    cti_hardware?: number
    cti_os?: number
  }
}

export interface Host {
  target: string
  timestamp: string
  nmap?: {
    services: Service[]
    os_guess?: string
    os_accuracy?: string
    os_cpe?: string
  }
  glpi?: Record<string, unknown>
  cves?: {
    nmap_vulners?: CVE[]
    cti_services?: CVE[]
    cti_software?: CVE[]
    cti_hardware?: CVE[]
    cti_os?: CVE[]
  }
  summary?: HostSummary
}

export interface NetworkSummary {
  total_hosts: number
  total_cves: number
  total_services: number
  hosts_with_cves: number
}

export interface Report {
  network_range?: string
  target?: string
  timestamp: string
  hosts_scanned?: number
  hosts: Host[]
  network_summary?: NetworkSummary
}

// Type pour un fichier chargé
export interface LoadedReport {
  filename: string
  data: Report
}
