import { useState, useCallback } from 'react'
import { 
  Shield, 
  Server, 
  AlertTriangle, 
  Activity,
  Trash2,
  ChevronRight
} from 'lucide-react'
import { Button } from './components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from './components/ui/dialog'
import { Badge } from './components/ui/badge'
import { cn } from './utils/cn'
import { DropZone } from './components/DropZone'
import { HostTabs } from './components/HostTabs'
import type { Report, Host, LoadedReport } from './types'

// Normaliser les rapports (simple hôte vs réseau)
function normalizeReport(data: any, filename: string): Report {
  // Rapport réseau avec plusieurs hôtes
  if (data.hosts && Array.isArray(data.hosts)) {
    return {
      ...data,
      network_range: data.network_range || filename
    } as Report
  }
  
  // Rapport d'un seul hôte
  if (data.target) {
    const host = data as Host
    
    // Calculer les stats
    const allCves = [
      ...(host.cves?.nmap_vulners || []),
      ...(host.cves?.cti_services || []),
      ...(host.cves?.cti_software || []),
      ...(host.cves?.cti_hardware || []),
      ...(host.cves?.cti_os || [])
    ]
    
    const uniqueCveIds = new Set(allCves.map(c => c.cve_id))
    
    return {
      network_range: host.target,
      target: host.target,
      timestamp: host.timestamp,
      hosts_scanned: 1,
      hosts: [{
        ...host,
        summary: host.summary || {
          total_unique_cves: uniqueCveIds.size,
          services_count: host.nmap?.services?.length || 0,
          by_source: {
            nmap_vulners: host.cves?.nmap_vulners?.length || 0,
            cti_services: host.cves?.cti_services?.length || 0,
            cti_software: host.cves?.cti_software?.length || 0,
            cti_hardware: host.cves?.cti_hardware?.length || 0,
            cti_os: host.cves?.cti_os?.length || 0
          }
        }
      }],
      network_summary: {
        total_hosts: 1,
        total_cves: uniqueCveIds.size,
        total_services: host.nmap?.services?.length || 0,
        hosts_with_cves: uniqueCveIds.size > 0 ? 1 : 0
      }
    }
  }
  
  return data as Report
}

function formatDate(isoString?: string): string {
  if (!isoString) return '-'
  const date = new Date(isoString)
  return date.toLocaleDateString('fr-FR', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

function getCvssVariant(cvss?: number): "critical" | "high" | "medium" | "low" {
  if (!cvss) return 'low'
  if (cvss >= 9.0) return 'critical'
  if (cvss >= 7.0) return 'high'
  if (cvss >= 4.0) return 'medium'
  return 'low'
}

// Calculer le total de CVE unique pour un hôte
function getHostTotalCves(host: Host): number {
  const allCves = [
    ...(host.cves?.nmap_vulners || []),
    ...(host.cves?.cti_services || []),
    ...(host.cves?.cti_software || []),
    ...(host.cves?.cti_hardware || []),
    ...(host.cves?.cti_os || [])
  ]
  return new Set(allCves.map(c => c.cve_id)).size
}

// Calculer les CVE critiques pour un hôte
function getHostCriticalCount(host: Host): number {
  const allCves = [
    ...(host.cves?.nmap_vulners || []),
    ...(host.cves?.cti_services || []),
    ...(host.cves?.cti_software || []),
    ...(host.cves?.cti_hardware || []),
    ...(host.cves?.cti_os || [])
  ]
  return allCves.filter(c => c.cvss && c.cvss >= 9).length
}

export default function App() {
  const [loadedReports, setLoadedReports] = useState<LoadedReport[]>([])
  const [currentReport, setCurrentReport] = useState<Report | null>(null)
  const [selectedHost, setSelectedHost] = useState<Host | null>(null)
  const [hostModalOpen, setHostModalOpen] = useState(false)

  // Handler pour les fichiers chargés via drag & drop
  const handleFilesLoaded = useCallback((files: { filename: string; data: unknown }[]) => {
    const newReports: LoadedReport[] = files.map(f => ({
      filename: f.filename,
      data: normalizeReport(f.data, f.filename)
    }))
    
    setLoadedReports(prev => [...prev, ...newReports])
    
    // Sélectionner automatiquement le premier rapport si aucun n'est sélectionné
    if (!currentReport && newReports.length > 0) {
      setCurrentReport(newReports[0].data)
    }
  }, [currentReport])

  // Réinitialiser
  const handleReset = useCallback(() => {
    setLoadedReports([])
    setCurrentReport(null)
    setSelectedHost(null)
    setHostModalOpen(false)
  }, [])

  // Calculer les statistiques
  const stats = currentReport ? {
    hosts: currentReport.network_summary?.total_hosts || currentReport.hosts?.length || 0,
    cves: currentReport.hosts?.reduce((acc, h) => acc + getHostTotalCves(h), 0) || 0,
    critical: currentReport.hosts?.reduce((acc, h) => acc + getHostCriticalCount(h), 0) || 0,
    services: currentReport.network_summary?.total_services || 
              currentReport.hosts?.reduce((acc, h) => acc + (h.nmap?.services?.length || 0), 0) || 0
  } : { hosts: 0, cves: 0, critical: 0, services: 0 }

  return (
    <div className="min-h-screen bg-background">
      {/* En-tête */}
      <header className="sticky top-0 z-50 border-b bg-background/80 backdrop-blur-sm">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-primary" />
            <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              Audit CVE - Dashboard
            </h1>
          </div>
          {loadedReports.length > 0 && (
            <Button variant="outline" onClick={handleReset}>
              <Trash2 className="h-4 w-4 mr-2" />
              Nouvelle session
            </Button>
          )}
        </div>
      </header>

      {loadedReports.length === 0 ? (
        // Zone de drop si aucun rapport chargé
        <div className="container mx-auto px-4 py-8">
          <DropZone onFilesLoaded={handleFilesLoaded} />
        </div>
      ) : (
        <div className="flex">
          {/* Barre latérale - Rapports chargés */}
          <aside className="w-72 border-r bg-card/50 min-h-[calc(100vh-4rem)]">
            <div className="p-4 border-b">
              <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                Rapports ({loadedReports.length})
              </h2>
            </div>
            <div className="p-2 space-y-1">
              {loadedReports.map((report, index) => (
                <button
                  key={index}
                  onClick={() => setCurrentReport(report.data)}
                  className={cn(
                    "w-full text-left p-3 rounded-lg transition-colors",
                    currentReport === report.data
                      ? "bg-primary/10 border border-primary/30"
                      : "hover:bg-accent"
                  )}
                >
                  <div className="font-mono text-sm font-medium truncate">
                    {report.data.network_range || report.data.target || report.filename}
                  </div>
                  <div className="flex justify-between text-xs text-muted-foreground mt-1">
                    <span>{formatDate(report.data.timestamp)}</span>
                    <span className="text-orange-400 font-semibold">
                      {report.data.hosts?.reduce((acc, h) => acc + getHostTotalCves(h), 0) || 0} CVE
                    </span>
                  </div>
                </button>
              ))}
            </div>
            
            {/* Zone pour ajouter plus de fichiers */}
            <div className="p-4 border-t">
              <label className="flex flex-col items-center justify-center p-4 border-2 border-dashed border-muted-foreground/30 rounded-lg cursor-pointer hover:border-primary/50 transition-colors">
                <input
                  type="file"
                  accept=".json"
                  multiple
                  onChange={(e) => {
                    if (e.target.files) {
                      const files = Array.from(e.target.files)
                      Promise.all(files.map(async (file) => {
                        const text = await file.text()
                        return { filename: file.name, data: JSON.parse(text) }
                      })).then(handleFilesLoaded)
                    }
                  }}
                  className="hidden"
                />
                <span className="text-xs text-muted-foreground">+ Ajouter des rapports</span>
              </label>
            </div>
          </aside>

          {/* Contenu principal */}
          <main className="flex-1 p-6">
            {!currentReport ? (
              <div className="flex flex-col items-center justify-center h-[60vh] text-muted-foreground">
                <Server className="h-16 w-16 mb-4 opacity-50" />
                <h2 className="text-xl font-medium mb-2">Aucun rapport sélectionné</h2>
                <p className="text-sm">Sélectionnez un rapport dans la liste</p>
              </div>
            ) : (
              <>
                {/* Statistiques */}
                <div className="grid grid-cols-4 gap-4 mb-6">
                  <Card>
                    <CardHeader className="flex flex-row items-center justify-between pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">
                        Hôtes
                      </CardTitle>
                      <Server className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">{stats.hosts}</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="flex flex-row items-center justify-between pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">
                        CVE Totales
                      </CardTitle>
                      <AlertTriangle className="h-4 w-4 text-orange-400" />
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold text-orange-400">{stats.cves}</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="flex flex-row items-center justify-between pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">
                        Critiques
                      </CardTitle>
                      <AlertTriangle className="h-4 w-4 text-red-500" />
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold text-red-500">{stats.critical}</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="flex flex-row items-center justify-between pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">
                        Services
                      </CardTitle>
                      <Activity className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">{stats.services}</div>
                    </CardContent>
                  </Card>
                </div>

                {/* En-tête du rapport */}
                <div className="mb-6">
                  <h2 className="text-2xl font-bold font-mono">
                    {currentReport.network_range || currentReport.target}
                  </h2>
                  <p className="text-muted-foreground text-sm">{formatDate(currentReport.timestamp)}</p>
                </div>

                {/* Grille des hôtes */}
                <h3 className="text-lg font-semibold mb-4 text-muted-foreground">Hôtes Scannés</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {currentReport.hosts?.map((host, index) => {
                    const cveCount = getHostTotalCves(host)
                    const maxCves = Math.max(...(currentReport.hosts?.map(h => getHostTotalCves(h)) || [1]), 1)
                    const barWidth = (cveCount / maxCves) * 100
                    
                    // Stats par source
                    const bySource = {
                      services: (host.cves?.nmap_vulners?.length || 0) + (host.cves?.cti_services?.length || 0),
                      software: host.cves?.cti_software?.length || 0,
                      hardware: host.cves?.cti_hardware?.length || 0,
                      os: host.cves?.cti_os?.length || 0
                    }
                    
                    return (
                      <Card 
                        key={index} 
                        className="cursor-pointer hover:border-primary/50 transition-colors"
                        onClick={() => { setSelectedHost(host); setHostModalOpen(true) }}
                      >
                        <CardContent className="p-4">
                          <div className="flex justify-between items-start mb-2">
                            <span className="font-mono font-semibold">{host.target}</span>
                            <Badge variant={getCvssVariant(cveCount > 0 ? 7 : 0)}>
                              {cveCount} CVE
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mb-2 truncate">
                            {host.nmap?.os_guess || 'OS inconnu'}
                          </p>
                          <p className="text-xs text-muted-foreground mb-3">
                            {host.nmap?.services?.length || 0} services détectés
                          </p>
                          
                          {/* Mini stats par catégorie */}
                          <div className="flex gap-2 text-xs text-muted-foreground mb-3">
                            {bySource.services > 0 && (
                              <span className="bg-blue-500/20 px-1.5 py-0.5 rounded">Svc: {bySource.services}</span>
                            )}
                            {bySource.software > 0 && (
                              <span className="bg-green-500/20 px-1.5 py-0.5 rounded">Soft: {bySource.software}</span>
                            )}
                            {bySource.hardware > 0 && (
                              <span className="bg-purple-500/20 px-1.5 py-0.5 rounded">HW: {bySource.hardware}</span>
                            )}
                            {bySource.os > 0 && (
                              <span className="bg-orange-500/20 px-1.5 py-0.5 rounded">OS: {bySource.os}</span>
                            )}
                          </div>
                          
                          <div className="h-1 bg-secondary rounded-full overflow-hidden">
                            <div 
                              className={cn(
                                "h-full rounded-full transition-all",
                                cveCount >= maxCves * 0.75 ? "bg-red-500" :
                                cveCount >= maxCves * 0.5 ? "bg-orange-500" :
                                cveCount >= maxCves * 0.25 ? "bg-yellow-500" : "bg-green-500"
                              )}
                              style={{ width: `${barWidth}%` }}
                            />
                          </div>
                          <div className="flex justify-end mt-2">
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          </div>
                        </CardContent>
                      </Card>
                    )
                  })}
                </div>
              </>
            )}
          </main>
        </div>
      )}

      {/* Modal détails hôte */}
      <Dialog open={hostModalOpen} onOpenChange={setHostModalOpen}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="font-mono text-xl">{selectedHost?.target}</DialogTitle>
            <DialogDescription>
              {selectedHost?.nmap?.os_guess || 'OS inconnu'}
            </DialogDescription>
          </DialogHeader>
          
          {selectedHost && (
            <div className="space-y-6">
              {/* Statistiques de l'hôte */}
              <div className="flex gap-6 text-sm">
                <div>
                  <span className="text-muted-foreground">CVE: </span>
                  <strong>{getHostTotalCves(selectedHost)}</strong>
                </div>
                <div>
                  <span className="text-muted-foreground">Services: </span>
                  <strong>{selectedHost.nmap?.services?.length || 0}</strong>
                </div>
                <div>
                  <span className="text-muted-foreground">Critiques: </span>
                  <strong className="text-red-500">{getHostCriticalCount(selectedHost)}</strong>
                </div>
              </div>

              {/* Info OS */}
              {selectedHost.nmap?.os_cpe && (
                <div className="text-xs text-muted-foreground">
                  <span className="font-semibold">CPE OS:</span> {selectedHost.nmap.os_cpe}
                </div>
              )}

              {/* Onglets Services / Software / Hardware / OS */}
              <HostTabs host={selectedHost} />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
