import { useState } from 'react'
import { HardDrive, Box, Cpu, Monitor } from 'lucide-react'
import { cn } from '../utils/cn'
import { CVEColumn } from './CVEColumn'
import type { Host, CVE } from '../types'

interface HostTabsProps {
  host: Host
}

type TabKey = 'services' | 'software' | 'hardware' | 'os'

interface TabConfig {
  key: TabKey
  label: string
  icon: React.ReactNode
  getCves: (host: Host) => CVE[]
}

const tabs: TabConfig[] = [
  {
    key: 'services',
    label: 'Services',
    icon: <HardDrive className="h-4 w-4" />,
    getCves: (host) => [
      ...(host.cves?.nmap_vulners || []),
      ...(host.cves?.cti_services || [])
    ]
  },
  {
    key: 'software',
    label: 'Logiciels',
    icon: <Box className="h-4 w-4" />,
    getCves: (host) => host.cves?.cti_software || []
  },
  {
    key: 'hardware',
    label: 'Hardware',
    icon: <Cpu className="h-4 w-4" />,
    getCves: (host) => host.cves?.cti_hardware || []
  },
  {
    key: 'os',
    label: 'OS',
    icon: <Monitor className="h-4 w-4" />,
    getCves: (host) => host.cves?.cti_os || []
  }
]

export function HostTabs({ host }: HostTabsProps) {
  const [activeTab, setActiveTab] = useState<TabKey>('services')

  const activeConfig = tabs.find(t => t.key === activeTab)!
  const activeCves = activeConfig.getCves(host)

  // Dédupliquer les CVE par cve_id
  const uniqueCves = activeCves.reduce((acc, cve) => {
    if (!acc.find(c => c.cve_id === cve.cve_id)) {
      acc.push(cve)
    }
    return acc
  }, [] as CVE[])

  return (
    <div>
      {/* Tab Navigation */}
      <div className="flex border-b border-white/10 mb-4">
        {tabs.map((tab) => {
          const cves = tab.getCves(host)
          const count = new Set(cves.map(c => c.cve_id)).size

          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={cn(
                "flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors",
                "border-b-2 -mb-px",
                activeTab === tab.key
                  ? "border-primary text-white bg-primary/10"
                  : "border-transparent text-muted-foreground hover:text-white hover:bg-white/5"
              )}
            >
              {tab.icon}
              {tab.label}
              {count > 0 && (
                <span className={cn(
                  "px-2 py-0.5 rounded-full text-xs font-bold",
                  activeTab === tab.key ? "bg-primary text-white" : "bg-white/10"
                )}>
                  {count}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* Tab Content */}
      <CVEColumn 
        cves={uniqueCves} 
        title={`CVE ${activeConfig.label}`}
      />
    </div>
  )
}
