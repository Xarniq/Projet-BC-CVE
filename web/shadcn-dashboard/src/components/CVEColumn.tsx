import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import type { CVE } from '../types'
import { cn } from '../utils/cn'

interface CVEColumnProps {
  cves: CVE[]
  title: string
  initialCount?: number
}

function getCvssClass(cvss?: number): string {
  if (!cvss) return 'bg-gray-500'
  if (cvss >= 9.0) return 'bg-red-600'
  if (cvss >= 7.0) return 'bg-orange-500'
  if (cvss >= 4.0) return 'bg-yellow-500 text-black'
  return 'bg-green-500'
}

function truncate(text: string, maxLength: number): string {
  if (!text) return ''
  if (text.length <= maxLength) return text
  return text.substring(0, maxLength) + '...'
}

export function CVEColumn({ cves, title, initialCount = 10 }: CVEColumnProps) {
  const [showAll, setShowAll] = useState(false)

  if (!cves || cves.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <p>Aucune CVE détectée</p>
      </div>
    )
  }

  // Trier par score CVSS décroissant
  const sortedCves = [...cves].sort((a, b) => {
    const cvssA = a.cvss ?? -1
    const cvssB = b.cvss ?? -1
    return cvssB - cvssA
  })

  const displayedCves = showAll ? sortedCves : sortedCves.slice(0, initialCount)
  const remaining = sortedCves.length - initialCount

  return (
    <div>
      <h4 className="text-sm font-semibold text-muted-foreground mb-3 flex items-center gap-2">
        {title}
        <Badge variant="default" className="text-xs">{cves.length}</Badge>
      </h4>

      <div className="space-y-3">
        {displayedCves.map((cve, idx) => (
          <div
            key={`${cve.cve_id}-${idx}`}
            className={cn(
              "rounded-lg p-4 transition-colors",
              "bg-black/20 border-l-4 hover:bg-black/30",
              cve.cvss && cve.cvss >= 9 ? "border-l-red-500" :
              cve.cvss && cve.cvss >= 7 ? "border-l-orange-500" :
              cve.cvss && cve.cvss >= 4 ? "border-l-yellow-500" : "border-l-green-500"
            )}
          >
            <div className="flex justify-between items-start gap-2 mb-2">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono font-bold text-pink-400 hover:text-pink-300 hover:underline flex items-center gap-1"
              >
                {cve.cve_id}
                <ExternalLink className="h-3 w-3" />
              </a>
              <span className={cn(
                "px-2 py-1 rounded-full text-xs font-bold whitespace-nowrap",
                getCvssClass(cve.cvss)
              )}>
                CVSS {cve.cvss?.toFixed(1) || 'N/A'}
              </span>
            </div>

            {cve.source && (
              <span className="text-xs bg-white/10 px-2 py-0.5 rounded-full mb-2 inline-block">
                {cve.source}
              </span>
            )}

            {cve.description && (
              <p className="text-sm text-gray-300 leading-relaxed mt-2">
                {truncate(cve.description, 250)}
              </p>
            )}

            {cve.cpe && (
              <p className="text-xs text-gray-500 font-mono mt-2 break-all">
                {cve.cpe}
              </p>
            )}

            {(cve.product || cve.version) && (
              <p className="text-xs text-gray-400 mt-1">
                {cve.product} {cve.version && `v${cve.version}`}
              </p>
            )}
          </div>
        ))}
      </div>

      {!showAll && remaining > 0 && (
        <div className="text-center mt-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowAll(true)}
          >
            Afficher plus ({remaining} CVE restantes)
          </Button>
        </div>
      )}

      {showAll && cves.length > initialCount && (
        <div className="text-center mt-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowAll(false)}
          >
            Réduire
          </Button>
        </div>
      )}
    </div>
  )
}
