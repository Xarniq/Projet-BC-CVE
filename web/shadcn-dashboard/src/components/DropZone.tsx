import { useCallback, useState } from 'react'
import { Upload } from 'lucide-react'
import { cn } from '../utils/cn'

interface DropZoneProps {
  onFilesLoaded: (files: { filename: string; data: unknown }[]) => void
}

export function DropZone({ onFilesLoaded }: DropZoneProps) {
  const [isDragging, setIsDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleFiles = useCallback(async (files: FileList) => {
    setError(null)
    const results: { filename: string; data: unknown }[] = []

    for (const file of Array.from(files)) {
      if (!file.name.endsWith('.json')) {
        setError('Seuls les fichiers JSON sont acceptés')
        continue
      }

      try {
        const text = await file.text()
        const data = JSON.parse(text)
        results.push({ filename: file.name, data })
      } catch (e) {
        setError(`Erreur lors du parsing de ${file.name}`)
        console.error(e)
      }
    }

    if (results.length > 0) {
      onFilesLoaded(results)
    }
  }, [onFilesLoaded])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)

    if (e.dataTransfer.files.length > 0) {
      handleFiles(e.dataTransfer.files)
    }
  }, [handleFiles])

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFiles(e.target.files)
    }
  }, [handleFiles])

  return (
    <div className="flex flex-col items-center justify-center h-[60vh]">
      <label
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={cn(
          "flex flex-col items-center justify-center w-full max-w-xl p-12 rounded-2xl cursor-pointer transition-all duration-300",
          "border-2 border-dashed",
          isDragging 
            ? "border-primary bg-primary/10 scale-105" 
            : "border-muted-foreground/30 bg-card/50 hover:border-primary/50 hover:bg-card"
        )}
      >
        <input
          type="file"
          accept=".json"
          multiple
          onChange={handleInputChange}
          className="hidden"
        />
        <Upload className={cn(
          "h-16 w-16 mb-4 transition-colors",
          isDragging ? "text-primary" : "text-muted-foreground"
        )} />
        <h2 className="text-xl font-semibold mb-2">
          Glissez vos rapports JSON ici
        </h2>
        <p className="text-muted-foreground text-center">
          ou cliquez pour sélectionner des fichiers
        </p>
        <p className="text-xs text-muted-foreground mt-4">
          Supporte les rapports réseau et hôte unique
        </p>
      </label>

      {error && (
        <p className="text-red-400 mt-4 text-sm">{error}</p>
      )}
    </div>
  )
}
