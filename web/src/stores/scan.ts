import { defineStore } from 'pinia'
import type { HealthStatus, ScanResult } from '../types/scan'

export const useScanStore = defineStore('scan', {
  state: () => ({
    result: null as ScanResult | null,
    scanning: false,
    error: null as string | null,
    health: null as HealthStatus | null,
  }),

  getters: {
    hasResult: (s) => s.result !== null,
    verdictColor: (s) => {
      if (!s.result) return '#6b7280'
      const map: Record<string, string> = {
        Safe: '#22c55e',
        Suspicious: '#f97316',
        Malicious: '#ef4444',
        Unknown: '#6b7280',
      }
      return map[s.result.verdict] ?? '#6b7280'
    },
    verdictLabel: (s) => {
      if (!s.result) return ''
      const map: Record<string, string> = {
        Safe: 'SAIN',
        Suspicious: 'SUSPECT',
        Malicious: 'MALVEILLANT',
        Unknown: 'INCONNU',
      }
      return map[s.result.verdict] ?? s.result.verdict
    },
  },

  actions: {
    async loadHealth() {
      try {
        const res = await fetch('/api/health')
        if (res.ok) this.health = await res.json()
      } catch {
        this.health = null
      }
    },

    async scanFile(file: File) {
      this.scanning = true
      this.error = null
      this.result = null

      try {
        const form = new FormData()
        form.append('file', file)

        const res = await fetch('/api/scan', { method: 'POST', body: form })
        if (!res.ok) {
          if (res.status === 429) {
            throw new Error('Trop de scans — patientez une minute avant de réessayer.')
          }
          const msg = await res
            .json()
            .then((j: { error?: string }) => j.error)
            .catch(() => undefined)
          throw new Error(msg ?? `Erreur serveur (${res.status})`)
        }

        this.result = await res.json()
      } catch (e) {
        this.error = e instanceof Error ? e.message : String(e)
      } finally {
        this.scanning = false
      }
    },

    exportJson() {
      if (!this.result) return
      const blob = new Blob([JSON.stringify(this.result, null, 2)], { type: 'application/json' })
      downloadBlob(blob, `rapport_${this.result.file_name}.json`)
    },

    exportTxt() {
      if (!this.result) return
      const r = this.result
      const lines: string[] = [
        '═══ RAPPORT FILESCANNER ═══',
        `Fichier   : ${r.file_name}`,
        `Taille    : ${r.file_size} octets`,
        `Type MIME : ${r.mime_type}`,
        `Catégorie : ${r.category}`,
        `Verdict   : ${r.verdict} (score ${r.verdict_score}/100)`,
        `Scanné le : ${r.scanned_at}`,
        '',
        '─── Hashes ───',
        `MD5    : ${r.hashes.md5}`,
        `SHA1   : ${r.hashes.sha1}`,
        `SHA256 : ${r.hashes.sha256}`,
        `SHA512 : ${r.hashes.sha512}`,
        `Entropie globale : ${r.global_entropy.toFixed(2)}`,
        '',
      ]
      if (r.yara_matches.length > 0) {
        lines.push('─── Règles YARA déclenchées ───')
        for (const m of r.yara_matches) {
          lines.push(`[${m.severity}] ${m.rule_name} — ${m.description}`)
        }
        lines.push('')
      }
      if (r.ioc_list.length > 0) {
        lines.push('─── Indicateurs (IoC) ───')
        for (const ioc of r.ioc_list) {
          lines.push(`[${ioc.severity}] ${ioc.ioc_type} : ${ioc.value} — ${ioc.description}`)
        }
        lines.push('')
      }
      if (r.extracted_iocs.urls.length > 0) {
        lines.push('─── URLs extraites ───', ...r.extracted_iocs.urls, '')
      }
      if (r.extracted_iocs.ips.length > 0) {
        lines.push('─── IPs extraites ───', ...r.extracted_iocs.ips, '')
      }
      if (r.clamav) {
        lines.push(`─── ClamAV ───`, `Détection : ${r.clamav.malware_name} (${r.clamav.database})`, '')
      }
      if (r.virustotal) {
        lines.push(
          '─── VirusTotal ───',
          `Détections : ${r.virustotal.positives}/${r.virustotal.total}`,
          `Lien : ${r.virustotal.permalink}`,
          ''
        )
      }
      const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' })
      downloadBlob(blob, `rapport_${r.file_name}.txt`)
    },

    reset() {
      this.result = null
      this.error = null
    },
  },
})

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}
