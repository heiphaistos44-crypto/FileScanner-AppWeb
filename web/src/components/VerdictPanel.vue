<script setup lang="ts">
import { computed } from 'vue'
import { useScanStore } from '../stores/scan'
import { formatBytes } from '../types/scan'

const store = useScanStore()
const r = computed(() => store.result!)

const scoreDash = computed(() => {
  const score = r.value.verdict_score
  const circ = 2 * Math.PI * 44
  return `${(score / 100) * circ} ${circ}`
})
</script>

<template>
  <div class="verdict-panel" :style="{ borderColor: store.verdictColor + '66' }">
    <div class="gauge">
      <svg viewBox="0 0 100 100" width="110" height="110">
        <circle cx="50" cy="50" r="44" fill="none" stroke="var(--border)" stroke-width="8" />
        <circle
          cx="50" cy="50" r="44" fill="none"
          :stroke="store.verdictColor" stroke-width="8" stroke-linecap="round"
          :stroke-dasharray="scoreDash" transform="rotate(-90 50 50)"
        />
        <text x="50" y="47" text-anchor="middle" fill="var(--text)" font-size="22" font-weight="700">
          {{ r.verdict_score }}
        </text>
        <text x="50" y="64" text-anchor="middle" fill="var(--text-dim)" font-size="10">/ 100</text>
      </svg>
    </div>
    <div class="info">
      <p class="verdict-label" :style="{ color: store.verdictColor }">{{ store.verdictLabel }}</p>
      <p class="filename" :title="r.file_name">{{ r.file_name }}</p>
      <p class="meta">
        {{ formatBytes(r.file_size) }} · {{ r.mime_type }} · {{ r.category }}
        · entropie {{ r.global_entropy.toFixed(2) }}
      </p>
      <p v-if="r.clamav" class="clamav-hit">⚠ ClamAV : {{ r.clamav.malware_name }}</p>
      <div class="actions">
        <button @click="store.exportJson()">Export JSON</button>
        <button @click="store.exportTxt()">Export TXT</button>
        <button @click="store.reset()">Nouveau scan</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.verdict-panel {
  display: flex;
  gap: 24px;
  align-items: center;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 20px 24px;
  margin-top: 20px;
}
.verdict-label { font-size: 22px; font-weight: 800; letter-spacing: 0.04em; }
.filename { font-weight: 600; margin-top: 2px; word-break: break-all; }
.meta { color: var(--text-dim); font-size: 12px; margin-top: 4px; }
.clamav-hit { color: var(--red); font-weight: 600; margin-top: 6px; }
.actions { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.info { flex: 1; min-width: 0; }
</style>
