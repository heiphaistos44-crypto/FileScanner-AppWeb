<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useScanStore } from './stores/scan'
import DropZone from './components/DropZone.vue'
import VerdictPanel from './components/VerdictPanel.vue'
import ResultDetails from './components/ResultDetails.vue'

declare const __APP_VERSION__: string

const store = useScanStore()
const pendingName = ref('')

onMounted(() => store.loadHealth())

async function onFile(f: File) {
  if (f.size > 100 * 1024 * 1024) {
    store.error = 'Fichier trop volumineux (max 100 MB)'
    return
  }
  pendingName.value = f.name
  await store.scanFile(f)
}
</script>

<template>
  <header class="header">
    <div class="brand">
      <div class="logo">🛡️</div>
      <h1>FileScanner</h1>
      <span class="version">v{{ __APP_VERSION__ }}</span>
    </div>
    <div class="status" v-if="store.health">
      <span class="dot on"></span>
      Scanner actif
    </div>
  </header>

  <main>
    <!-- Zone de scan -->
    <template v-if="!store.hasResult">
      <DropZone :disabled="store.scanning" @file="onFile" />

      <div v-if="store.scanning" class="scanning">
        <div class="spinner"></div>
        <p>Analyse de <strong>{{ pendingName }}</strong> en cours…</p>
        <p class="phases">hashes · type réel · binaire · scripts · archives · YARA · ClamAV · VirusTotal</p>
      </div>

      <div v-if="store.error" class="error">✗ {{ store.error }}</div>

      <div class="features">
        <p class="features-title">Analyses effectuées</p>
        <div class="features-grid">
          <div>⚙️ Exécutables <strong>Windows (PE) · Linux (ELF) · macOS (Mach-O)</strong> — sections, imports, entropie, packers</div>
          <div>📜 Scripts <strong>PowerShell, Batch, VBS, JS, Bash, Python, PHP</strong> — appels dangereux, obfuscation</div>
          <div>📦 Archives <strong>ZIP, JAR, APK</strong> — exécutables cachés, doubles extensions, chiffrement</div>
          <div>📝 Documents <strong>Office</strong> — détection de macros VBA auto-exécutables</div>
          <div>📄 <strong>PDF</strong> — JavaScript, actions automatiques, fichiers embarqués</div>
          <div>🔗 Raccourcis <strong>LNK</strong> — commandes encodées, cibles suspectes</div>
          <div>🧬 <strong>38 règles YARA</strong> — ransomware, stealers, RATs, mineurs, webshells, bypass AV</div>
          <div>🌐 Extraction d'<strong>IoC</strong> — URLs, IPs, wallets BTC, adresses Tor, clés de registre</div>
        </div>
      </div>
    </template>

    <!-- Résultats -->
    <template v-else>
      <VerdictPanel />
      <ResultDetails />
    </template>
  </main>

  <footer class="footer">
    Analyse heuristique locale — aucun fichier conservé après le scan.
    Un verdict « sain » ne garantit pas l'absence de menace.
  </footer>
</template>

<style scoped>
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
  gap: 8px;
}
.brand { display: flex; align-items: center; gap: 10px; }
.logo { font-size: 22px; }
h1 { font-size: 18px; font-weight: 700; }
.version { font-size: 11px; color: var(--text-dim); background: var(--bg-card); border-radius: 99px; padding: 2px 8px; }
.status { font-size: 12px; color: var(--text-dim); display: flex; align-items: center; gap: 5px; }
.dot { width: 8px; height: 8px; border-radius: 99px; background: var(--text-dim); display: inline-block; }
.dot.on { background: var(--green); }

.scanning { text-align: center; margin-top: 28px; color: var(--text-muted); }
.spinner {
  width: 36px; height: 36px;
  border: 3px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  margin: 0 auto 12px;
  animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.phases { font-size: 11px; color: var(--text-dim); margin-top: 6px; }

.error {
  margin-top: 20px;
  background: #ef444415;
  border: 1px solid #ef444455;
  color: #fca5a5;
  border-radius: 10px;
  padding: 12px 16px;
}

.features { margin-top: 36px; }
.features-title {
  color: var(--text-dim);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 12px;
}
.features-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  font-size: 13px;
  color: var(--text-muted);
}
.features-grid > div {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px 14px;
}
@media (max-width: 640px) { .features-grid { grid-template-columns: 1fr; } }

.footer {
  margin-top: 48px;
  text-align: center;
  font-size: 11px;
  color: var(--text-dim);
}
</style>
