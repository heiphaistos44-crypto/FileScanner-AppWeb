<script setup lang="ts">
import { computed } from 'vue'
import { useScanStore } from '../stores/scan'
import { formatBytes, SEVERITY_LABELS } from '../types/scan'
import SectionCard from './SectionCard.vue'

const store = useScanStore()
const r = computed(() => store.result!)

const iocsTotal = computed(() => {
  const e = r.value.extracted_iocs
  return e.urls.length + e.ips.length + e.emails.length + e.btc_wallets.length
    + e.onion_addresses.length + e.registry_keys.length
})
</script>

<template>
  <div>
    <!-- Hashes -->
    <SectionCard title="🔑 Empreintes (hashes)" :default-open="false">
      <dl class="kv">
        <dt>MD5</dt><dd class="mono">{{ r.hashes.md5 }}</dd>
        <dt>SHA-1</dt><dd class="mono">{{ r.hashes.sha1 }}</dd>
        <dt>SHA-256</dt><dd class="mono">{{ r.hashes.sha256 }}</dd>
        <dt>SHA-512</dt><dd class="mono">{{ r.hashes.sha512 }}</dd>
      </dl>
    </SectionCard>

    <!-- YARA -->
    <SectionCard
      v-if="r.yara_matches.length > 0"
      title="🧬 Règles YARA déclenchées"
      :count="r.yara_matches.length"
      :default-open="true"
    >
      <table>
        <thead><tr><th>Sévérité</th><th>Règle</th><th>Description</th><th>Motifs</th></tr></thead>
        <tbody>
          <tr v-for="m in r.yara_matches" :key="m.rule_name">
            <td><span class="sev" :class="`sev-${m.severity}`">{{ SEVERITY_LABELS[m.severity] }}</span></td>
            <td class="mono">{{ m.rule_name }}</td>
            <td>{{ m.description }}</td>
            <td class="mono" style="color: var(--text-dim)">{{ m.matched_strings.slice(0, 3).join(', ') }}</td>
          </tr>
        </tbody>
      </table>
    </SectionCard>

    <!-- IoC -->
    <SectionCard
      v-if="r.ioc_list.length > 0"
      title="🚩 Indicateurs de compromission"
      :count="r.ioc_list.length"
      :default-open="true"
    >
      <table>
        <thead><tr><th>Sévérité</th><th>Type</th><th>Valeur</th><th>Description</th></tr></thead>
        <tbody>
          <tr v-for="(ioc, i) in r.ioc_list" :key="i">
            <td><span class="sev" :class="`sev-${ioc.severity}`">{{ SEVERITY_LABELS[ioc.severity] }}</span></td>
            <td>{{ ioc.ioc_type }}</td>
            <td class="mono">{{ ioc.value }}</td>
            <td style="color: var(--text-muted)">{{ ioc.description }}</td>
          </tr>
        </tbody>
      </table>
    </SectionCard>

    <!-- Binaire -->
    <SectionCard v-if="r.binary_info" :title="`⚙️ Binaire ${r.binary_info.format}`">
      <dl class="kv">
        <dt>Format</dt><dd>{{ r.binary_info.format }} {{ r.binary_info.is_64bit ? '64-bit' : '32-bit' }}</dd>
        <dt>Signé</dt><dd>{{ r.binary_info.is_signed ? 'Oui ✓' : 'Non' }}</dd>
        <dt>Packé</dt><dd :style="r.binary_info.is_packed ? 'color: var(--orange)' : ''">{{ r.binary_info.is_packed ? 'Probable ⚠' : 'Non détecté' }}</dd>
        <dt>Entry point</dt><dd class="mono">0x{{ r.binary_info.entry_point.toString(16) }}</dd>
        <dt>Entropie max</dt><dd>{{ r.binary_info.entropy_max.toFixed(2) }}</dd>
        <dt>Imports</dt><dd>{{ r.binary_info.imports.length }} ({{ r.binary_info.suspicious_imports.length }} suspects)</dd>
      </dl>
      <div v-if="r.binary_info.suspicious_imports.length > 0" style="margin-top: 8px">
        <p style="color: var(--text-dim); font-size: 12px; margin-bottom: 4px">Imports suspects :</p>
        <span v-for="imp in r.binary_info.suspicious_imports" :key="imp" class="chip danger">{{ imp }}</span>
      </div>
      <div v-if="r.binary_info.sections.length > 0" style="margin-top: 12px">
        <table>
          <thead><tr><th>Section</th><th>Taille brute</th><th>Taille virtuelle</th><th>Entropie</th></tr></thead>
          <tbody>
            <tr v-for="s in r.binary_info.sections" :key="s.name">
              <td class="mono">{{ s.name }}</td>
              <td>{{ formatBytes(s.raw_size) }}</td>
              <td>{{ formatBytes(s.virtual_size) }}</td>
              <td :style="s.entropy > 7.2 ? 'color: var(--orange); font-weight: 600' : ''">{{ s.entropy.toFixed(2) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </SectionCard>

    <!-- Script -->
    <SectionCard v-if="r.script_info" :title="`📜 Script ${r.script_info.script_type}`">
      <dl class="kv">
        <dt>Obfuscation</dt><dd :style="r.script_info.obfuscation_detected ? 'color: var(--orange)' : ''">{{ r.script_info.obfuscation_detected ? 'Détectée ⚠' : 'Non détectée' }}</dd>
        <dt>Blobs Base64</dt><dd>{{ r.script_info.base64_blobs_count }}</dd>
        <dt>Appels dangereux</dt><dd>{{ r.script_info.dangerous_calls.length }}</dd>
      </dl>
      <div v-if="r.script_info.dangerous_calls.length > 0" style="margin-top: 4px">
        <span v-for="c in r.script_info.dangerous_calls" :key="c" class="chip warn">{{ c }}</span>
      </div>
      <div v-if="r.script_info.matched_lines.length > 0" style="margin-top: 12px">
        <table>
          <thead><tr><th>Ligne</th><th>Motif</th><th>Contenu</th></tr></thead>
          <tbody>
            <tr v-for="(l, i) in r.script_info.matched_lines.slice(0, 20)" :key="i">
              <td>{{ l.line_number }}</td>
              <td class="mono">{{ l.pattern }}</td>
              <td class="mono" style="color: var(--text-muted)">{{ l.line_content }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </SectionCard>

    <!-- Archive -->
    <SectionCard
      v-if="r.archive_info"
      :title="`📦 Archive ${r.archive_info.archive_type}`"
      :count="r.archive_info.total_entries"
    >
      <dl class="kv">
        <dt>Entrées</dt><dd>{{ r.archive_info.total_entries }}</dd>
        <dt>Exécutable imbriqué</dt><dd :style="r.archive_info.has_nested_executable ? 'color: var(--orange)' : ''">{{ r.archive_info.has_nested_executable ? 'Oui ⚠' : 'Non' }}</dd>
        <dt>Double extension</dt><dd :style="r.archive_info.has_double_extension ? 'color: var(--red)' : ''">{{ r.archive_info.has_double_extension ? 'Oui ⚠⚠' : 'Non' }}</dd>
        <dt>Entrées chiffrées</dt><dd :style="r.archive_info.has_encrypted_entries ? 'color: var(--orange)' : ''">{{ r.archive_info.has_encrypted_entries ? 'Oui ⚠' : 'Non' }}</dd>
        <dt>Macros VBA</dt><dd :style="r.archive_info.has_vba_macros ? 'color: var(--red)' : ''">{{ r.archive_info.has_vba_macros ? 'Oui ⚠' : 'Non' }}</dd>
      </dl>
      <div v-if="r.archive_info.vba_keywords.length > 0" style="margin-top: 4px">
        <p style="color: var(--text-dim); font-size: 12px; margin-bottom: 4px">Mots-clés VBA détectés :</p>
        <span v-for="k in r.archive_info.vba_keywords" :key="k" class="chip danger">{{ k }}</span>
      </div>
      <div v-if="r.archive_info.entries.length > 0" style="margin-top: 12px; max-height: 300px; overflow-y: auto">
        <table>
          <thead><tr><th>Fichier</th><th>Taille</th><th></th></tr></thead>
          <tbody>
            <tr v-for="e in r.archive_info.entries" :key="e.name">
              <td class="mono" :style="e.is_executable ? 'color: var(--orange)' : ''">{{ e.name }}</td>
              <td>{{ formatBytes(e.size) }}</td>
              <td>
                <span v-if="e.is_executable" class="sev sev-High">EXÉCUTABLE</span>
                <span v-if="e.is_encrypted" class="sev sev-Medium">CHIFFRÉ</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </SectionCard>

    <!-- PDF -->
    <SectionCard v-if="r.pdf_info" title="📄 Analyse PDF">
      <dl class="kv">
        <dt>JavaScript</dt><dd :style="r.pdf_info.has_javascript ? 'color: var(--red)' : ''">{{ r.pdf_info.has_javascript ? 'Présent ⚠' : 'Absent' }}</dd>
        <dt>Action à l'ouverture</dt><dd :style="r.pdf_info.has_open_action ? 'color: var(--orange)' : ''">{{ r.pdf_info.has_open_action ? 'Oui ⚠' : 'Non' }}</dd>
        <dt>Action /Launch</dt><dd :style="r.pdf_info.has_launch_action ? 'color: var(--red)' : ''">{{ r.pdf_info.has_launch_action ? 'Oui ⚠⚠' : 'Non' }}</dd>
        <dt>Fichiers embarqués</dt><dd :style="r.pdf_info.has_embedded_files ? 'color: var(--orange)' : ''">{{ r.pdf_info.has_embedded_files ? 'Oui ⚠' : 'Non' }}</dd>
        <dt>Formulaire XFA</dt><dd>{{ r.pdf_info.has_acroform ? 'Oui' : 'Non' }}</dd>
      </dl>
    </SectionCard>

    <!-- LNK -->
    <SectionCard v-if="r.lnk_info" title="🔗 Raccourci Windows (LNK)">
      <dl class="kv">
        <dt>Cible</dt><dd class="mono">{{ r.lnk_info.target_hint }}</dd>
      </dl>
      <div v-if="r.lnk_info.suspicious_args.length > 0" style="margin-top: 4px">
        <p style="color: var(--text-dim); font-size: 12px; margin-bottom: 4px">Arguments suspects :</p>
        <span v-for="a in r.lnk_info.suspicious_args" :key="a" class="chip danger">{{ a }}</span>
      </div>
    </SectionCard>

    <!-- IOCs extraits -->
    <SectionCard v-if="iocsTotal > 0" title="🌐 Artefacts extraits (strings)" :count="iocsTotal">
      <template v-for="(list, label) in {
        'URLs': r.extracted_iocs.urls,
        'Adresses IP': r.extracted_iocs.ips,
        'Emails': r.extracted_iocs.emails,
        'Wallets Bitcoin': r.extracted_iocs.btc_wallets,
        'Adresses .onion': r.extracted_iocs.onion_addresses,
        'Clés de registre': r.extracted_iocs.registry_keys,
      }" :key="label">
        <div v-if="list.length > 0" style="margin-top: 10px">
          <p style="color: var(--text-dim); font-size: 12px; font-weight: 600">{{ label }} ({{ list.length }})</p>
          <ul class="plain mono" style="font-size: 12px; color: var(--text-muted); max-height: 180px; overflow-y: auto">
            <li v-for="v in list" :key="v">{{ v }}</li>
          </ul>
        </div>
      </template>
    </SectionCard>

    <!-- VirusTotal -->
    <SectionCard v-if="r.virustotal" title="🛡️ VirusTotal" :default-open="true">
      <dl class="kv">
        <dt>Détections</dt>
        <dd :style="r.virustotal.positives > 0 ? 'color: var(--red); font-weight: 700' : 'color: var(--green)'">
          {{ r.virustotal.positives }} / {{ r.virustotal.total }}
        </dd>
        <dt>Dernier scan</dt><dd>{{ r.virustotal.scan_date }}</dd>
        <dt>Lien</dt><dd><a :href="r.virustotal.permalink" target="_blank" rel="noopener" style="color: var(--accent)">Voir sur VirusTotal ↗</a></dd>
      </dl>
      <div v-if="r.virustotal.detection_names.length > 0" style="margin-top: 4px">
        <span v-for="n in r.virustotal.detection_names" :key="n" class="chip danger">{{ n }}</span>
      </div>
    </SectionCard>
  </div>
</template>
