export type Verdict = 'Safe' | 'Suspicious' | 'Malicious' | 'Unknown'
export type Severity = 'Low' | 'Medium' | 'High' | 'Critical'

export interface Hashes {
  md5: string
  sha1: string
  sha256: string
  sha512: string
}

export interface BinarySection {
  name: string
  virtual_size: number
  raw_size: number
  entropy: number
}

export interface BinaryInfo {
  format: string
  is_64bit: boolean
  is_signed: boolean
  sections: BinarySection[]
  imports: string[]
  entry_point: number
  entropy_max: number
  suspicious_imports: string[]
  is_packed: boolean
}

export interface ScriptMatchedLine {
  line_number: number
  pattern: string
  line_content: string
}

export interface ScriptInfo {
  obfuscation_detected: boolean
  dangerous_calls: string[]
  base64_blobs_count: number
  script_type: string
  matched_lines: ScriptMatchedLine[]
  base64_samples: string[]
}

export interface ArchiveEntry {
  name: string
  size: number
  compressed_size: number
  is_executable: boolean
  is_encrypted: boolean
}

export interface ArchiveInfo {
  archive_type: string
  total_entries: number
  entries: ArchiveEntry[]
  has_nested_executable: boolean
  has_double_extension: boolean
  has_encrypted_entries: boolean
  has_vba_macros: boolean
  vba_keywords: string[]
}

export interface PdfInfo {
  has_javascript: boolean
  has_open_action: boolean
  has_launch_action: boolean
  has_embedded_files: boolean
  has_acroform: boolean
  suspicious_count: number
}

export interface LnkInfo {
  target_hint: string
  suspicious_args: string[]
}

export interface ExtractedIoCs {
  urls: string[]
  ips: string[]
  emails: string[]
  btc_wallets: string[]
  onion_addresses: string[]
  registry_keys: string[]
}

export interface VtResult {
  positives: number
  total: number
  permalink: string
  scan_date: string
  detection_names: string[]
}

export interface YaraMatch {
  rule_name: string
  description: string
  severity: Severity
  matched_strings: string[]
}

export interface IoC {
  ioc_type: string
  value: string
  severity: Severity
  description: string
}

export interface ClamavResult {
  malware_name: string
  database: string
}

export interface ScanResult {
  file_name: string
  file_size: number
  mime_type: string
  category: string
  hashes: Hashes
  global_entropy: number
  verdict: Verdict
  verdict_score: number
  binary_info: BinaryInfo | null
  script_info: ScriptInfo | null
  archive_info: ArchiveInfo | null
  pdf_info: PdfInfo | null
  lnk_info: LnkInfo | null
  extracted_iocs: ExtractedIoCs
  virustotal: VtResult | null
  clamav: ClamavResult | null
  yara_matches: YaraMatch[]
  ioc_list: IoC[]
  scanned_at: string
}

export interface HealthStatus {
  status: string
  version: string
  clamav: { loaded: boolean; md5_count: number; sha256_count: number } | null
  virustotal: boolean
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  Low: '#64748b',
  Medium: '#eab308',
  High: '#f97316',
  Critical: '#ef4444',
}

export const SEVERITY_LABELS: Record<Severity, string> = {
  Low: 'FAIBLE',
  Medium: 'MOYEN',
  High: 'ÉLEVÉ',
  Critical: 'CRITIQUE',
}
