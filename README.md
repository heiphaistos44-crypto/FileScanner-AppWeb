# FileScanner Web

## Démonstration

https://github.com/heiphaistos44-crypto/FileScanner-AppWeb/releases/download/v1.0.0/filescanner.mp4


Version web de [FileScanner](https://github.com/heiphaistos44-crypto/FileScanner) — analyse antivirus de fichiers en ligne, **grandement améliorée** par rapport à la version desktop.

**Prod : https://filescanner.heiphaistos.org**

## Améliorations vs desktop v1.1.0

| Domaine | Desktop | Web |
|---|---|---|
| Binaires | PE uniquement | **PE + ELF (Linux) + Mach-O (macOS)** |
| Hashes | MD5, SHA-256 | **+ SHA-1, SHA-512** |
| Scripts | BAT/PS1/VBS/JS | **+ Bash, Python, PHP, Perl, Ruby + 21 patterns** (AMSI bypass, vssadmin, reverse shells…) |
| Archives | non analysées | **ZIP/JAR/APK : exécutables imbriqués, doubles extensions, entrées chiffrées** |
| Office | non analysé | **Détection macros VBA + mots-clés auto-exec (AutoOpen, Shell…)** |
| PDF | non analysé | **/JavaScript, /OpenAction, /Launch, /EmbeddedFile, XFA** |
| LNK | non analysé | **Cible + arguments suspects (PowerShell encodé…)** |
| Règles YARA | 13 | **38** (stealers, RATs, miners, webshells, Cobalt Strike, bypass AV…) |
| IoC strings | non | **Extraction URLs, IPs, emails, wallets BTC, .onion, clés registre** |
| ClamAV | base locale utilisateur | **Base serveur (main+daily.cvd) chargée au démarrage** |
| VirusTotal | clé API utilisateur | **Clé serveur partagée (env `VT_API_KEY`)** |

## Architecture

- `server/` — Rust **axum** : API + frontend statique. Pipeline 100% en mémoire (aucun fichier conservé).
- `web/` — **Vue 3 + Pinia + Vite** : UI sombre, score gauge, sections par analyseur, export JSON/TXT.
- `deploy/` — script déploiement + vhost nginx.

### API

| Route | Méthode | Détail |
|-------|---------|--------|
| `/api/scan` | POST | multipart `file` → ScanResult JSON complet |
| `/api/health` | GET | `{status, version, clamav: {...}, virustotal}` |

### Protections (accès public)

- Upload max **100 MB**
- Rate-limit **10 scans/min/IP**
- Max **2 scans simultanés** (sémaphore)
- Timeout scan 120 s
- Fichiers jamais écrits sur disque (analyse en RAM)
- Écoute `127.0.0.1:3004` (exposé via nginx)

## Dev local

```bash
cd server && cargo run              # backend :3004
cd web && npm install && npm run dev  # frontend :1422 (proxy /api)

# Optionnel :
# VT_API_KEY=<clé>          → active VirusTotal
# CLAMAV_DB_DIR=<dossier>   → active ClamAV (fichiers .cvd/.hdb/.msb)
```

## Déploiement VPS (212.227.140.45)

```bash
# 1. Build frontend local : cd web && npm run build
# 2. Sync vers /opt/filescanner puis :
cd /opt/filescanner && bash deploy/deploy.sh

# 3. nginx (une fois) :
cp deploy/nginx-filescanner.conf /etc/nginx/sites-available/filescanner
ln -s /etc/nginx/sites-available/filescanner /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
certbot --nginx -d filescanner.heiphaistos.org --non-interactive --agree-tos --redirect

# 4. DNS Ionos : A filescanner → 212.227.140.45
```

## Versions

- **1.0.0** (2026-06-11) — portage web + refonte majeure du scanner depuis FileScanner desktop v1.1.0
