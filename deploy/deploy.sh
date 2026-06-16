#!/bin/bash
# deploy.sh — Déploiement FileScanner Web sur VPS Debian 13
# Usage : exécuter SUR le VPS depuis /opt/filescanner
set -euo pipefail

APP_DIR="/opt/filescanner"
CLAMAV_DIR="$APP_DIR/clamav-db"
LOG() { echo "[$(date -Iseconds)] [INFO] $*"; }

cd "$APP_DIR"

# ── 1. Rust toolchain ──────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
    source "$HOME/.cargo/env" 2>/dev/null || {
        LOG "Installation rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    }
fi
source "$HOME/.cargo/env" 2>/dev/null || true

# ── 2. Bases ClamAV (hash signatures) ──────────────────────────────
mkdir -p "$CLAMAV_DIR"
if [ ! -f "$CLAMAV_DIR/daily.cvd" ]; then
    LOG "Téléchargement daily.cvd ClamAV (~60 MB)..."
    curl -sL "https://database.clamav.net/daily.cvd" -o "$CLAMAV_DIR/daily.cvd" || \
        LOG "WARN: téléchargement daily.cvd échoué — ClamAV désactivé"
fi
if [ ! -f "$CLAMAV_DIR/main.cvd" ]; then
    LOG "Téléchargement main.cvd ClamAV (~170 MB)..."
    curl -sL "https://database.clamav.net/main.cvd" -o "$CLAMAV_DIR/main.cvd" || \
        LOG "WARN: téléchargement main.cvd échoué"
fi

# ── 3. Build frontend Vue ──────────────────────────────────────────
LOG "Build frontend Vue 3..."
cd "$APP_DIR/web"
npm ci --prefer-offline
npm run build
LOG "Frontend buildé dans $APP_DIR/web/dist"

# ── 4. Build serveur Rust ──────────────────────────────────────────
LOG "cargo build --release..."
cd "$APP_DIR/server"
cargo build --release
LOG "Binaire : $APP_DIR/server/target/release/filescanner-server"

# ── 5. PM2 ─────────────────────────────────────────────────────────
cd "$APP_DIR"
if pm2 describe filescanner >/dev/null 2>&1; then
    LOG "Restart PM2 filescanner..."
    pm2 restart filescanner --update-env
else
    LOG "Création process PM2 filescanner (port 3004)..."
    STATIC_DIR="$APP_DIR/web/dist" \
    PORT=3004 \
    CLAMAV_DB_DIR="$CLAMAV_DIR" \
    pm2 start "$APP_DIR/server/target/release/filescanner-server" --name filescanner
    pm2 save
fi

# ── 6. Vérification ────────────────────────────────────────────────
sleep 3
curl -fsS http://127.0.0.1:3004/api/health && echo "" && LOG "Déploiement OK ✅"