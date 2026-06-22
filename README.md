<div align="center">
  <h1>🔍 FileScanner AppWeb</h1>
  <p><strong>Scanner de fichiers web — analyse malware, hashes cryptographiques, YARA et PE via interface drag & drop.</strong></p>

  ![Version](https://img.shields.io/badge/version-1.0.0-blue)
  ![Stack](https://img.shields.io/badge/stack-Rust%20%2B%20Axum%20%2B%20Vue%203-purple)
  ![Platform](https://img.shields.io/badge/platform-Web%20%2F%20Docker-informational)
  ![Prod](https://img.shields.io/badge/prod-filescanner--app.heiphaistos.org-brightgreen)
  ![License](https://img.shields.io/badge/licence-MIT-green)
</div>

---

## 📋 Description

FileScanner AppWeb est un scanner de fichiers accessible depuis le navigateur. Uploadez un ou plusieurs fichiers et obtenez instantanément : empreintes cryptographiques (MD5, SHA1, SHA256), analyse YARA avec règles configurables, parsing des headers PE Windows et détection de patterns malveillants.

**URL de production** : [https://filescanner-app.heiphaistos.org](https://filescanner-app.heiphaistos.org)

---

## ✨ Fonctionnalités

- **Upload multi-fichiers** : interface drag & drop, validation MIME + taille côté serveur
- **Calcul de hashes** : MD5, SHA1, SHA256 pour chaque fichier analysé
- **Règles YARA configurables** : chargement de règles personnalisées, résultats par règle
- **Analyse PE headers** : sections, imports DLL, exports, entrypoint, timestamps
- **Détection malware** : patterns suspects, signatures connues
- **Résultats en temps réel** : affichage progressif pendant l'analyse
- **API REST Rust/Axum** : backend performant, zéro copie sur les buffers de fichiers

---

## 🛠️ Stack technique

| Couche | Technologies |
|--------|-------------|
| Frontend | Vue 3 + TypeScript + Vite |
| Backend | Rust + Axum |
| Hashing | sha2 + md5 crates |
| Analyse YARA | yara-rust |
| Parsing PE | goblin |
| Conteneurisation | Docker + Docker Compose |
| Reverse proxy | nginx (VPS) |
| Process manager | PM2 (port 3004) |

---

## 🚀 Installation & Déploiement

### Prérequis

- Docker + Docker Compose
- Node.js 18+ (développement frontend)
- Rust stable + libyara (développement backend)

### Démarrage rapide (Docker)

```bash
# Cloner le dépôt
git clone https://mydepot.heiphaistos.org/Heiphaistos/FileScanner-AppWeb.git
cd FileScanner-AppWeb

# Configurer les variables d'environnement
cp .env.example .env
# Éditer .env : JWT_SECRET, ALLOWED_ORIGINS, MAX_FILE_SIZE, YARA_RULES_DIR

# Lancer les conteneurs
docker compose up -d

# Vérifier le statut
docker compose ps
```

### Développement local

```bash
# Backend Rust
cd backend
cargo run

# Frontend Vue 3 (dans un autre terminal)
cd frontend
npm install
npm run dev
```

### Variables d'environnement

| Variable | Description | Exemple |
|----------|-------------|---------|
| `JWT_SECRET` | Secret de signature JWT (min. 32 chars) | `changeme_prod_secret` |
| `ALLOWED_ORIGINS` | CORS whitelist | `https://filescanner-app.heiphaistos.org` |
| `MAX_FILE_SIZE` | Taille max upload (bytes) | `52428800` |
| `YARA_RULES_DIR` | Dossier des règles YARA | `./rules/` |
| `PORT` | Port d'écoute backend | `3004` |

---

## 📂 Architecture

```
FileScanner-AppWeb/
├── backend/
│   ├── src/
│   │   ├── main.rs            # Entrée Axum, routes
│   │   ├── handlers/
│   │   │   └── scan.rs        # Upload + pipeline d'analyse
│   │   ├── services/
│   │   │   ├── hash.rs        # MD5 / SHA1 / SHA256
│   │   │   ├── yara.rs        # Moteur YARA
│   │   │   └── pe_parser.rs   # Analyse PE headers
│   │   └── middleware/
│   │       ├── auth.rs        # JWT middleware
│   │       └── rate_limit.rs  # Tower governor
│   └── Cargo.toml
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── FileDropzone.vue   # Zone drag & drop
│   │   │   ├── ScanResults.vue    # Affichage résultats
│   │   │   └── HashDisplay.vue    # Hashes calculés
│   │   └── api/                   # Appels API typés
│   └── package.json
├── rules/
│   └── *.yar                  # Règles YARA par défaut
├── docker-compose.yml
└── .env.example
```

---

## 🔒 Sécurité

- Validation MIME + extension + taille sur chaque upload (serveur, jamais client seul)
- Rate limiting via `tower_governor` — prévention abus upload
- Fichiers analysés en mémoire, jamais persistés sur disque
- CORS restreint à l'origine de production
- Aucune stack trace exposée dans les réponses d'erreur
- Healthcheck Docker sur `127.0.0.1` (pas `localhost`)

---

## 📝 Licence

MIT — © 2026 Heiphaistos
