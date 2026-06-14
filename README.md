# 🛡️ Mylo — Système Intelligent d'Analyse et de Réponse aux Incidents

**Mylo** est un système de détection et de réponse aux intrusions basé sur l'IA, conçu pour surveiller les réseaux d'entreprise en temps réel. Il combine une capture réseau passive (Scapy), une classification XGBoost multi-classes, un apprentissage en ligne (River), et une intégration SIEM via Wazuh.

## 🏗️ Architecture
MYLO/

├── api/          → FastAPI (XGBoost + River — inférence ML)

├── backend/      → Django (auth, BDD, API REST, Celery)

│   ├── accounts/ → Gestion utilisateurs + TOTP (2FA)

│   ├── alerts/   → Alertes, blacklist, corrélation, SIEM

│   ├── actions/  → River online learning

│   └── reports/  → Export CSV/JSON/PDF

├── frontend/     → React/Vite (SOC dashboard)

├── ml/           → Scripts d'entraînement + modèles XGBoost

└── docker-compose.yml → Déploiement complet conteneurisé

## 🚀 Déploiement (Docker — recommandé)

### Prérequis
- Docker Desktop (Windows/macOS) ou Docker Engine (Linux)
- 8 GB RAM minimum recommandés

### Lancement complet
```bash
cp .env.exemple .env
# Éditez .env avec vos paramètres

docker compose up -d db redis api backend celery-worker celery-beat frontend
```

### Vérification
```bash
docker compose ps -a
```

Accès :
- **Frontend** → http://localhost:5173
- **API Django** → http://localhost:8001
- **API FastAPI** → http://localhost:8000

> ⚠️ Le service `capture` nécessite Linux avec accès aux interfaces réseau (BanqueAdmin/Ubuntu en production). Il n'est pas lancé en développement local.

---

## 🛠️ Installation manuelle (développement)

### Prérequis
- Python 3.11+
- Node.js 18+
- PostgreSQL 15+ (ou SQLite en dev)
- Redis

### Backend Django
```bash
cd backend
pip install -r ../requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 8001
```

### API FastAPI
```bash
cd api
uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir /app/api --reload
```

### Frontend React
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

### Celery (tâches planifiées)
```bash
# Worker
celery -A core worker --loglevel=info

# Beat (scheduler)
celery -A core beat --loglevel=info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

### Capture réseau (Linux uniquement, admin requis)
```bash
python ml/capture.py
```

---

## ⚙️ Configuration

Copiez `.env.exemple` en `.env` et configurez :

```env
VITE_DJANGO_URL=http://localhost:8001
VITE_FASTAPI_URL=http://localhost:8000
VITE_GROQ_API_KEY=your_groq_key

# PostgreSQL
POSTGRES_DB=mylo_db
POSTGRES_USER=your_user
POSTGRES_PASSWORD=your_password

# Wazuh SIEM
WAZUH_URL=https://172.16.30.20:55000
WAZUH_USER=your_wazuh_user
WAZUH_PASSWORD=your_wazuh_password

# Telegram
TELEGRAM_BOT_TOKEN=your_token
TELEGRAM_CHAT_ID=your_chat_id
```

---

## 🤖 Modèle ML

- **XGBoost** entraîné sur 8 datasets combinés (NSL-KDD, CICIDS2017, CIC-IDS2018, CICDDoS2019, UNSW-NB15...)
- **10 classes** : Normal, DoS, DDoS, Probe, R2L, U2R, BruteForce, WebAttack, Botnet, Infiltration
- **River** : apprentissage en ligne (HoeffdingAdaptiveTree) — adaptation continue au trafic réel
- **Accuracy globale** : ~90%
- Images publiées sur Docker Hub : `dydybinks1/mylo-*:1.0.0`

---

## 📊 Fonctionnalités

- ✅ Détection temps réel (10 classes d'attaques)
- ✅ Capture réseau passive multi-interfaces (Scapy)
- ✅ Intégration SIEM Wazuh (polling toutes les 10s via Celery)
- ✅ Blocage automatique IP via OPNsense REST API
- ✅ Dashboard SOC React avec KPIs
- ✅ Live Monitor & alertes en temps réel
- ✅ Analyse comportementale (IPBaseline, Z-score, Welford)
- ✅ Corrélation d'alertes (9 patterns d'attaque)
- ✅ Découverte d'assets (ARP + Nmap)
- ✅ Notifications Telegram
- ✅ Rapports PDF planifiés
- ✅ Copilot SOC (LLaMA 3.3 70B via Groq)
- ✅ Double authentification TOTP (2FA)
- ✅ RBAC multi-tenant
- ✅ Audit Log
- ✅ Online Learning avec River

## 🖥️ Infrastructure lab (VirtualBox)

| VM | OS | IP | Rôle |
|---|---|---|---|
| OPNsense | FreeBSD | 172.16.1.1 | Routeur/Firewall |
| BanqueAdmin | Ubuntu 24.04 | 172.16.1.94 | Hôte Docker Mylo |
| dmzserveur | Ubuntu | 172.16.30.20 | Wazuh SIEM Manager |
| WindowsServer | Windows Server 2019 | 172.16.1.10 | DC waribank.local |
| ClientWin1 | Windows 10 | 172.16.20.136 | Poste client |
| Kali Linux | Kali | — | Attaquant (tests) |

## 📄 Licence

Projet académique — Master 2 Réseaux, Systèmes & Sécurité  
Institut Ivoirien de Technologie (IIT), Grand-Bassam, Côte d'Ivoire
