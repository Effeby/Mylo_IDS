# 🛡️ Mylo IDS — Intrusion Detection System

**Mylo** est un système de détection d'intrusions basé sur l'IA, conçu pour surveiller les réseaux d'entreprise en temps réel.

## 🏗️ Architecture

```
MYLO/
├── api/          → FastAPI (XGBoost + River inference)
├── backend/      → Django (auth, BDD, API REST)
│   ├── accounts/ → Gestion utilisateurs
│   ├── alerts/   → Alertes, blacklist, paramètres IDS
│   ├── actions/  → River online learning
│   └── reports/  → Export CSV/JSON/PDF
├── frontend/     → React/Vite (dashboard)
└── ml/           → Scripts d'entraînement + modèles
```

## 🚀 Installation

### Prérequis
- Python 3.11+
- Node.js 18+
- (Optionnel) PostgreSQL 15+

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
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend React
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

### Capture réseau (admin requis)
```bash
python ml/capture.py
```

## ⚙️ Configuration

Copiez `.env.example` en `.env` et configurez :

```env
VITE_DJANGO_URL=http://localhost:8001
VITE_FASTAPI_URL=http://localhost:8000
VITE_GROQ_API_KEY=your_groq_key
```

## 🤖 Modèle ML

- **XGBoost** entraîné sur 8 datasets (NSL-KDD, CICIDS2017, CIC-IDS2018, UNSW-NB15...)
- **9 classes** : Normal, DoS, DDoS, Probe, R2L, U2R, BruteForce, WebAttack, Botnet, Infiltration
- **River** : apprentissage en ligne (HoeffdingAdaptiveTree)
- **Accuracy globale** : 90.29%

## 📊 Fonctionnalités

- ✅ Détection temps réel (9 classes)
- ✅ Dashboard React avec KPIs
- ✅ Threat Map géographique
- ✅ Notifications Telegram
- ✅ Rapports PDF
- ✅ Copilot SOC (LLaMA 3.3 70B via Groq)
- ✅ Attack Replay
- ✅ Online Learning avec River

## 🗺️ Roadmap

- [ ] Multi-tenant (SaaS)
- [ ] RBAC (rôles et permissions)
- [ ] Audit Log
- [ ] Agent léger (déploiement distant)
- [ ] Docker / Docker Compose
- [ ] PostgreSQL support

## 📄 Licence

Projet académique — Master Réseaux & Cybersécurité, IIT Côte d'Ivoire