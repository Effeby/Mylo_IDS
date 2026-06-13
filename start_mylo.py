"""
start_mylo.py — Lance tout Mylo IPS dans des terminaux VS Code
Usage : python start_mylo.py

Ouvre 5 terminaux intégrés VS Code :
  [1] FastAPI  (port 8000)
  [2] Django   (port 8001)
  [3] React    (port 5173)
  [4] Capture  (Scapy)
  [5] Syslog   (UDP 5140)
"""

import subprocess
import sys
import time
import os

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
VENV_PY      = os.path.join(BASE_DIR, "venv", "Scripts", "python.exe")
PYTHON       = VENV_PY if os.path.exists(VENV_PY) else sys.executable
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
NPM          = "npm.cmd"

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║           Mylo IPS — Démarrage complet                   ║
║  FastAPI:8000 | Django:8001 | React:5173 | Syslog:5140   ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def check_models():
    required = [
        os.path.join(BASE_DIR, "ml", "models", "mylo_xgb_binary.pkl"),
        os.path.join(BASE_DIR, "ml", "models", "mylo_xgb_multiclass.pkl"),
        os.path.join(BASE_DIR, "ml", "models", "label_encoder.pkl"),
        os.path.join(BASE_DIR, "ml", "models", "xgb_features.pkl"),
    ]
    missing = [f for f in required if not os.path.exists(f)]
    if missing:
        print(f"{RED}❌  Modèles manquants :{RESET}")
        for f in missing:
            print(f"     • {os.path.basename(f)}")
        print(f"\n  Lance d'abord : python ml/train_xgb.py\n")
        return False
    print(f"{GREEN}  ✅  Modèles ML vérifiés{RESET}")
    return True


def check_frontend():
    nm = os.path.join(FRONTEND_DIR, "node_modules")
    if not os.path.exists(nm):
        print(f"{RED}❌  node_modules absent — lance : cd frontend && npm install{RESET}")
        return False
    print(f"{GREEN}  ✅  Frontend vérifié{RESET}")
    return True


def check_syslog_script():
    script = os.path.join(BASE_DIR, "scripts", "syslog_server.py")
    if not os.path.exists(script):
        print(f"{YELLOW}  ⚠️  scripts/syslog_server.py absent — Syslog désactivé{RESET}")
        return False
    print(f"{GREEN}  ✅  Syslog server vérifié{RESET}")
    return True


def send_to_vscode_terminal(name, command, cwd):
    full_cmd = f'cd "{cwd}"; {command}'
    proc = subprocess.Popen(
        [
            "powershell.exe",
            "-NoExit",
            "-ExecutionPolicy", "Bypass",
            "-Command", full_cmd,
        ],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        cwd=cwd,
    )
    return proc


def main():
    banner()

    print(f"{BOLD}  Vérifications...{RESET}")
    if not check_models():
        sys.exit(1)
    if not check_frontend():
        sys.exit(1)
    syslog_ok = check_syslog_script()

    SERVICES = [
        {
            "name":    "MYLO — FastAPI :8000",
            "command": f'& "{PYTHON}" -m uvicorn api.main:app --reload --port 8000 --host 0.0.0.0',
            "cwd":     BASE_DIR,
            "delay":   3,
        },
        {
            "name":    "MYLO — Django :8001",
            "command": f'& "{PYTHON}" manage.py runserver 8001',
            "cwd":     os.path.join(BASE_DIR, "backend"),
            "delay":   3,
        },
        {
            "name":    "MYLO — React :5173",
            "command": f'& "{NPM}" run dev',
            "cwd":     FRONTEND_DIR,
            "delay":   2,
        },
        {
            "name":    "MYLO — Capture Scapy",
            "command": f'& "{PYTHON}" ml/capture.py',
            "cwd":     BASE_DIR,
            "delay":   1,
        },
    ]

    # Ajouter Syslog si le script existe
    if syslog_ok:
        SERVICES.append({
            "name":    "MYLO — Syslog UDP:5140",
            "command": f'& "{PYTHON}" scripts/syslog_server.py',
            "cwd":     BASE_DIR,
            "delay":   0,
        })

    total = len(SERVICES)
    print(f"\n{BOLD}  Lancement de {total} services...{RESET}\n")

    for i, svc in enumerate(SERVICES, 1):
        print(f"  [{i}/{total}] {svc['name']}...")
        send_to_vscode_terminal(svc["name"], svc["command"], svc["cwd"])
        if svc["delay"] > 0:
            print(f"         ⏳ {svc['delay']}s...")
            time.sleep(svc["delay"])

    syslog_line = "║  🔴 Syslog    →  UDP:5140 (logs réseau)              ║" if syslog_ok else "║  ⚠️  Syslog    →  Absent (scripts/syslog_server.py)  ║"

    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║              ✅  Mylo IPS ACTIF                      ║
╠══════════════════════════════════════════════════════╣
║  🔵 FastAPI   →  http://localhost:8000               ║
║  🟢 Django    →  http://localhost:8001               ║
║  🟣 React     →  http://localhost:5173               ║
║  📚 API Docs  →  http://localhost:8000/docs          ║
║  🟡 Capture   →  terminal Scapy                      ║
{syslog_line}
╠══════════════════════════════════════════════════════╣
║  {total} terminaux PowerShell ouverts                      ║
║  Ferme chaque terminal pour arrêter le service       ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


if __name__ == "__main__":
    main()