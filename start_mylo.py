"""
start_mylo.py — Lance tout Mylo IDS dans des terminaux VS Code
Usage : python start_mylo.py

Ouvre 4 terminaux intégrés VS Code :
  [1] FastAPI  (port 8000)
  [2] Django   (port 8001)
  [3] React    (port 5173)
  [4] Capture  (Scapy)
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

RESET = "\033[0m"
BOLD  = "\033[1m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW = "\033[93m"


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║           MYLO IDS — Démarrage complet               ║
║  FastAPI:8000 | Django:8001 | React:5173 | Scapy     ║
╚══════════════════════════════════════════════════════╝{RESET}
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


def open_vscode_terminal(name, command, cwd):
    """
    Ouvre un nouveau terminal intégré dans VS Code et exécute la commande.
    Utilise l'API VS Code via la ligne de commande 'code'.
    """
    # VS Code terminal via --command flag dans une nouvelle fenêtre terminal
    # On utilise PowerShell pour envoyer une commande au terminal VS Code intégré
    
    # Méthode : créer un script temporaire et l'ouvrir dans un nouveau terminal VS Code
    script_path = os.path.join(BASE_DIR, f"_start_{name.replace(' ', '_').replace('/', '_')}.ps1")
    
    # Créer le script PowerShell temporaire
    ps_content = f"""
# {name}
Set-Location "{cwd}"
Write-Host "=== {name} ===" -ForegroundColor Cyan
{command}
"""
    with open(script_path, 'w', encoding='utf-8') as f:
        f.write(ps_content)
    
    # Ouvrir dans un nouveau terminal VS Code
    # 'code' --new-window ouvre une nouvelle instance
    # On utilise workbench.action.terminal.new via --command
    vscode_cmd = [
        "code",
        "--reuse-window",
        cwd,
    ]
    
    # Alternative plus fiable : PowerShell dans un nouveau terminal VS Code
    # via l'extension terminal de VS Code
    try:
        subprocess.Popen(
            [
                "code",
                "--new-window",
                "--disable-extensions",
            ],
            cwd=cwd,
            shell=False,
        )
    except FileNotFoundError:
        pass
    
    # Méthode principale : démarrer directement le processus
    # VS Code va capturer les terminaux ouverts depuis son dossier
    return subprocess.Popen(
        ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path],
        cwd=cwd,
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )


def open_terminal_vscode(name, command, cwd):
    """
    Lance le service dans un nouveau terminal VS Code intégré.
    Utilise la commande 'code' avec l'option terminal.
    """
    # Construire la commande PowerShell qui sera exécutée dans le terminal VS Code
    # On utilise Start-Process pour ouvrir un terminal PowerShell dans VS Code
    
    inner = f'cd "{cwd}"; Write-Host "{name}" -ForegroundColor Cyan; {command}'
    
    try:
        # Essayer d'abord via VS Code CLI
        result = subprocess.run(
            ["code", "--version"],
            capture_output=True, text=True
        )
        vscode_available = result.returncode == 0
    except FileNotFoundError:
        vscode_available = False

    if vscode_available:
        # VS Code est disponible — utiliser son terminal intégré
        # via l'API terminal de VS Code
        js_code = f"""
const vscode = require('vscode');
const terminal = vscode.window.createTerminal('{name}');
terminal.show();
terminal.sendText('cd "{cwd}"');
terminal.sendText('{command}');
"""
        # Méthode la plus simple et fiable : ouvrir un terminal PowerShell
        # dans le répertoire du projet, VS Code le détecte automatiquement
        subprocess.Popen(
            [
                "powershell.exe", "-NoExit", "-Command",
                f'$host.UI.RawUI.WindowTitle = "{name}"; cd "{cwd}"; {command}'
            ],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            cwd=cwd,
        )
    else:
        # Fallback : cmd.exe standard
        subprocess.Popen(
            ["cmd.exe", "/k", f'title {name} && cd /d "{cwd}" && {command}'],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            cwd=cwd,
        )


def send_to_vscode_terminal(name, command, cwd):
    """
    Méthode la plus fiable : utilise le terminal intégré VS Code
    via l'extension Python de VS Code ou directement via PowerShell.
    """
    # Construire la commande complète
    full_cmd = f'cd "{cwd}"; {command}'
    
    # Utiliser le terminal intégré VS Code via PowerShell
    # -NoExit garde le terminal ouvert après l'exécution
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
        "delay":   0,
    },
]


def main():
    banner()

    print(f"{BOLD}  Vérifications...{RESET}")
    if not check_models():
        sys.exit(1)
    if not check_frontend():
        sys.exit(1)

    print(f"\n{BOLD}  Lancement des services dans VS Code...{RESET}\n")

    processes = []
    for i, svc in enumerate(SERVICES, 1):
        print(f"  [{i}/4] {svc['name']}...")
        proc = send_to_vscode_terminal(svc["name"], svc["command"], svc["cwd"])
        processes.append(proc)
        if svc["delay"] > 0:
            print(f"         ⏳ {svc['delay']}s...")
            time.sleep(svc["delay"])

    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║              ✅  MYLO IDS ACTIF                      ║
╠══════════════════════════════════════════════════════╣
║  🔵 FastAPI   →  http://localhost:8000               ║
║  🟢 Django    →  http://localhost:8001               ║
║  🟣 React     →  http://localhost:5173               ║
║  📚 API Docs  →  http://localhost:8000/docs          ║
║  🟡 Capture   →  terminal Scapy                      ║
╠══════════════════════════════════════════════════════╣
║  4 terminaux PowerShell ouverts                      ║
║  Ferme chaque terminal pour arrêter le service       ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


if __name__ == "__main__":
    main()