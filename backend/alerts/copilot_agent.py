# backend/alerts/copilot_agent.py
import os
import json
from groq import Groq

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# ── Définition des tools ──────────────────────────────────────────────
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_recent_alerts",
            "description": "Récupère les alertes récentes de Mylo IPS",
            "parameters": {
                "type": "object",
                "properties": {
                    "attack_type": {
                        "type": "string",
                        "description": "Type d'attaque: DoS, R2L, Probe, Normal, Behavioral, Anomalie"
                    },
                    "limit": {"type": "integer", "description": "Nombre d'alertes (max 20)"},
                    "severity": {"type": "string", "description": "LOW, MEDIUM, HIGH, CRITICAL"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "whitelist_ip",
            "description": "Ajoute une IP à la whitelist pour qu'elle ne génère plus d'alertes",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP à whitelister"},
                    "description": {"type": "string", "description": "Raison du whitelisting"}
                },
                "required": ["ip_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "blacklist_ip",
            "description": "Bloque une IP suspecte",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP à bloquer"},
                    "reason": {"type": "string", "description": "Raison du blocage"}
                },
                "required": ["ip_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_stats",
            "description": "Retourne les statistiques globales de Mylo",
            "parameters": {"type": "object", "properties": {}}
        }
    }
]

# ── Exécution des tools ───────────────────────────────────────────────
def execute_tool(tool_name, tool_args, org):
    from alerts.models import Alert, WhitelistedIP, BlacklistedIP
    from django.db.models import Count

    if tool_name == "get_recent_alerts":
        qs = Alert.objects.filter(organisation=org)
        if tool_args.get("attack_type"):
            qs = qs.filter(attack_type=tool_args["attack_type"])
        if tool_args.get("severity"):
            qs = qs.filter(severity=tool_args["severity"])
        limit = min(tool_args.get("limit", 10), 20)
        alerts = qs.order_by("-timestamp")[:limit]
        return [
            {
                "id": a.id,
                "type": a.attack_type,
                "severity": a.severity,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "confidence": float(a.binary_confidence or 0),
                "status": a.alert_status,
                "timestamp": a.timestamp.isoformat()
            } for a in alerts
        ]

    elif tool_name == "whitelist_ip":
        ip = tool_args["ip_address"]
        desc = tool_args.get("description", "Ajouté par Copilot Mylo")
        obj, created = WhitelistedIP.objects.get_or_create(
            ip_address=ip, organisation=org,
            defaults={"description": desc}
        )
        return {
            "success": True,
            "created": created,
            "message": f"IP {ip} {'ajoutée à' if created else 'déjà dans'} la whitelist"
        }

    elif tool_name == "blacklist_ip":
        ip = tool_args["ip_address"]
        reason = tool_args.get("reason", "Bloqué par Copilot Mylo")
        obj, created = BlacklistedIP.objects.get_or_create(
            ip_address=ip, organisation=org,
            defaults={"reason": reason}
        )
        return {
            "success": True,
            "created": created,
            "message": f"IP {ip} {'bloquée' if created else 'déjà bloquée'}"
        }

    elif tool_name == "get_stats":
        total = Alert.objects.filter(organisation=org).count()
        attacks = Alert.objects.filter(organisation=org, is_attack=True).count()
        by_type = dict(
            Alert.objects.filter(organisation=org)
            .values("attack_type")
            .annotate(n=Count("id"))
            .values_list("attack_type", "n")
        )
        return {
            "total_alerts": total,
            "total_attacks": attacks,
            "normal": total - attacks,
            "by_type": by_type
        }

    return {"error": f"Tool {tool_name} inconnu"}


# ── Agent principal ───────────────────────────────────────────────────
def run_agent(user_message: str, org, conversation_history: list = None):
    if conversation_history is None:
        conversation_history = []

    messages = [
        {
            "role": "system",
            "content": (
                "Tu es Mylo Copilot, l'assistant IA de Mylo IPS — un système de détection "
                "d'intrusion pour environnements bancaires. "
                "Tu peux consulter les alertes, whitelister/blacklister des IPs, et donner des stats. "
                "Réponds toujours en français. Sois concis et professionnel. "
                "Quand tu effectues une action, confirme-la clairement."
            )
        },
        *conversation_history,
        {"role": "user", "content": user_message}
    ]

    # Premier appel Groq
    response = client.chat.completions.create(
        model="llama3-70b-8192",
        messages=messages,
        tools=TOOLS,
        tool_choice="auto",
        max_tokens=1024
    )

    msg = response.choices[0].message

    # Si Groq veut utiliser un tool
    if msg.tool_calls:
        messages.append({"role": "assistant", "content": msg.content, "tool_calls": [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments}
            } for tc in msg.tool_calls
        ]})

        # Exécute chaque tool
        for tc in msg.tool_calls:
            tool_args = json.loads(tc.function.arguments)
            result = execute_tool(tc.function.name, tool_args, org)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result, ensure_ascii=False)
            })

        # Deuxième appel — réponse finale avec résultat du tool
        final = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=messages,
            max_tokens=1024
        )
        return final.choices[0].message.content

    return msg.content