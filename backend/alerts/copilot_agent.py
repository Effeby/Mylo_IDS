# backend/alerts/copilot_agent.py
import os
import json
from groq import Groq, BadRequestError

# Le client Groq est instancié à la demande (pas au chargement du module) :
# si GROQ_API_KEY n'est pas configurée, on veut une erreur claire au moment
# de l'appel — pas un crash de l'import de ce module (qui casserait par ex.
# les tests ou tout autre code qui importe copilot_agent sans avoir besoin
# d'appeler Groq).
_client = None


def _get_client() -> Groq:
    global _client
    if _client is None:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY non configurée — Copilot indisponible.")
        _client = Groq(api_key=api_key)
    return _client

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
                    "limit": {"type": ["integer", "string"], "description": "Nombre d'alertes (max 20). Doit être un entier, ex: 20"},
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
    from core.validators import validate_ip, validate_safe_text
    from rest_framework.exceptions import ValidationError

    def _validation_error(e: ValidationError) -> str:
        return str(e.detail[0]) if isinstance(e.detail, list) else str(e)

    if tool_name == "get_recent_alerts":
        qs = Alert.objects.filter(organisation=org)
        if tool_args.get("attack_type"):
            qs = qs.filter(attack_type=tool_args["attack_type"])
        if tool_args.get("severity"):
            qs = qs.filter(severity=tool_args["severity"])
        try:
            limit = int(tool_args.get("limit", 10))
        except (TypeError, ValueError):
            limit = 10
        limit = min(limit, 20)
        alerts = qs.order_by("-detected_at")[:limit]
        return [
            {
                "id": a.id,
                "type": a.attack_type,
                "severity": a.severity,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "confidence": float(a.binary_confidence or 0),
                "status": a.status,
                "timestamp": a.detected_at.isoformat()
            } for a in alerts
        ]

    elif tool_name == "whitelist_ip":
        if org is None:
            return {"success": False, "error": "Aucune organisation associée à cet utilisateur — whitelist impossible."}
        try:
            ip   = validate_ip(tool_args.get("ip_address"))
            desc = validate_safe_text(
                tool_args.get("description") or "Ajouté par Copilot Mylo",
                max_length=200, field_name="description",
            )
        except ValidationError as e:
            return {"success": False, "error": _validation_error(e)}

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
        if org is None:
            return {"success": False, "error": "Aucune organisation associée à cet utilisateur — blocage impossible."}
        try:
            ip     = validate_ip(tool_args.get("ip_address"))
            reason = validate_safe_text(
                tool_args.get("reason") or "Bloqué par Copilot Mylo",
                max_length=200, field_name="reason",
            )
        except ValidationError as e:
            return {"success": False, "error": _validation_error(e)}

        obj, created = BlacklistedIP.objects.get_or_create(
            ip_address=ip, organisation=org,
            defaults={"reason": reason, "blocked_by": "copilot"}
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


# ── Contexte réseau (système prompt dynamique) ─────────────────────────
def _build_network_context(org) -> dict:
    """Récupère l'état réseau directement en BDD (pas d'appel HTTP — on est
    déjà dans le process Django)."""
    from alerts.models import Alert, BlacklistedIP

    alerts = list(Alert.objects.filter(organisation=org).order_by("-detected_at")[:20])
    attack_alerts  = [a for a in alerts if a.is_attack]
    recent_attacks = attack_alerts[:5]
    top_ips        = list(dict.fromkeys(a.src_ip for a in attack_alerts if a.src_ip))[:5]
    attack_types   = list(dict.fromkeys(a.attack_type for a in attack_alerts))
    new_alerts     = sum(1 for a in alerts if a.status == "new" and a.is_attack)

    total         = Alert.objects.filter(organisation=org).count()
    attacks_total = Alert.objects.filter(organisation=org, is_attack=True).count()

    blacklist_active = BlacklistedIP.objects.filter(organisation=org, is_active=True).count()

    river_total, river_accuracy = 0, 0.0
    try:
        from actions.views import _get_model, _river_state
        _get_model()
        river_total    = _river_state["total"]
        river_accuracy = round(_river_state["metric"].get(), 4)
    except Exception:
        pass

    return {
        "alerts_count":     len(alerts),
        "total":            total,
        "attacks":          attacks_total,
        "attack_rate":      (attacks_total / total) if total else 0.0,
        "new_alerts":       new_alerts,
        "blacklist_active": blacklist_active,
        "attack_types":     attack_types,
        "top_ips":          top_ips,
        "recent_attacks":   recent_attacks,
        "river_total":      river_total,
        "river_accuracy":   river_accuracy,
    }


def _build_system_prompt(org) -> str:
    ctx = _build_network_context(org)

    if ctx["alerts_count"] > 0:
        attacks_lines = "\n".join(
            f"• [{a.detected_at.strftime('%H:%M:%S')}] {a.attack_type} | {a.severity} | "
            f"{a.src_ip or '?'} → {a.dst_ip or '?'} | "
            f"Confiance: {round((a.binary_confidence or 0) * 100)}% | Statut: {a.status}"
            for a in ctx["recent_attacks"]
        ) or "• Aucune attaque récente détectée"

        river_line = (
            f"{round(ctx['river_accuracy'] * 100, 1)}%"
            if ctx["river_total"] > 0 else "En cours d'initialisation"
        )

        network_summary = f"""
ÉTAT ACTUEL DU RÉSEAU (données en temps réel) :
- Total flux analysés : {ctx['total']}
- Attaques détectées  : {ctx['attacks']}
- Taux d'attaque      : {round(ctx['attack_rate'] * 100, 1)}%
- Alertes non traitées: {ctx['new_alerts']}
- IPs bloquées actives: {ctx['blacklist_active']}
- Types observés      : {', '.join(ctx['attack_types']) or 'Aucun'}
- IPs suspectes       : {', '.join(ctx['top_ips']) or 'Aucune'}

DÉTAIL DES DERNIÈRES ALERTES :
{attacks_lines}

APPRENTISSAGE EN LIGNE :
- Flux appris : {ctx['river_total']}
- Précision   : {river_line}
"""
    else:
        network_summary = "\nÉTAT ACTUEL : Aucune donnée disponible — système en attente de trafic.\n"

    return f"""Tu es Mylo Copilot, l'assistant IA de sécurité de Mylo IPS — un système de détection et de prévention d'intrusions pour environnements exigeants (ex. bancaires).

TON RÔLE :
Tu aides l'analyste à comprendre ce qui se passe sur le réseau surveillé, et tu peux agir directement via des outils :
- get_recent_alerts  : consulter les alertes récentes
- whitelist_ip       : whitelister une IP de confiance
- blacklist_ip       : bloquer une IP suspecte
- get_stats          : statistiques globales

RÈGLES IMPORTANTES :
- Quand l'utilisateur te demande d'effectuer une action (whitelister, bloquer une IP...), tu DOIS appeler l'outil correspondant. Ne dis JAMAIS qu'une action a été effectuée sans avoir réellement appelé le tool.
- Si le résultat d'un tool indique un échec ("success": false), rapporte l'échec clairement à l'utilisateur — n'affirme jamais un succès non confirmé par le tool.
- Réponds toujours en français, de façon concise et professionnelle.
{network_summary}"""


# ── Agent principal ───────────────────────────────────────────────────
def run_agent(user_message: str, org, conversation_history: list = None):
    if conversation_history is None:
        conversation_history = []

    messages = [
        {"role": "system", "content": _build_system_prompt(org)},
        *conversation_history,
        {"role": "user", "content": user_message}
    ]

    client = _get_client()

    # Premier appel Groq
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            max_tokens=1024
        )
    except BadRequestError as e:
        if "tool_use_failed" in str(e):
            # Retry une fois sans tools : le modèle répond en texte simple
            # plutôt que de planter toute la conversation.
            messages.append({
                "role": "system",
                "content": "Réponds en texte simple sans utiliser d'outil, le précédent appel a échoué."
            })
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                max_tokens=1024
            )
        else:
            raise

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

        # Exécute chaque tool — une erreur sur un tool ne doit jamais être
        # avalée silencieusement ni faire planter toute la conversation :
        # elle est renvoyée au modèle comme résultat du tool, pour qu'il
        # rapporte l'échec à l'utilisateur plutôt que d'inventer un succès.
        for tc in msg.tool_calls:
            try:
                tool_args = json.loads(tc.function.arguments)
                result = execute_tool(tc.function.name, tool_args, org)
            except Exception as e:
                result = {"success": False, "error": f"Erreur d'exécution du tool : {e}"}
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result, ensure_ascii=False)
            })

        # Deuxième appel — réponse finale avec résultat du tool
        final = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            max_tokens=1024
        )
        return final.choices[0].message.content

    return msg.content