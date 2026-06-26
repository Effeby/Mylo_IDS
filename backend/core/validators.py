"""
Validateurs centralisés — IP, CIDR et champs texte/recherche.
À utiliser dans les vues/serializers DRF pour valider les entrées utilisateur
avant de les transmettre à l'ORM, à OPNsense, à Scapy/Nmap, etc.
"""
import ipaddress
import re

from rest_framework.exceptions import ValidationError

# Texte libre (recherche, description, raison...) : lettres/chiffres/ponctuation
# courante uniquement, pas de caractères de contrôle ni de balises.
SAFE_TEXT_RE = re.compile(r'^[\w\s.,;:!?@#&()\-\'"/]*$', re.UNICODE)


def validate_ip(value: str) -> str:
    """Valide une adresse IPv4 ou IPv6. Lève ValidationError si invalide."""
    if not value or not isinstance(value, str):
        raise ValidationError("Adresse IP requise.")
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValidationError(f"Adresse IP invalide : {value!r}")
    return value.strip()


def validate_cidr(value: str) -> str:
    """Valide un réseau CIDR (IPv4 ou IPv6), ex: 192.168.1.0/24."""
    if not value or not isinstance(value, str):
        raise ValidationError("Réseau CIDR requis.")
    try:
        ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValidationError(f"Réseau CIDR invalide : {value!r}")
    return value.strip()


def validate_ip_or_cidr(value: str) -> str:
    """Accepte soit une IP unique, soit une plage CIDR."""
    try:
        return validate_ip(value)
    except ValidationError:
        return validate_cidr(value)


def validate_safe_text(value: str, max_length: int = 255, field_name: str = "Champ") -> str:
    """Valide un champ texte libre : longueur max + caractères autorisés."""
    if value is None:
        return value
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} doit être une chaîne.")
    if len(value) > max_length:
        raise ValidationError(f"{field_name} dépasse {max_length} caractères.")
    if not SAFE_TEXT_RE.match(value):
        raise ValidationError(f"{field_name} contient des caractères non autorisés.")
    return value
