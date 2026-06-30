"""
Mylo IPS — Client API OPNsense
Gère le blocage/déblocage d'IPs via l'API REST OPNsense.

Prérequis OPNsense :
  1. Système → Accès → Serveurs → API → Créer une clé API
  2. Pare-feu → Alias → Créer alias "blocklist" (type Host)
  3. Pare-feu → Règles → LAN → Bloquer si src dans blocklist
"""
import requests
import urllib3
from django.conf import settings

# Désactiver les warnings SSL (OPNsense utilise un cert auto-signé)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OPNsenseClient:

    def __init__(self, organisation=None):
        """
        Charge la config OPNsense depuis IDSSettings de l'organisation.
        """
        if organisation:
            from alerts.models import IDSSettings
            ids_settings = IDSSettings.get(organisation=organisation)
            self.base_url = getattr(ids_settings, 'opnsense_url', '')
            self.api_key  = getattr(ids_settings, 'opnsense_api_key', '')
            self.api_secret = getattr(ids_settings, 'opnsense_api_secret', '')
        else:
            # Fallback sur les settings Django
            self.base_url   = getattr(settings, 'OPNSENSE_URL', 'https://172.16.1.1')
            self.api_key    = getattr(settings, 'OPNSENSE_API_KEY', '')
            self.api_secret = getattr(settings, 'OPNSENSE_API_SECRET', '')

        self.alias_name = "mylo_blocklist"
        self.timeout    = 5

    def _auth(self):
        return (self.api_key, self.api_secret)

    def _apply_firewall(self):
        """Applique les règles de filtrage après reconfiguration de l'alias."""
        return self._post("firewall/filter/apply")

    def _post(self, endpoint: str, data: dict = None):
        url = f"{self.base_url}/api/{endpoint}"
        try:
            r = requests.post(
                url,
                json=data or {},
                auth=self._auth(),
                verify=False,
                timeout=self.timeout
            )
            r.raise_for_status()
            return r.json()
        except requests.exceptions.ConnectionError:
            raise Exception(f"OPNsense inaccessible — vérifie {self.base_url}")
        except requests.exceptions.Timeout:
            raise Exception("OPNsense timeout — réponse trop lente")
        except Exception as e:
            raise Exception(f"OPNsense erreur: {e}")

    def _get(self, endpoint: str):
        url = f"{self.base_url}/api/{endpoint}"
        try:
            r = requests.get(
                url,
                auth=self._auth(),
                verify=False,
                timeout=self.timeout
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            raise Exception(f"OPNsense GET erreur: {e}")

    def tester_connexion(self) -> dict:
        """Teste la connexion à l'API OPNsense."""
        try:
            result = self._get("core/firmware/status")
            return {
                'success': True,
                'message': 'Connexion OPNsense OK',
                'version': result.get('product_version', '?')
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def bloquer_ip(self, ip: str, raison: str = "Mylo IPS") -> dict:
        """
        Ajoute une IP à l'alias blocklist OPNsense.
        L'alias doit exister et une règle firewall doit le bloquer.
        """
        if not self.api_key:
            return {'success': False, 'message': 'API OPNsense non configurée'}

        try:
            # 1 — Récupérer l'alias existant
            alias_result = self._get(
                f"firewall/alias/getAliasUUID/{self.alias_name}"
            )
            alias_uuid = alias_result.get('uuid')

            if not alias_uuid:
                # Créer l'alias s'il n'existe pas
                create_result = self._post("firewall/alias/addItem", {
                    "alias": {
                        "name":    self.alias_name,
                        "type":    "host",
                        "content": ip,
                        "description": f"Mylo IPS blocklist — {raison}"
                    }
                })
                alias_uuid = create_result.get('uuid')
            else:
                # Ajouter l'IP à l'alias existant
                alias_data = self._get(f"firewall/alias/getItem/{alias_uuid}")
                content_actuel = alias_data.get('alias', {}).get('content', {})

                # Construire le nouveau contenu
                ips_actuelles = [
                    v.get('value', '') 
                    for v in content_actuel.values()
                    if isinstance(v, dict)
                ] if isinstance(content_actuel, dict) else []

                if ip in ips_actuelles:
                    return {
                        'success': True,
                        'message': f'{ip} déjà dans la blocklist',
                        'already_blocked': True
                    }

                ips_actuelles.append(ip)
                self._post(f"firewall/alias/setItem/{alias_uuid}", {
                    "alias": {
                        "name":    self.alias_name,
                        "type":    "host",
                        "content": "\n".join(ips_actuelles),
                        "description": f"Mylo IPS blocklist"
                    }
                })

            # 2 — Appliquer les changements
            self._post("firewall/alias/reconfigure")
            self._apply_firewall()

            return {
                'success': True,
                'message': f'IP {ip} bloquée sur OPNsense',
                'ip':      ip
            }

        except Exception as e:
            return {'success': False, 'message': str(e)}

    def debloquer_ip(self, ip: str) -> dict:
        """Retire une IP de la blocklist OPNsense."""
        if not self.api_key:
            return {'success': False, 'message': 'API OPNsense non configurée'}

        try:
            alias_result = self._get(
                f"firewall/alias/getAliasUUID/{self.alias_name}"
            )
            alias_uuid = alias_result.get('uuid')

            if not alias_uuid:
                return {'success': False, 'message': 'Alias blocklist introuvable'}

            alias_data  = self._get(f"firewall/alias/getItem/{alias_uuid}")
            content     = alias_data.get('alias', {}).get('content', {})
            ips         = [
                v.get('value', '')
                for v in content.values()
                if isinstance(v, dict)
            ] if isinstance(content, dict) else []

            if ip not in ips:
                return {'success': True, 'message': f'{ip} pas dans la blocklist'}

            ips.remove(ip)
            self._post(f"firewall/alias/setItem/{alias_uuid}", {
                "alias": {
                    "name":    self.alias_name,
                    "type":    "host",
                    "content": "\n".join(ips),
                }
            })
            self._post("firewall/alias/reconfigure")
            self._apply_firewall()

            return {'success': True, 'message': f'IP {ip} débloquée', 'ip': ip}

        except Exception as e:
            return {'success': False, 'message': str(e)}

    def get_ips_bloquees(self) -> list:
        """Retourne la liste des IPs actuellement bloquées."""
        try:
            alias_result = self._get(
                f"firewall/alias/getAliasUUID/{self.alias_name}"
            )
            alias_uuid = alias_result.get('uuid')
            if not alias_uuid:
                return []

            alias_data = self._get(f"firewall/alias/getItem/{alias_uuid}")
            content    = alias_data.get('alias', {}).get('content', {})
            return [
                v.get('value', '')
                for v in content.values()
                if isinstance(v, dict) and v.get('value')
            ] if isinstance(content, dict) else []

        except Exception:
            return []