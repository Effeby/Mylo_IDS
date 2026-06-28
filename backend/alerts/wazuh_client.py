import requests
import urllib3
from django.conf import settings
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhClient:
    def __init__(self):
        self.base_url = getattr(settings, 'WAZUH_API_URL', 'https://172.16.30.20')
        self.port = getattr(settings, 'WAZUH_API_PORT', '55000')
        self.user = getattr(settings, 'WAZUH_API_USER', 'wazuh-wui')
        self.password = getattr(settings, 'WAZUH_API_PASSWORD', '')
        self.verify = getattr(settings, 'WAZUH_VERIFY_SSL', False)
        self.timeout = 5

    @property
    def api_url(self):
        return f"{self.base_url}:{self.port}"

    def authenticate(self):
        if not self.user or not self.password:
            raise Exception('Wazuh credentials manquantes')

        url = f"{self.api_url}/security/user/authenticate"
        resp = requests.post(
            url,
            auth=(self.user, self.password),
            verify=self.verify,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json().get('data', {})
        token = data.get('token')
        if not token:
            raise Exception('Token Wazuh introuvable')
        return token

    def get_alerts(self, limit=50, since_minutes=None):
        """
        Récupère les alertes Wazuh depuis OpenSearch.

        since_minutes, si fourni, restreint la recherche aux documents dont
        @timestamp est dans la fenêtre [now - since_minutes, now] — évite de
        repolling indéfiniment les mêmes vieilles alertes à chaque cycle.

        Chaque dict retourné est le `_source` du document, enrichi d'une clé
        `_id` (l'identifiant du document OpenSearch) utilisée pour dédupliquer
        les alertes déjà persistées en BD.
        """
        url = f"{self.base_url}:9200/wazuh-alerts-*/_search"
        query = {"match_all": {}}
        if since_minutes is not None:
            query = {
                "range": {
                    "@timestamp": {"gte": f"now-{since_minutes}m", "lte": "now"}
                }
            }
        payload = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": query,
        }
        resp = requests.post(
            url,
            json=payload,
            auth=(
                getattr(settings, 'WAZUH_INDEXER_USER', 'admin'),
                getattr(settings, 'WAZUH_INDEXER_PASSWORD', '')
            ),
            verify=self.verify,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        hits = resp.json().get('hits', {}).get('hits', [])
        results = []
        for h in hits:
            source = dict(h['_source'])
            source['_id'] = h.get('_id')
            results.append(source)
        return results

    def status(self):
        try:
            alerts = self.get_alerts(limit=1)
            return {
                'success': True,
                'connected': True,
                'message': 'Connexion Wazuh OK',
                'wazuh_url': self.api_url,
                'alert_count': len(alerts),
                'last_check_at': datetime.utcnow().isoformat() + 'Z',
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'connected': False,
                'message': f'Impossible de joindre Wazuh à {self.api_url}',
                'wazuh_url': self.api_url,
                'alert_count': 0,
                'last_check_at': datetime.utcnow().isoformat() + 'Z',
            }
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'connected': False,
                'message': 'Connexion Wazuh trop lente',
                'wazuh_url': self.api_url,
                'alert_count': 0,
                'last_check_at': datetime.utcnow().isoformat() + 'Z',
            }
        except Exception as e:
            return {
                'success': False,
                'connected': False,
                'message': str(e),
                'wazuh_url': self.api_url,
                'alert_count': 0,
                'last_check_at': datetime.utcnow().isoformat() + 'Z',
            }
