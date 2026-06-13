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

    def get_alerts(self, limit=50):
        token = self.authenticate()
        url = f"{self.api_url}/alerts"
        headers = {'Authorization': f'Bearer {token}'}
        resp = requests.get(
            url,
            headers=headers,
            params={'limit': limit, 'sort': '-timestamp'},
            verify=self.verify,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json().get('data', {})
        return data.get('affected_items', [])

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
