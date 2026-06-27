"""
Tests du mini serveur HTTP de mise à jour live du token (capture.py).
Pas de dépendance externe : unittest + http.server (stdlib uniquement).

Lancer depuis le dossier ml/ :  python -m unittest test_capture.py -v
"""
import json
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

import capture


class TokenUpdateHandlerTests(unittest.TestCase):

    def setUp(self):
        # Port 0 → l'OS choisit un port libre, pour ne pas entrer en
        # conflit avec une instance de capture.py déjà lancée sur :9999.
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), capture.TokenUpdateHandler)
        self.port   = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        self._orig_token  = capture.AUTH_TOKEN
        self._orig_secret = capture.CAPTURE_AGENT_SECRET
        capture.AUTH_TOKEN = None
        capture.CAPTURE_AGENT_SECRET = ''

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        capture.AUTH_TOKEN = self._orig_token
        capture.CAPTURE_AGENT_SECRET = self._orig_secret

    def _post(self, path, payload, headers=None, raw_body=None):
        data = raw_body if raw_body is not None else json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}',
            data=data, method='POST', headers=headers or {'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_update_token_sets_global_auth_token(self):
        status, body = self._post('/update-token/', {'token': 'abc123'})
        self.assertEqual(status, 200)
        self.assertEqual(body, {'status': 'ok'})
        self.assertEqual(capture.AUTH_TOKEN, 'abc123')

    def test_trailing_slash_optional(self):
        status, _ = self._post('/update-token', {'token': 'no-slash'})
        self.assertEqual(status, 200)
        self.assertEqual(capture.AUTH_TOKEN, 'no-slash')

    def test_missing_token_returns_400(self):
        status, _ = self._post('/update-token/', {})
        self.assertEqual(status, 400)
        self.assertIsNone(capture.AUTH_TOKEN)

    def test_unknown_path_returns_404(self):
        status, _ = self._post('/something-else/', {'token': 'x'})
        self.assertEqual(status, 404)
        self.assertIsNone(capture.AUTH_TOKEN)

    def test_invalid_json_returns_400(self):
        status, _ = self._post('/update-token/', None, raw_body=b'not-json')
        self.assertEqual(status, 400)
        self.assertIsNone(capture.AUTH_TOKEN)

    def test_secret_required_when_configured(self):
        capture.CAPTURE_AGENT_SECRET = 'topsecret'
        status, _ = self._post('/update-token/', {'token': 'abc'})
        self.assertEqual(status, 401)
        self.assertIsNone(capture.AUTH_TOKEN)

    def test_secret_accepted_when_correct(self):
        capture.CAPTURE_AGENT_SECRET = 'topsecret'
        status, _ = self._post(
            '/update-token/', {'token': 'abc'},
            headers={'Content-Type': 'application/json', 'X-Capture-Secret': 'topsecret'},
        )
        self.assertEqual(status, 200)
        self.assertEqual(capture.AUTH_TOKEN, 'abc')

    def test_no_secret_configured_is_open_by_default(self):
        # CAPTURE_AGENT_SECRET vide (défaut) : comportement actuel préservé,
        # aucune régression pour les déploiements qui n'en configurent pas.
        self.assertEqual(capture.CAPTURE_AGENT_SECRET, '')
        status, _ = self._post('/update-token/', {'token': 'open-by-default'})
        self.assertEqual(status, 200)
        self.assertEqual(capture.AUTH_TOKEN, 'open-by-default')


if __name__ == '__main__':
    unittest.main()
