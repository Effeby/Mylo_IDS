from unittest.mock import patch, mock_open
import pyotp

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from axes.handlers.proxy import AxesProxyHandler
from accounts.totp import generate_totp_secret
from accounts.views import _push_token_to_capture_agent

User = get_user_model()
LOGIN_URL = '/api/auth/login/'
TOTP_VERIFY_URL = '/api/auth/totp/verify/'


class LoginViewAxesLockoutTests(TestCase):
    """LoginView + django-axes : verrou IP après 5 échecs (AXES_FAILURE_LIMIT=5,
    AXES_COOLOFF_TIME=0.5h, AXES_LOCKOUT_PARAMETERS=['ip_address'])."""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='alice', password='CorrectPass123!', email='alice@example.com',
        )
        # Évite toute pollution entre tests (axes stocke en base par IP/username).
        AxesProxyHandler.reset_attempts()

    def tearDown(self):
        AxesProxyHandler.reset_attempts()

    def _login(self, username, password):
        return self.client.post(LOGIN_URL, {'username': username, 'password': password}, format='json')

    def test_wrong_password_and_unknown_username_return_identical_generic_message(self):
        resp_wrong_pw = self._login('alice', 'WrongPass!')
        AxesProxyHandler.reset_attempts()  # isole le test du compteur axes
        resp_unknown_user = self._login('ghost', 'whatever')

        self.assertEqual(resp_wrong_pw.status_code, 401)
        self.assertEqual(resp_unknown_user.status_code, 401)
        self.assertEqual(resp_wrong_pw.data['error'], resp_unknown_user.data['error'])
        self.assertEqual(resp_wrong_pw.data['error'], 'Identifiants incorrects')

    def test_correct_login_still_works(self):
        resp = self._login('alice', 'CorrectPass123!')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('access', resp.data)

    def test_locks_ip_after_5_failed_attempts(self):
        for _ in range(5):
            resp = self._login('alice', 'WrongPass!')
            self.assertEqual(resp.status_code, 401)

        # 6e tentative (même avec le bon mot de passe) : IP bloquée par axes
        resp = self._login('alice', 'CorrectPass123!')
        self.assertEqual(resp.status_code, 429)
        self.assertEqual(resp.data['error'], 'Identifiants incorrects')

    def test_lockout_does_not_reveal_username_validity(self):
        for _ in range(5):
            self._login('alice', 'WrongPass!')

        # Même un username inexistant déclenche le même blocage générique
        resp = self._login('does-not-exist', 'whatever')
        self.assertEqual(resp.status_code, 429)
        self.assertEqual(resp.data['error'], 'Identifiants incorrects')

    def test_successful_login_resets_axes_failure_count(self):
        for _ in range(4):
            self._login('alice', 'WrongPass!')

        resp = self._login('alice', 'CorrectPass123!')
        self.assertEqual(resp.status_code, 200)

        # Le compteur axes a été réinitialisé (AXES_RESET_ON_SUCCESS=True) :
        # 4 nouveaux échecs ne suffisent pas à re-bloquer immédiatement.
        for _ in range(4):
            resp = self._login('alice', 'WrongPass!')
            self.assertEqual(resp.status_code, 401)

    def test_manual_account_lock_still_applies_after_5_failures(self):
        """La logique métier existante (User.is_locked permanent) reste intacte
        en parallèle du verrou IP axes (30 min)."""
        for _ in range(5):
            self._login('alice', 'WrongPass!')
            AxesProxyHandler.reset_attempts()  # isole l'axe IP pour ne tester que le verrou compte

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_locked)
        self.assertEqual(self.user.failed_login_attempts, 5)


class PushTokenToCaptureAgentTests(TestCase):
    """_push_token_to_capture_agent : push non bloquant du JWT vers ml/capture.py."""

    @override_settings(CAPTURE_AGENT_URL='')
    def test_noop_when_agent_url_not_configured(self):
        with patch('accounts.views.requests.post') as mock_post:
            _push_token_to_capture_agent('sometoken')
            mock_post.assert_not_called()

    @override_settings(CAPTURE_AGENT_URL='http://10.0.0.2:9999', CAPTURE_AGENT_SECRET='')
    def test_posts_token_to_configured_agent(self):
        with patch('accounts.views.requests.post') as mock_post:
            _push_token_to_capture_agent('sometoken')
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            self.assertEqual(args[0], 'http://10.0.0.2:9999/update-token/')
            self.assertEqual(kwargs['json'], {'token': 'sometoken'})
            self.assertEqual(kwargs['headers'], {})

    @override_settings(CAPTURE_AGENT_URL='http://10.0.0.2:9999/', CAPTURE_AGENT_SECRET='shh')
    def test_includes_secret_header_when_configured(self):
        with patch('accounts.views.requests.post') as mock_post:
            _push_token_to_capture_agent('sometoken')
            args, kwargs = mock_post.call_args
            # rstrip('/') sur l'URL : pas de double slash devant /update-token/
            self.assertEqual(args[0], 'http://10.0.0.2:9999/update-token/')
            self.assertEqual(kwargs['headers'].get('X-Capture-Secret'), 'shh')

    @override_settings(CAPTURE_AGENT_URL='http://unreachable:9999')
    def test_silently_swallows_connection_errors(self):
        with patch('accounts.views.requests.post', side_effect=ConnectionError('boom')):
            try:
                _push_token_to_capture_agent('sometoken')
            except Exception:
                self.fail('_push_token_to_capture_agent ne doit jamais lever, même si l\'agent est down')


class TotpVerifyPushesTokenTests(TestCase):
    """Le login TOTP réussi déclenche le push (en thread, non bloquant) vers l'agent de capture."""

    def setUp(self):
        self.client = APIClient()
        self.secret = generate_totp_secret()
        self.user = User.objects.create_user(
            username='bob', password='Pass1234!', email='bob@example.com',
            totp_enabled=True, totp_secret=self.secret, habilitation_level=3,
        )
        self.client.force_authenticate(self.user)

    def _valid_code(self):
        return pyotp.TOTP(self.secret).now()

    @override_settings(CAPTURE_AGENT_URL='http://10.0.0.2:9999')
    def test_totp_verify_triggers_push_in_background_thread(self):
        with patch('accounts.views.open', mock_open()), \
             patch('accounts.views.threading.Thread') as mock_thread_cls:
            resp = self.client.post(TOTP_VERIFY_URL, {'code': self._valid_code()}, format='json')

        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['totp_verified'])
        mock_thread_cls.assert_called_once()
        _, kwargs = mock_thread_cls.call_args
        self.assertIs(kwargs['target'], _push_token_to_capture_agent)
        self.assertEqual(kwargs['args'], (resp.data['access'],))
        self.assertTrue(kwargs['daemon'])

    @override_settings(CAPTURE_AGENT_URL='')
    def test_totp_verify_does_not_block_or_fail_when_agent_not_configured(self):
        # Pas de mock sur requests.post : CAPTURE_AGENT_URL vide → no-op,
        # le endpoint doit répondre normalement (comportement existant préservé).
        with patch('accounts.views.open', mock_open()):
            resp = self.client.post(TOTP_VERIFY_URL, {'code': self._valid_code()}, format='json')
        self.assertEqual(resp.status_code, 200)

    def test_low_habilitation_user_does_not_trigger_push(self):
        self.user.habilitation_level = 2
        self.user.save(update_fields=['habilitation_level'])
        with patch('accounts.views.threading.Thread') as mock_thread_cls:
            resp = self.client.post(TOTP_VERIFY_URL, {'code': self._valid_code()}, format='json')
        self.assertEqual(resp.status_code, 200)
        mock_thread_cls.assert_not_called()

    def test_wrong_code_does_not_trigger_push(self):
        with patch('accounts.views.threading.Thread') as mock_thread_cls:
            resp = self.client.post(TOTP_VERIFY_URL, {'code': '000000'}, format='json')
        self.assertEqual(resp.status_code, 401)
        mock_thread_cls.assert_not_called()
