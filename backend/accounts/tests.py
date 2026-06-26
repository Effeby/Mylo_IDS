from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from axes.handlers.proxy import AxesProxyHandler

User = get_user_model()
LOGIN_URL = '/api/auth/login/'


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
