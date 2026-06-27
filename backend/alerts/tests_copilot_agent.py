"""
Tests de l'agent Copilot (alerts/copilot_agent.py) — execute_tool().
Vérifie que whitelist_ip / blacklist_ip écrivent vraiment en base, avec
l'organisation passée en argument, et qu'ils échouent proprement (sans
jamais lever) sur les entrées invalides.
"""
from django.test import TestCase

from accounts.models import Organisation
from alerts.models import Alert, WhitelistedIP, BlacklistedIP
from alerts.copilot_agent import execute_tool, _build_system_prompt


class WhitelistIpToolTests(TestCase):

    def setUp(self):
        self.org = Organisation.objects.create(
            name='Acme', slug='acme', email='contact@acme.test',
        )

    def test_whitelist_ip_persists_to_database(self):
        result = execute_tool(
            'whitelist_ip',
            {'ip_address': '203.0.113.10', 'description': 'IP partenaire'},
            self.org,
        )

        self.assertTrue(result['success'])
        self.assertTrue(result['created'])

        ip = WhitelistedIP.objects.get(organisation=self.org, ip_address='203.0.113.10')
        self.assertEqual(ip.description, 'IP partenaire')

    def test_whitelist_ip_uses_default_description_when_missing(self):
        execute_tool('whitelist_ip', {'ip_address': '203.0.113.11'}, self.org)
        ip = WhitelistedIP.objects.get(organisation=self.org, ip_address='203.0.113.11')
        self.assertEqual(ip.description, 'Ajouté par Copilot Mylo')

    def test_whitelist_ip_is_idempotent(self):
        execute_tool('whitelist_ip', {'ip_address': '203.0.113.12'}, self.org)
        result = execute_tool('whitelist_ip', {'ip_address': '203.0.113.12'}, self.org)

        self.assertTrue(result['success'])
        self.assertFalse(result['created'])
        self.assertEqual(
            WhitelistedIP.objects.filter(organisation=self.org, ip_address='203.0.113.12').count(),
            1,
        )

    def test_whitelist_ip_rejects_invalid_ip_without_writing(self):
        result = execute_tool('whitelist_ip', {'ip_address': 'not-an-ip'}, self.org)

        self.assertFalse(result['success'])
        self.assertIn('error', result)
        self.assertFalse(WhitelistedIP.objects.filter(organisation=self.org).exists())

    def test_whitelist_ip_without_organisation_returns_clear_error(self):
        result = execute_tool('whitelist_ip', {'ip_address': '203.0.113.13'}, None)

        self.assertFalse(result['success'])
        self.assertIn('organisation', result['error'].lower())
        self.assertFalse(WhitelistedIP.objects.filter(ip_address='203.0.113.13').exists())

    def test_whitelist_ip_scoped_to_organisation(self):
        other_org = Organisation.objects.create(
            name='Other', slug='other', email='contact@other.test',
        )
        execute_tool('whitelist_ip', {'ip_address': '203.0.113.14'}, self.org)

        self.assertTrue(
            WhitelistedIP.objects.filter(organisation=self.org, ip_address='203.0.113.14').exists()
        )
        self.assertFalse(
            WhitelistedIP.objects.filter(organisation=other_org, ip_address='203.0.113.14').exists()
        )


class BlacklistIpToolTests(TestCase):

    def setUp(self):
        self.org = Organisation.objects.create(
            name='Acme', slug='acme', email='contact@acme.test',
        )

    def test_blacklist_ip_persists_to_database(self):
        result = execute_tool(
            'blacklist_ip',
            {'ip_address': '198.51.100.20', 'reason': 'Scan de ports répété'},
            self.org,
        )

        self.assertTrue(result['success'])
        self.assertTrue(result['created'])

        ip = BlacklistedIP.objects.get(organisation=self.org, ip_address='198.51.100.20')
        self.assertEqual(ip.reason, 'Scan de ports répété')
        self.assertEqual(ip.blocked_by, 'copilot')

    def test_blacklist_ip_is_idempotent(self):
        execute_tool('blacklist_ip', {'ip_address': '198.51.100.21'}, self.org)
        result = execute_tool('blacklist_ip', {'ip_address': '198.51.100.21'}, self.org)

        self.assertTrue(result['success'])
        self.assertFalse(result['created'])
        self.assertEqual(
            BlacklistedIP.objects.filter(organisation=self.org, ip_address='198.51.100.21').count(),
            1,
        )

    def test_blacklist_ip_rejects_invalid_ip_without_writing(self):
        result = execute_tool('blacklist_ip', {'ip_address': '999.999.999.999'}, self.org)

        self.assertFalse(result['success'])
        self.assertIn('error', result)
        self.assertFalse(BlacklistedIP.objects.filter(organisation=self.org).exists())

    def test_blacklist_ip_without_organisation_returns_clear_error(self):
        result = execute_tool('blacklist_ip', {'ip_address': '198.51.100.22'}, None)

        self.assertFalse(result['success'])
        self.assertIn('organisation', result['error'].lower())
        self.assertFalse(BlacklistedIP.objects.filter(ip_address='198.51.100.22').exists())


class UnknownToolTests(TestCase):

    def test_unknown_tool_returns_error_dict(self):
        org = Organisation.objects.create(name='Acme', slug='acme2', email='contact@acme2.test')
        result = execute_tool('delete_everything', {}, org)
        self.assertIn('error', result)


class BuildSystemPromptTests(TestCase):
    """Le system prompt est désormais construit côté backend (contexte réseau
    en direct depuis la BDD), au lieu d'être fabriqué côté frontend."""

    def setUp(self):
        self.org = Organisation.objects.create(
            name='Acme', slug='acme3', email='contact@acme3.test',
        )

    def test_prompt_mentions_no_data_when_no_alerts(self):
        prompt = _build_system_prompt(self.org)
        self.assertIn('Aucune donnée disponible', prompt)

    def test_prompt_includes_live_alert_data(self):
        Alert.objects.create(
            organisation=self.org, attack_type='DoS', severity='HIGH',
            binary_confidence=0.9, attack_confidence=0.9, is_attack=True,
            src_ip='1.2.3.4', dst_ip='5.6.7.8', status='new',
        )
        prompt = _build_system_prompt(self.org)
        self.assertIn('1.2.3.4', prompt)
        self.assertIn('DoS', prompt)
        self.assertIn('Total flux analysés : 1', prompt)

    def test_prompt_instructs_against_fake_success(self):
        prompt = _build_system_prompt(self.org)
        self.assertIn('Ne dis JAMAIS', prompt)
