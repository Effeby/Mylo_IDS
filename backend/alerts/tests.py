from django.test import TestCase

from .wazuh_rules import (
    get_alert_class, is_rule_id_mapped, CLASS_DEFAULTS,
    BRUTE_FORCE, PORT_SCAN, MALWARE, PRIVILEGE_ESCALATION,
    WEB_ATTACK, RECONNAISSANCE, NORMAL, SUSPICIOUS,
)
from .tasks import _has_sufficient_features


class GetAlertClassTests(TestCase):
    """Vérifie le mapping rule_id Wazuh → classe Mylo (alerts/wazuh_rules.py)."""

    def test_bruteforce_rule_ids(self):
        for rule_id in (5551, 5712, 5763, 5710, 5711, 5716, 5720, 5503, 5504):
            self.assertEqual(get_alert_class(rule_id), BRUTE_FORCE)
            self.assertTrue(is_rule_id_mapped(rule_id))

    def test_portscan_rule_ids(self):
        for rule_id in (40101, 40102, 40111, 1002):
            self.assertEqual(get_alert_class(rule_id), PORT_SCAN)
            self.assertTrue(is_rule_id_mapped(rule_id))

    def test_malware_rule_ids(self):
        for rule_id in (510, 511, 512, 31103, 31104):
            self.assertEqual(get_alert_class(rule_id), MALWARE)
            self.assertTrue(is_rule_id_mapped(rule_id))

    def test_privilege_escalation_rule_ids(self):
        for rule_id in (5401, 5402, 5403, 5404, 2502, 2503):
            self.assertEqual(get_alert_class(rule_id), PRIVILEGE_ESCALATION)
            self.assertTrue(is_rule_id_mapped(rule_id))

    def test_webattack_rule_ids(self):
        for rule_id in (31101, 31102, 33101, 33102, 31151):
            self.assertEqual(get_alert_class(rule_id), WEB_ATTACK)
            self.assertTrue(is_rule_id_mapped(rule_id))

    def test_reconnaissance_rule_ids(self):
        for rule_id in (40100, 40110, 19101):
            self.assertEqual(get_alert_class(rule_id), RECONNAISSANCE)
            self.assertTrue(is_rule_id_mapped(rule_id))

    def test_unmapped_rule_id_defaults_to_normal(self):
        unmapped = 999999
        self.assertEqual(get_alert_class(unmapped), NORMAL)
        self.assertFalse(is_rule_id_mapped(unmapped))

    def test_accepts_string_rule_id(self):
        self.assertEqual(get_alert_class("5551"), BRUTE_FORCE)
        self.assertTrue(is_rule_id_mapped("5551"))

    def test_invalid_rule_id_defaults_to_normal_and_unmapped(self):
        self.assertEqual(get_alert_class(None), NORMAL)
        self.assertFalse(is_rule_id_mapped(None))
        self.assertFalse(is_rule_id_mapped("not-an-int"))

    def test_every_mapped_class_has_defaults(self):
        for mylo_class in CLASS_DEFAULTS:
            self.assertIn('confidence', CLASS_DEFAULTS[mylo_class])
            self.assertIn('severity', CLASS_DEFAULTS[mylo_class])

    def test_suspicious_is_a_valid_fallback_class(self):
        # 'Suspicious' n'est jamais retourné par get_alert_class() (réservé
        # au fallback ML de tasks.py) mais doit avoir des defaults définis.
        self.assertIn(SUSPICIOUS, CLASS_DEFAULTS)


class HasSufficientFeaturesTests(TestCase):
    """Vérifie l'heuristique de suffisance des features utilisée par tasks.py
    pour décider entre prédiction ML et fallback 'Suspicious'."""

    def test_no_signal_is_insufficient(self):
        traffic = {'src_bytes': 0, 'dst_bytes': 0, 'src_port': 0, 'dst_port': 0}
        self.assertFalse(_has_sufficient_features(traffic))

    def test_missing_keys_is_insufficient(self):
        self.assertFalse(_has_sufficient_features({}))

    def test_src_bytes_signal_is_sufficient(self):
        traffic = {'src_bytes': 491, 'dst_bytes': 0, 'src_port': 0, 'dst_port': 0}
        self.assertTrue(_has_sufficient_features(traffic))

    def test_port_signal_is_sufficient(self):
        traffic = {'src_bytes': 0, 'dst_bytes': 0, 'src_port': 0, 'dst_port': 443}
        self.assertTrue(_has_sufficient_features(traffic))
