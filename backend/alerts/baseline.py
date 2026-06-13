"""
Mylo IPS — Gestionnaire de phases baseline
Contrôle quand River peut apprendre et alerter.

Phases :
  LEARNING    → River observe silencieusement, pas d'alertes comportementales
  VALIDATION  → Baseline prête, en attente de validation admin
  PRODUCTION  → Système pleinement opérationnel
"""
from django.utils import timezone
from datetime import timedelta

PHASE_LEARNING    = "learning"
PHASE_VALIDATION  = "validation"
PHASE_PRODUCTION  = "production"

# Seuils pour passer en production
MIN_JOURS    = 3      # Au moins 3 jours d'observation (7 idéal, 3 pour le lab)
MIN_FLOWS    = 500    # Au moins 500 flux analysés
MIN_IPS      = 3      # Au moins 3 IPs différentes vues


class BaselineManager:

    def __init__(self, organisation):
        self.org = organisation

    def get_stats(self):
        """Calcule les stats actuelles de la baseline."""
        from alerts.models import IPBaseline, Alert

        jours_depuis_creation = (timezone.now() - self.org.created_at).days

        # Compter les flux totaux (somme des flows de toutes les IPBaseline)
        baselines = IPBaseline.objects.filter(organisation=self.org)
        total_flows = sum(b.total_flows for b in baselines)
        total_ips   = baselines.count()
        ips_etablies = baselines.filter(baseline_established=True).count()

        return {
            'jours':        jours_depuis_creation,
            'total_flows':  total_flows,
            'total_ips':    total_ips,
            'ips_etablies': ips_etablies,
            'min_jours':    MIN_JOURS,
            'min_flows':    MIN_FLOWS,
            'min_ips':      MIN_IPS,
        }

    def get_phase(self):
        """
        Retourne (phase, message, progression%).
        """
        from accounts.models import Organisation

        stats = self.get_stats()

        # Vérifier si l'admin a validé manuellement
        settings = self._get_settings()
        if getattr(settings, 'baseline_validated', False):
            return PHASE_PRODUCTION, "Baseline validée — Système opérationnel", 100

        # Critères non atteints → apprentissage
        criteres = [
            stats['jours']       >= MIN_JOURS,
            stats['total_flows'] >= MIN_FLOWS,
            stats['total_ips']   >= MIN_IPS,
        ]

        if not all(criteres):
            # Calculer progression
            prog_jours  = min(stats['jours']       / MIN_JOURS   * 33, 33)
            prog_flows  = min(stats['total_flows']  / MIN_FLOWS   * 33, 33)
            prog_ips    = min(stats['total_ips']    / MIN_IPS     * 34, 34)
            progression = int(prog_jours + prog_flows + prog_ips)

            message = (
                f"Apprentissage en cours — "
                f"{stats['jours']}/{MIN_JOURS} jours | "
                f"{stats['total_flows']}/{MIN_FLOWS} flux | "
                f"{stats['total_ips']}/{MIN_IPS} IPs"
            )
            return PHASE_LEARNING, message, progression

        # Critères atteints → validation
        message = (
            f"Baseline prête — En attente de validation admin. "
            f"{stats['total_flows']} flux sur {stats['total_ips']} IPs"
        )
        return PHASE_VALIDATION, message, 99

    def river_peut_apprendre(self, confidence: float, is_attack: bool) -> bool:
        """
        River peut-il apprendre ce flux ?
        
        Règles :
        - LEARNING    : apprend SEULEMENT le trafic Normal (pour construire la baseline)
        - VALIDATION  : n'apprend rien (en attente admin)
        - PRODUCTION  : apprend Normal + Attaques confirmées (confidence >= seuil)
        """
        phase, _, _ = self.get_phase()

        if phase == PHASE_LEARNING:
            # En apprentissage, River apprend SEULEMENT le trafic normal
            # pour construire sa référence du comportement habituel
            return not is_attack

        if phase == PHASE_VALIDATION:
            # On attend la validation admin — River n'apprend rien
            return False

        if phase == PHASE_PRODUCTION:
            # En production, River apprend si confiance suffisante
            # ET seulement si ce n'est pas une attaque en cours
            # (éviter d'apprendre les attaques comme "normales")
            settings = self._get_settings()
            seuil    = getattr(settings, 'river_learn_threshold', 0.70)
            return confidence >= seuil

        return False

    def river_peut_alerter_comportement(self) -> bool:
        """
        Les anomalies comportementales (Z-score IPBaseline) 
        ne sont affichées qu'en PRODUCTION.
        """
        phase, _, _ = self.get_phase()
        return phase == PHASE_PRODUCTION

    def xgboost_peut_alerter(self, confidence: float) -> bool:
        """
        XGBoost alerte TOUJOURS — même en apprentissage.
        C'est le moteur principal, indépendant de la baseline.
        """
        return True

    def _get_settings(self):
        from alerts.models import IDSSettings
        return IDSSettings.get(organisation=self.org)