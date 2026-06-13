from django.shortcuts import render
import csv
import json
from datetime import datetime
from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Count
from alerts.models import Alert
from accounts.permissions import CanGenerateReports, IsOrgAdmin


class ExportCSVView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = (
            f'attachment; filename="mylo_alerts_{datetime.now().strftime("%Y%m%d_%H%M")}.csv"'
        )
        response.write('\ufeff')
        writer = csv.writer(response)
        writer.writerow([
            'ID', 'Timestamp', 'Type Attaque', 'Sévérité',
            'IP Source', 'IP Destination', 'Protocole',
            'Confiance Binaire', 'Confiance Attaque', 'Statut'
        ])
        for a in Alert.objects.filter(is_attack=True).order_by('-detected_at')[:1000]:
            writer.writerow([
                a.id,
                a.detected_at.strftime('%Y-%m-%d %H:%M:%S'),
                a.attack_type, a.severity, a.src_ip, a.dst_ip, a.protocol,
                f"{a.binary_confidence:.4f}", f"{a.attack_confidence:.4f}", a.status,
            ])
        return response


class ExportJSONView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        alerts = list(
            Alert.objects.filter(is_attack=True)
            .order_by('-detected_at')[:1000]
            .values('id', 'attack_type', 'severity', 'src_ip', 'dst_ip',
                    'protocol', 'binary_confidence', 'attack_confidence',
                    'status', 'detected_at')
        )
        for a in alerts:
            a['detected_at'] = a['detected_at'].isoformat()
        response = HttpResponse(json.dumps(alerts, indent=2), content_type='application/json')
        response['Content-Disposition'] = (
            f'attachment; filename="mylo_alerts_{datetime.now().strftime("%Y%m%d_%H%M")}.json"'
        )
        return response


class GenerateReportView(APIView):
    """Génère un rapport JSON — utilisé par le Copilot et le frontend."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from_date = request.query_params.get('from')
        to_date   = request.query_params.get('to')

        qs_all    = Alert.objects.all()
        qs        = Alert.objects.filter(is_attack=True)
        if from_date:
            qs_all = qs_all.filter(detected_at__date__gte=from_date)
            qs     = qs.filter(detected_at__date__gte=from_date)
        if to_date:
            qs_all = qs_all.filter(detected_at__date__lte=to_date)
            qs     = qs.filter(detected_at__date__lte=to_date)

        total_all   = qs_all.count()
        total       = qs.count()
        by_type     = dict(qs.values_list('attack_type').annotate(c=Count('id')).values_list('attack_type', 'c'))
        by_severity = dict(qs.values_list('severity').annotate(c=Count('id')).values_list('severity', 'c'))
        top_ips     = list(qs.values('src_ip').annotate(count=Count('id')).order_by('-count')[:10])
        blocked_ips = []
        try:
            from alerts.models import BlacklistedIP
            blocked_ips = list(BlacklistedIP.objects.filter(is_active=True).values(
                'ip_address', 'reason', 'blocked_by', 'created_at'
            )[:20])
            for b in blocked_ips:
                b['created_at'] = b['created_at'].isoformat()
        except Exception:
            pass
        recent = list(qs.order_by('-detected_at')[:10].values(
            'id', 'attack_type', 'severity', 'src_ip', 'dst_ip', 'detected_at', 'status'
        ))
        for r in recent:
            r['detected_at'] = r['detected_at'].isoformat()

        return Response({
            'generated_at': datetime.now().isoformat(),
            'period':       {'from': from_date or 'Toute la période', 'to': to_date or 'Maintenant'},
            'summary': {
                'total_analysed': total_all,
                'total_attacks':  total,
                'total_normal':   total_all - total,
                'attack_rate':    round(total / total_all * 100, 2) if total_all > 0 else 0,
                'by_type':        by_type,
                'by_severity':    by_severity,
                'top_ips':        top_ips,
                'blocked_ips':    blocked_ips,
            },
            'recent_alerts':   recent,
            'recommendations': _recommendations(by_type, by_severity),
        })


class GeneratePDFView(APIView):
    """Génère un rapport PDF professionnel — téléchargeable directement."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                             Table, TableStyle, HRFlowable)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            import io
        except ImportError:
            return HttpResponse(
                "reportlab non installé. Lance : pip install reportlab",
                status=500
            )

        from_date = request.query_params.get('from')
        to_date   = request.query_params.get('to')
        org_name = request.user.organisation.name if getattr(request.user, 'organisation', None) else 'votre organisation'

        # ── Collecter les données ─────────────────────────────────────
        qs_all = Alert.objects.all()
        qs     = Alert.objects.filter(is_attack=True)
        if from_date:
            qs_all = qs_all.filter(detected_at__date__gte=from_date)
            qs     = qs.filter(detected_at__date__gte=from_date)
        if to_date:
            qs_all = qs_all.filter(detected_at__date__lte=to_date)
            qs     = qs.filter(detected_at__date__lte=to_date)

        total_all   = qs_all.count()
        total       = qs.count()
        by_type     = dict(qs.values_list('attack_type').annotate(c=Count('id')).values_list('attack_type', 'c'))
        by_severity = dict(qs.values_list('severity').annotate(c=Count('id')).values_list('severity', 'c'))
        top_ips     = list(qs.values('src_ip').annotate(count=Count('id')).order_by('-count')[:10])
        recent      = list(qs.order_by('-detected_at')[:20].values(
            'id', 'attack_type', 'severity', 'src_ip', 'dst_ip', 'detected_at', 'status'
        ))
        recommendations = _recommendations(by_type, by_severity)

        # ── Couleurs Mylo ─────────────────────────────────────────────
        BLUE_DARK  = colors.HexColor('#0A0E1A')
        BLUE_MID   = colors.HexColor('#0F1629')
        BLUE_ACC   = colors.HexColor('#3B82F6')
        RED        = colors.HexColor('#EF4444')
        ORANGE     = colors.HexColor('#F97316')
        YELLOW     = colors.HexColor('#EAB308')
        GREEN      = colors.HexColor('#22C55E')
        GRAY       = colors.HexColor('#94A3B8')
        WHITE      = colors.white

        SEV_COLORS = {
            'CRITICAL': RED, 'HIGH': ORANGE, 'MEDIUM': YELLOW, 'LOW': GREEN,
        }

        # ── Styles ────────────────────────────────────────────────────
        buf    = io.BytesIO()
        doc    = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm,  bottomMargin=2*cm,
        )
        styles = getSampleStyleSheet()

        def style(name, **kw):
            s = ParagraphStyle(name, parent=styles['Normal'], **kw)
            return s

        S_TITLE    = style('title',    fontSize=22, textColor=WHITE,      fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=4)
        S_SUBTITLE = style('sub',      fontSize=11, textColor=GRAY,       fontName='Helvetica',      alignment=TA_CENTER, spaceAfter=2)
        S_H1       = style('h1',       fontSize=14, textColor=BLUE_ACC,   fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=6)
        S_H2       = style('h2',       fontSize=11, textColor=WHITE,      fontName='Helvetica-Bold', spaceBefore=8,  spaceAfter=4)
        S_BODY     = style('body',     fontSize=9,  textColor=GRAY,       fontName='Helvetica',      spaceAfter=3)
        S_REC      = style('rec',      fontSize=9,  textColor=WHITE,      fontName='Helvetica',      spaceAfter=4, leftIndent=10)

        now_str  = datetime.now().strftime('%d/%m/%Y à %H:%M')
        per_from = from_date or 'Début'
        per_to   = to_date   or datetime.now().strftime('%Y-%m-%d')
        attack_rate = round(total / total_all * 100, 2) if total_all > 0 else 0

        elements = []

        # ── En-tête ───────────────────────────────────────────────────
        header_data = [[
            Paragraph('Mylo IPS', S_TITLE),
        ]]
        header_table = Table(header_data, colWidths=[17*cm])
        header_table.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,-1), BLUE_MID),
            ('ROUNDEDCORNERS', [8]),
            ('TOPPADDING',  (0,0), (-1,-1), 16),
            ('BOTTOMPADDING', (0,0), (-1,-1), 16),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.3*cm))
        elements.append(Paragraph(f'Rapport de Sécurité — {org_name}', S_SUBTITLE))
        elements.append(Paragraph(f'Généré le {now_str}  |  Période : {per_from} → {per_to}', S_SUBTITLE))
        elements.append(Spacer(1, 0.5*cm))
        elements.append(HRFlowable(width="100%", thickness=1, color=BLUE_ACC))
        elements.append(Spacer(1, 0.4*cm))

        # ── KPI Cards ─────────────────────────────────────────────────
        elements.append(Paragraph('1. Résumé Exécutif', S_H1))

        kpi_data = [[
            Paragraph(f'<font size=20><b>{total_all:,}</b></font><br/><font size=8 color="#94A3B8">Flux analysés</font>', style('k', alignment=TA_CENTER, textColor=BLUE_ACC)),
            Paragraph(f'<font size=20><b>{total:,}</b></font><br/><font size=8 color="#94A3B8">Attaques</font>',         style('k2', alignment=TA_CENTER, textColor=RED)),
            Paragraph(f'<font size=20><b>{total_all-total:,}</b></font><br/><font size=8 color="#94A3B8">Normal</font>', style('k3', alignment=TA_CENTER, textColor=GREEN)),
            Paragraph(f'<font size=20><b>{attack_rate}%</b></font><br/><font size=8 color="#94A3B8">Taux attaque</font>', style('k4', alignment=TA_CENTER, textColor=ORANGE)),
        ]]
        kpi_table = Table(kpi_data, colWidths=[4.25*cm]*4)
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), BLUE_MID),
            ('BOX',           (0,0), (0,0), 1, BLUE_ACC),
            ('BOX',           (1,0), (1,0), 1, RED),
            ('BOX',           (2,0), (2,0), 1, GREEN),
            ('BOX',           (3,0), (3,0), 1, ORANGE),
            ('TOPPADDING',    (0,0), (-1,-1), 12),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ]))
        elements.append(kpi_table)
        elements.append(Spacer(1, 0.4*cm))

        # ── Répartition par type ──────────────────────────────────────
        if by_type:
            elements.append(Paragraph('2. Répartition par Type d\'Attaque', S_H1))
            type_data = [['Type', 'Nombre', 'Sévérité']]
            TYPE_SEV = {
                'DoS':'HIGH','DDoS':'HIGH','Probe':'MEDIUM',
                'R2L':'CRITICAL','U2R':'CRITICAL','BruteForce':'HIGH',
                'WebAttack':'CRITICAL','Botnet':'CRITICAL','Infiltration':'CRITICAL',
            }
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                sev = TYPE_SEV.get(t, 'MEDIUM')
                type_data.append([t, str(c), sev])

            type_table = Table(type_data, colWidths=[7*cm, 4*cm, 6*cm])
            ts = TableStyle([
                ('BACKGROUND',    (0,0), (-1,0), BLUE_ACC),
                ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
                ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE',      (0,0), (-1,-1), 9),
                ('BACKGROUND',    (0,1), (-1,-1), BLUE_MID),
                ('TEXTCOLOR',     (0,1), (-1,-1), WHITE),
                ('ROWBACKGROUNDS',(0,1), (-1,-1), [BLUE_MID, colors.HexColor('#111827')]),
                ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#1E2D4F')),
                ('TOPPADDING',    (0,0), (-1,-1), 7),
                ('BOTTOMPADDING', (0,0), (-1,-1), 7),
                ('ALIGN',         (1,0), (1,-1), 'CENTER'),
            ])
            # Colorier la colonne sévérité
            for i, (t, c) in enumerate(sorted(by_type.items(), key=lambda x: -x[1]), 1):
                sev = TYPE_SEV.get(t, 'MEDIUM')
                col = SEV_COLORS.get(sev, GRAY)
                ts.add('TEXTCOLOR', (2,i), (2,i), col)
                ts.add('FONTNAME',  (2,i), (2,i), 'Helvetica-Bold')
            type_table.setStyle(ts)
            elements.append(type_table)
            elements.append(Spacer(1, 0.4*cm))

        # ── Top IPs suspectes ─────────────────────────────────────────
        if top_ips:
            elements.append(Paragraph('3. Top IPs Suspectes', S_H1))
            ip_data = [['Rang', 'IP Source', 'Nb Alertes']]
            for i, ip in enumerate(top_ips, 1):
                ip_data.append([f'#{i}', ip['src_ip'] or '—', str(ip['count'])])
            ip_table = Table(ip_data, colWidths=[2*cm, 10*cm, 5*cm])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,0), BLUE_ACC),
                ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
                ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE',      (0,0), (-1,-1), 9),
                ('BACKGROUND',    (0,1), (-1,-1), BLUE_MID),
                ('TEXTCOLOR',     (0,1), (-1,-1), WHITE),
                ('ROWBACKGROUNDS',(0,1), (-1,-1), [BLUE_MID, colors.HexColor('#111827')]),
                ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#1E2D4F')),
                ('TOPPADDING',    (0,0), (-1,-1), 7),
                ('BOTTOMPADDING', (0,0), (-1,-1), 7),
                ('ALIGN',         (0,0), (0,-1), 'CENTER'),
                ('ALIGN',         (2,0), (2,-1), 'CENTER'),
                ('TEXTCOLOR',     (0,1), (0,-1), BLUE_ACC),
            ]))
            elements.append(ip_table)
            elements.append(Spacer(1, 0.4*cm))

        # ── Alertes récentes ──────────────────────────────────────────
        if recent:
            elements.append(Paragraph('4. Alertes Récentes (20 dernières)', S_H1))
            rec_data = [['Heure', 'Type', 'Sévérité', 'IP Source', 'Statut']]
            STATUS_FR = {
                'new':'Nouvelle','false_positive':'Faux positif',
                'confirmed':'Confirmée','investigating':'En cours',
                'resolved':'Résolue','ignored':'Ignorée','normal':'Normal',
            }
            for a in recent:
                dt_val = a['detected_at']
                dt = dt_val.strftime('%d/%m %H:%M') if hasattr(dt_val, 'strftime') else datetime.fromisoformat(str(dt_val)).strftime('%d/%m %H:%M')
                rec_data.append([
                    dt, a['attack_type'], a['severity'],
                    a['src_ip'] or '—',
                    STATUS_FR.get(a['status'], a['status']),
                ])
            rec_table = Table(rec_data, colWidths=[2.8*cm, 3.5*cm, 2.8*cm, 4.5*cm, 3.4*cm])
            rec_ts = TableStyle([
                ('BACKGROUND',    (0,0), (-1,0), BLUE_ACC),
                ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
                ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE',      (0,0), (-1,-1), 8),
                ('BACKGROUND',    (0,1), (-1,-1), BLUE_MID),
                ('TEXTCOLOR',     (0,1), (-1,-1), WHITE),
                ('ROWBACKGROUNDS',(0,1), (-1,-1), [BLUE_MID, colors.HexColor('#111827')]),
                ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#1E2D4F')),
                ('TOPPADDING',    (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ])
            for i, a in enumerate(recent, 1):
                col = SEV_COLORS.get(a['severity'], GRAY)
                rec_ts.add('TEXTCOLOR', (2,i), (2,i), col)
                rec_ts.add('FONTNAME',  (2,i), (2,i), 'Helvetica-Bold')
            rec_table.setStyle(rec_ts)
            elements.append(rec_table)
            elements.append(Spacer(1, 0.4*cm))

        # ── Recommandations ───────────────────────────────────────────
        elements.append(Paragraph('5. Recommandations', S_H1))
        for rec in recommendations:
            elements.append(Paragraph(rec, S_REC))
        elements.append(Spacer(1, 0.4*cm))

        # ── Footer ────────────────────────────────────────────────────
        elements.append(HRFlowable(width="100%", thickness=1, color=BLUE_ACC))
        elements.append(Spacer(1, 0.2*cm))
        elements.append(Paragraph(
            f'Mylo IPS — {org_name} Security Center — Généré le {now_str}',
            style('footer', fontSize=8, textColor=GRAY, alignment=TA_CENTER)
        ))

        # ── Construire le PDF ─────────────────────────────────────────
        doc.build(elements)
        buf.seek(0)

        filename = f"mylo_rapport_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        response = HttpResponse(buf.read(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response



def _recommendations(by_type, by_severity):
    recs = []
    if by_type.get('DoS', 0) + by_type.get('DDoS', 0) > 10:
        recs.append("Volume DoS/DDoS élevé — Activer la limitation de débit sur OPNsense")
    if by_type.get('Probe', 0) > 5:
        recs.append("Activité Probe — Vérifier les règles de scan réseau")
    if by_type.get('BruteForce', 0) > 3:
        recs.append("Tentatives BruteForce — Activer fail2ban sur SSH/FTP")
    if by_type.get('WebAttack', 0) > 0:
        recs.append("WebAttack détectée — Vérifier le WAF et les entrées utilisateur")
    if by_type.get('R2L', 0) > 0:
        recs.append("Tentatives R2L — Renforcer l'authentification SSH/FTP")
    if by_type.get('U2R', 0) > 0:
        recs.append("Tentatives U2R — Audit des privilèges système immédiat")
    if by_type.get('Botnet', 0) > 0:
        recs.append("Botnet détecté — Isoler les machines suspectes du VLAN")
    if by_type.get('Infiltration', 0) > 0:
        recs.append("Infiltration détectée — Incident Response immédiat")
    if by_severity.get('CRITICAL', 0) > 0:
        recs.append("Alertes CRITICAL actives — Intervention immédiate requise")
    if not recs:
        recs.append("Situation normale — Continuer la surveillance")
    return recs



from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404

# IsAdminOrSuperAdmin → à remplacer par ta vraie classe après vérification
from rest_framework.permissions import IsAuthenticated as IsAdminOrSuperAdmin
from .models import ReportConfig
from .serializers import ReportConfigSerializer
from .tasks import send_daily_reports
from .utils.pdf_generator import generate_daily_report_pdf


@api_view(["GET", "POST", "PUT"])
@permission_classes([IsOrgAdmin])
def report_config(request):
    """GET/POST/PUT la configuration du rapport pour l'org courante."""
    org = request.user.organisation
    config, _ = ReportConfig.objects.get_or_create(
        organisation=org,
        defaults={"report_email": request.user.email, "send_hour": 7}
    )

    if request.method == "GET":
        return Response(ReportConfigSerializer(config).data)

    serializer = ReportConfigSerializer(config, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        # Replanifier la tâche Beat avec la nouvelle heure
        _update_beat_schedule(config)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsOrgAdmin])
def trigger_report_now(request):
    """Déclenche immédiatement la génération et l'envoi du rapport."""
    send_daily_reports.delay()
    return Response({"message": "Rapport en cours de génération et d'envoi."})


@api_view(["GET"])
@permission_classes([CanGenerateReports])
def preview_report(request):
    """Retourne le PDF en réponse HTTP pour prévisualisation."""
    from django.http import HttpResponse
    org = request.user.organisation
    pdf_bytes = generate_daily_report_pdf(org)
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = 'inline; filename="preview_rapport.pdf"'
    return response


def _update_beat_schedule(config):
    """Met à jour dynamiquement le schedule Celery Beat en DB."""
    try:
        from django_celery_beat.models import PeriodicTask, CrontabSchedule
        import json

        schedule, _ = CrontabSchedule.objects.get_or_create(
            hour=config.send_hour,
            minute=config.send_minute,
            day_of_week="*",
            day_of_month="*",
            month_of_year="*",
        )
        task, _ = PeriodicTask.objects.get_or_create(
            name=f"mylo-daily-report-{config.organisation.id}",
            defaults={"task": "reports.send_daily_reports"}
        )
        task.crontab = schedule
        task.enabled = config.is_active
        task.kwargs = json.dumps({"org_id": str(config.organisation.id)})
        task.save()
    except Exception:
        pass  # Beat DB non disponible (ex. en dev)