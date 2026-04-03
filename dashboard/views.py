from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from vulnerability.models import VulnerabilityScan, Vulnerability
from defense.models import DefenseRecommendation, DefenseImplementation
from accounts.models import ActivityLog

@login_required
def dashboard_index(request):
    # Single aggregated query for all vulnerability counts
    vuln_stats = Vulnerability.objects.filter(
        scan__initiated_by=request.user
    ).aggregate(
        total=Count('id'),
        critical=Count('id', filter=Q(severity='critical', is_mitigated=False)),
        high=Count('id', filter=Q(severity='high', is_mitigated=False)),
        medium=Count('id', filter=Q(severity='medium', is_mitigated=False)),
        low=Count('id', filter=Q(severity='low', is_mitigated=False)),
        mitigated=Count('id', filter=Q(is_mitigated=True)),
    )

    total_scans = VulnerabilityScan.objects.filter(initiated_by=request.user).count()

    # Defense statistics
    total_recommendations = DefenseRecommendation.objects.filter(
        vulnerability__scan__initiated_by=request.user
    ).count()

    active_implementations = DefenseImplementation.objects.filter(
        implemented_by=request.user,
        status='in_progress'
    ).count()

    # Recent activity with select_related
    recent_scans = VulnerabilityScan.objects.filter(
        initiated_by=request.user
    ).select_related('network_environment').order_by('-start_time')[:5]

    recent_vulnerabilities = Vulnerability.objects.filter(
        scan__initiated_by=request.user
    ).select_related('scan').order_by('-discovered_date')[:5]

    recent_activities = ActivityLog.objects.filter(
        user=request.user
    ).order_by('-timestamp')[:10]

    # Calculate threat level
    critical_vulns = vuln_stats['critical']
    high_vulns = vuln_stats['high']
    medium_vulns = vuln_stats['medium']

    if critical_vulns > 5:
        threat_level = 'Critical'
    elif critical_vulns > 0 or high_vulns > 10:
        threat_level = 'High'
    elif high_vulns > 0 or medium_vulns > 15:
        threat_level = 'Medium'
    else:
        threat_level = 'Low'

    context = {
        'total_scans': total_scans,
        'total_vulnerabilities': vuln_stats['total'],
        'critical_vulnerabilities': critical_vulns,
        'high_vulnerabilities': high_vulns,
        'medium_vulnerabilities': medium_vulns,
        'low_vulnerabilities': vuln_stats['low'],
        'mitigated_vulnerabilities': vuln_stats['mitigated'],
        'total_recommendations': total_recommendations,
        'active_implementations': active_implementations,
        'threat_level': threat_level,
        'recent_scans': recent_scans,
        'recent_vulnerabilities': recent_vulnerabilities,
        'recent_activities': recent_activities,
    }

    return render(request, 'dashboard/index.html', context)
