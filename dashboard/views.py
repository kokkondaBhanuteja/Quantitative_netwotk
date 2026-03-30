from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from vulnerability.models import VulnerabilityScan, Vulnerability
from defense.models import DefenseRecommendation, DefenseImplementation
from accounts.models import ActivityLog

@login_required
def dashboard_index(request):
    # Get user-specific statistics
    total_scans = VulnerabilityScan.objects.filter(initiated_by=request.user).count()
    total_vulnerabilities = Vulnerability.objects.filter(scan__initiated_by=request.user).count()
    
    critical_vulns = Vulnerability.objects.filter(
        scan__initiated_by=request.user,
        severity='critical',
        is_mitigated=False
    ).count()
    
    high_vulns = Vulnerability.objects.filter(
        scan__initiated_by=request.user,
        severity='high',
        is_mitigated=False
    ).count()
    
    medium_vulns = Vulnerability.objects.filter(
        scan__initiated_by=request.user,
        severity='medium',
        is_mitigated=False
    ).count()
    
    low_vulns = Vulnerability.objects.filter(
        scan__initiated_by=request.user,
        severity='low',
        is_mitigated=False
    ).count()
    
    mitigated_vulns = Vulnerability.objects.filter(
        scan__initiated_by=request.user,
        is_mitigated=True
    ).count()
    
    # Defense statistics
    total_recommendations = DefenseRecommendation.objects.filter(
        vulnerability__scan__initiated_by=request.user
    ).count()
    
    active_implementations = DefenseImplementation.objects.filter(
        implemented_by=request.user,
        status='in_progress'
    ).count()
    
    # Recent activity
    recent_scans = VulnerabilityScan.objects.filter(
        initiated_by=request.user
    ).order_by('-start_time')[:5]
    
    recent_vulnerabilities = Vulnerability.objects.filter(
        scan__initiated_by=request.user
    ).order_by('-discovered_date')[:5]
    
    recent_activities = ActivityLog.objects.filter(
        user=request.user
    ).order_by('-timestamp')[:10]
    
    # Calculate threat level
    if critical_vulns > 5:
        threat_level = 'Critical'
        threat_color = 'danger'
    elif critical_vulns > 0 or high_vulns > 10:
        threat_level = 'High'
        threat_color = 'warning'
    elif high_vulns > 0 or medium_vulns > 15:
        threat_level = 'Medium'
        threat_color = 'info'
    else:
        threat_level = 'Low'
        threat_color = 'success'
    
    context = {
        'total_scans': total_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulnerabilities': critical_vulns,
        'high_vulnerabilities': high_vulns,
        'medium_vulnerabilities': medium_vulns,
        'low_vulnerabilities': low_vulns,
        'mitigated_vulnerabilities': mitigated_vulns,
        'total_recommendations': total_recommendations,
        'active_implementations': active_implementations,
        'threat_level': threat_level,
        'threat_color': threat_color,
        'recent_scans': recent_scans,
        'recent_vulnerabilities': recent_vulnerabilities,
        'recent_activities': recent_activities,
    }
    
    return render(request, 'dashboard/index.html', context)
