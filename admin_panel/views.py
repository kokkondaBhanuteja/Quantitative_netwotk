from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from accounts.models import UserProfile, ActivityLog
from vulnerability.models import VulnerabilityScan, Vulnerability, NetworkEnvironment
from defense.models import DefenseTechnique, DefenseRecommendation

def is_admin(user):
    return user.is_authenticated and (user.is_superuser or user.profile.role == 'admin')

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    # System-wide statistics
    total_users = User.objects.count()
    total_scans = VulnerabilityScan.objects.count()
    total_vulnerabilities = Vulnerability.objects.count()
    total_techniques = DefenseTechnique.objects.count()
    
    critical_vulns = Vulnerability.objects.filter(severity='critical', is_mitigated=False).count()
    high_vulns = Vulnerability.objects.filter(severity='high', is_mitigated=False).count()
    
    recent_users = User.objects.order_by('-date_joined')[:10]
    recent_scans = VulnerabilityScan.objects.order_by('-start_time')[:10]
    recent_activities = ActivityLog.objects.order_by('-timestamp')[:15]
    
    context = {
        'total_users': total_users,
        'total_scans': total_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'total_techniques': total_techniques,
        'critical_vulnerabilities': critical_vulns,
        'high_vulnerabilities': high_vulns,
        'recent_users': recent_users,
        'recent_scans': recent_scans,
        'recent_activities': recent_activities,
    }
    
    return render(request, 'admin_panel/dashboard.html', context)


@login_required
@user_passes_test(is_admin)
def user_management(request):
    users_qs = User.objects.all().select_related('profile').order_by('-date_joined')
    paginator = Paginator(users_qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'admin_panel/user_management.html', {'users': page_obj, 'page_obj': page_obj})


@login_required
@user_passes_test(is_admin)
def user_detail(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    activities = ActivityLog.objects.filter(user=user).order_by('-timestamp')[:20]
    scans = VulnerabilityScan.objects.filter(initiated_by=user)
    
    context = {
        'user_obj': user,
        'activities': activities,
        'scans': scans,
    }
    return render(request, 'admin_panel/user_detail.html', context)


@login_required
@user_passes_test(is_admin)
def toggle_user_role(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    profile = user.profile
    
    if profile.role == 'user':
        profile.role = 'admin'
    else:
        profile.role = 'user'
    
    profile.save()
    messages.success(request, f'User role updated to {profile.role}')
    return redirect('admin_panel:user_detail', user_id=user_id)


@login_required
@user_passes_test(is_admin)
def system_analytics(request):
    # Vulnerability statistics
    vuln_by_severity = Vulnerability.objects.values('severity').annotate(count=Count('id'))
    
    # Scan statistics
    scan_by_status = VulnerabilityScan.objects.values('status').annotate(count=Count('id'))
    
    # Defense technique effectiveness
    techniques = DefenseTechnique.objects.all()
    
    context = {
        'vuln_by_severity': vuln_by_severity,
        'scan_by_status': scan_by_status,
        'techniques': techniques,
    }
    
    return render(request, 'admin_panel/system_analytics.html', context)


@login_required
@user_passes_test(is_admin)
def network_config_management(request):
    environments = NetworkEnvironment.objects.all()
    return render(request, 'admin_panel/network_config_management.html', {'environments': environments})


@login_required
@user_passes_test(is_admin)
def system_maintenance(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'clear_logs':
            ActivityLog.objects.all().delete()
            messages.success(request, 'Activity logs cleared successfully')
        elif action == 'reset_scans':
            VulnerabilityScan.objects.filter(status='failed').delete()
            messages.success(request, 'Failed scans cleared successfully')
        
        return redirect('admin_panel:system_maintenance')
    
    log_count = ActivityLog.objects.count()
    failed_scans = VulnerabilityScan.objects.filter(status='failed').count()
    
    context = {
        'log_count': log_count,
        'failed_scans': failed_scans,
    }
    
    return render(request, 'admin_panel/system_maintenance.html', context)
