from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.contrib import messages
from django.utils import timezone
from vulnerability.models import VulnerabilityScan, Vulnerability
from defense.models import DefenseRecommendation, DefenseImplementation
from .models import Report
import json
from datetime import datetime

@login_required
def report_list(request):
    reports_qs = Report.objects.filter(generated_by=request.user).order_by('-generated_at')
    paginator = Paginator(reports_qs, 15)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'reports/report_list.html', {'reports': page_obj, 'page_obj': page_obj})


@login_required
def generate_report(request):
    if request.method == 'POST':
        report_type = request.POST.get('report_type')
        
        report_data = {}
        
        if report_type == 'security_assessment':
            report_data = generate_security_assessment(request.user)
        elif report_type == 'vulnerability_summary':
            report_data = generate_vulnerability_summary(request.user)
        elif report_type == 'defense_recommendations':
            report_data = generate_defense_recommendations_report(request.user)
        elif report_type == 'mitigation_results':
            report_data = generate_mitigation_results(request.user)
        elif report_type == 'comprehensive':
            report_data = generate_comprehensive_report(request.user)
        
        report = Report.objects.create(
            title=f"{dict(Report.REPORT_TYPES)[report_type]} - {timezone.now().strftime('%Y-%m-%d %H:%M')}",
            report_type=report_type,
            generated_by=request.user,
            content=report_data
        )
        
        messages.success(request, 'Report generated successfully!')
        return redirect('reports:report_detail', pk=report.pk)
    
    report_types = Report.REPORT_TYPES
    return render(request, 'reports/generate_report.html', {'report_types': report_types})


def generate_security_assessment(user):
    scans = VulnerabilityScan.objects.filter(initiated_by=user)
    vulnerabilities = Vulnerability.objects.filter(scan__initiated_by=user)
    
    return {
        'total_scans': scans.count(),
        'total_vulnerabilities': vulnerabilities.count(),
        'critical_count': vulnerabilities.filter(severity='critical').count(),
        'high_count': vulnerabilities.filter(severity='high').count(),
        'medium_count': vulnerabilities.filter(severity='medium').count(),
        'low_count': vulnerabilities.filter(severity='low').count(),
        'mitigated_count': vulnerabilities.filter(is_mitigated=True).count(),
        'generated_at': timezone.now().isoformat(),
    }


def generate_vulnerability_summary(user):
    vulnerabilities = Vulnerability.objects.filter(scan__initiated_by=user)
    
    vulns_list = []
    for vuln in vulnerabilities[:50]:  # Limit to 50 most recent
        vulns_list.append({
            'cve_id': vuln.cve_id,
            'name': vuln.name,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'affected_system': vuln.affected_system,
            'is_mitigated': vuln.is_mitigated,
        })
    
    return {
        'vulnerabilities': vulns_list,
        'total_count': vulnerabilities.count(),
        'generated_at': timezone.now().isoformat(),
    }


def generate_defense_recommendations_report(user):
    recommendations = DefenseRecommendation.objects.filter(
        vulnerability__scan__initiated_by=user
    ).select_related('defense_technique', 'vulnerability')
    
    recs_list = []
    for rec in recommendations[:50]:
        recs_list.append({
            'vulnerability_cve': rec.vulnerability.cve_id,
            'technique_name': rec.defense_technique.name,
            'priority_score': rec.priority_score,
            'confidence_score': rec.confidence_score,
            'category': rec.defense_technique.category,
        })
    
    return {
        'recommendations': recs_list,
        'total_count': recommendations.count(),
        'generated_at': timezone.now().isoformat(),
    }


def generate_mitigation_results(user):
    implementations = DefenseImplementation.objects.filter(
        implemented_by=user
    ).select_related('recommendation__defense_technique')
    
    impl_list = []
    for impl in implementations:
        impl_list.append({
            'technique': impl.recommendation.defense_technique.name,
            'status': impl.status,
            'start_date': impl.start_date.isoformat() if impl.start_date else None,
            'completion_date': impl.completion_date.isoformat() if impl.completion_date else None,
            'success_rate': impl.success_rate,
        })
    
    return {
        'implementations': impl_list,
        'total_count': implementations.count(),
        'completed_count': implementations.filter(status='completed').count(),
        'in_progress_count': implementations.filter(status='in_progress').count(),
        'generated_at': timezone.now().isoformat(),
    }


def generate_comprehensive_report(user):
    return {
        'security_assessment': generate_security_assessment(user),
        'vulnerability_summary': generate_vulnerability_summary(user),
        'defense_recommendations': generate_defense_recommendations_report(user),
        'mitigation_results': generate_mitigation_results(user),
        'generated_at': timezone.now().isoformat(),
    }


@login_required
def report_detail(request, pk):
    report = get_object_or_404(Report, pk=pk, generated_by=request.user)
    # Pre-format JSON for safe display (avoids |safe XSS risk)
    report_content_json = json.dumps(report.content, indent=2, default=str)
    return render(request, 'reports/report_detail.html', {
        'report': report,
        'report_content_json': report_content_json,
    })


@login_required
def download_report(request, pk):
    report = get_object_or_404(Report, pk=pk, generated_by=request.user)
    
    # Create JSON response
    response = HttpResponse(
        json.dumps(report.content, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="{report.title}.json"'
    
    return response
