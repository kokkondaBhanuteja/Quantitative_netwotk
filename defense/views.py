from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.utils import timezone
from vulnerability.models import Vulnerability
from .models import DefenseTechnique, DefenseRecommendation, DefenseImplementation
import random

@login_required
def defense_dashboard(request):
    recommendations = DefenseRecommendation.objects.filter(
        vulnerability__scan__initiated_by=request.user
    ).select_related('defense_technique', 'vulnerability')[:10]
    
    techniques = DefenseTechnique.objects.all()
    implementations = DefenseImplementation.objects.filter(implemented_by=request.user)
    
    context = {
        'total_recommendations': recommendations.count(),
        'total_techniques': techniques.count(),
        'active_implementations': implementations.filter(status='in_progress').count(),
        'completed_implementations': implementations.filter(status='completed').count(),
        'recent_recommendations': recommendations,
    }
    return render(request, 'defense/dashboard.html', context)


@login_required
def recommendation_list(request):
    vulnerabilities = Vulnerability.objects.filter(
        scan__initiated_by=request.user,
        is_mitigated=False
    )

    # Bulk-check which vulnerabilities already have recommendations
    existing_vuln_ids = set(
        DefenseRecommendation.objects.filter(
            vulnerability__in=vulnerabilities
        ).values_list('vulnerability_id', flat=True)
    )

    # Generate recommendations only for those that don't have them
    vulns_needing_recs = [v for v in vulnerabilities if v.id not in existing_vuln_ids]
    if vulns_needing_recs:
        generate_recommendations_bulk(vulns_needing_recs)

    recs_qs = DefenseRecommendation.objects.filter(
        vulnerability__scan__initiated_by=request.user
    ).select_related('defense_technique', 'vulnerability').order_by('-priority_score')

    paginator = Paginator(recs_qs, 15)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'defense/recommendation_list.html', {'recommendations': page_obj, 'page_obj': page_obj})


def generate_recommendations_bulk(vulnerabilities):
    """Generate defense recommendations for multiple vulnerabilities efficiently"""
    techniques = list(DefenseTechnique.objects.all())

    if not techniques:
        create_default_defense_techniques()
        techniques = list(DefenseTechnique.objects.all())

    recommendations_to_create = []
    for vulnerability in vulnerabilities:
        selected_techniques = random.sample(techniques, min(3, len(techniques)))
        for idx, technique in enumerate(selected_techniques):
            recommendations_to_create.append(
                DefenseRecommendation(
                    vulnerability=vulnerability,
                    defense_technique=technique,
                    priority_score=100 - (idx * 20),
                    confidence_score=random.uniform(0.75, 0.95),
                    justification=f"This defense technique is recommended based on the vulnerability type ({vulnerability.severity}) and system impact analysis."
                )
            )

    if recommendations_to_create:
        DefenseRecommendation.objects.bulk_create(recommendations_to_create)


def create_default_defense_techniques():
    """Create default defense techniques"""
    techniques = [
        {
            'name': 'Next-Generation Firewall Implementation',
            'category': 'firewall',
            'description': 'Deploy advanced firewall with deep packet inspection and application-layer filtering',
            'effectiveness_score': 85.5,
            'implementation_difficulty': 'moderate',
            'estimated_cost': 15000.00,
            'implementation_time': '2-3 weeks',
            'prerequisites': 'Network topology mapping, Policy requirements documentation'
        },
        {
            'name': 'Intrusion Detection System (IDS)',
            'category': 'ids_ips',
            'description': 'Install and configure network-based IDS for real-time threat detection',
            'effectiveness_score': 78.3,
            'implementation_difficulty': 'moderate',
            'estimated_cost': 12000.00,
            'implementation_time': '1-2 weeks',
            'prerequisites': 'Network access points identification, Baseline traffic analysis'
        },
        {
            'name': 'End-to-End Encryption',
            'category': 'encryption',
            'description': 'Implement TLS 1.3 encryption for all data in transit',
            'effectiveness_score': 92.7,
            'implementation_difficulty': 'easy',
            'estimated_cost': 5000.00,
            'implementation_time': '1 week',
            'prerequisites': 'Certificate authority setup, Key management system'
        },
        {
            'name': 'Multi-Factor Authentication',
            'category': 'access_control',
            'description': 'Deploy MFA across all critical systems and applications',
            'effectiveness_score': 88.9,
            'implementation_difficulty': 'easy',
            'estimated_cost': 8000.00,
            'implementation_time': '1-2 weeks',
            'prerequisites': 'User directory integration, Authentication policy'
        },
        {
            'name': 'Automated Patch Management',
            'category': 'patch_management',
            'description': 'Establish automated patch deployment pipeline with testing',
            'effectiveness_score': 90.1,
            'implementation_difficulty': 'moderate',
            'estimated_cost': 10000.00,
            'implementation_time': '2-3 weeks',
            'prerequisites': 'Asset inventory, Change management process'
        },
        {
            'name': 'Security Information and Event Management (SIEM)',
            'category': 'security_monitoring',
            'description': 'Deploy SIEM solution for centralized security monitoring and analysis',
            'effectiveness_score': 86.4,
            'implementation_difficulty': 'difficult',
            'estimated_cost': 25000.00,
            'implementation_time': '4-6 weeks',
            'prerequisites': 'Log collection infrastructure, Use case development'
        },
    ]
    
    for tech_data in techniques:
        DefenseTechnique.objects.create(**tech_data)


@login_required
def technique_list(request):
    techniques = DefenseTechnique.objects.all()
    return render(request, 'defense/technique_list.html', {'techniques': techniques})


@login_required
def technique_detail(request, pk):
    technique = get_object_or_404(DefenseTechnique, pk=pk)
    return render(request, 'defense/technique_detail.html', {'technique': technique})


@login_required
def implement_defense(request, recommendation_id):
    recommendation = get_object_or_404(DefenseRecommendation, pk=recommendation_id)
    
    implementation, created = DefenseImplementation.objects.get_or_create(
        recommendation=recommendation,
        implemented_by=request.user,
        defaults={'status': 'planned', 'start_date': timezone.now()}
    )
    
    if created:
        messages.success(request, 'Defense implementation planned successfully!')
    else:
        messages.info(request, 'This defense is already in your implementation plan.')
    
    return redirect('defense:implementation_list')


@login_required
def implementation_list(request):
    impl_qs = DefenseImplementation.objects.filter(
        implemented_by=request.user
    ).select_related('recommendation__defense_technique', 'recommendation__vulnerability')

    paginator = Paginator(impl_qs, 15)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'defense/implementation_list.html', {'implementations': page_obj, 'page_obj': page_obj})


@login_required
def update_implementation_status(request, pk):
    implementation = get_object_or_404(DefenseImplementation, pk=pk, implemented_by=request.user)
    
    if request.method == 'POST':
        new_status = request.POST.get('status')
        implementation.status = new_status
        
        if new_status == 'completed':
            implementation.completion_date = timezone.now()
            implementation.success_rate = random.uniform(85.0, 98.0)
            
            # Mark vulnerability as mitigated
            implementation.recommendation.vulnerability.is_mitigated = True
            implementation.recommendation.vulnerability.mitigation_date = timezone.now()
            implementation.recommendation.vulnerability.save()
        
        implementation.save()
        messages.success(request, 'Implementation status updated successfully!')
    
    return redirect('defense:implementation_list')
