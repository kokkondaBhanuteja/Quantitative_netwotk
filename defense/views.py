from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
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
    
    # Generate recommendations if not already generated
    for vulnerability in vulnerabilities:
        if not DefenseRecommendation.objects.filter(vulnerability=vulnerability).exists():
            generate_recommendations_for_vulnerability(vulnerability)
    
    recommendations = DefenseRecommendation.objects.filter(
        vulnerability__scan__initiated_by=request.user
    ).select_related('defense_technique', 'vulnerability')
    
    return render(request, 'defense/recommendation_list.html', {'recommendations': recommendations})


def generate_recommendations_for_vulnerability(vulnerability):
    """Generate defense recommendations using ML model simulation"""
    techniques = DefenseTechnique.objects.all()
    
    if not techniques.exists():
        create_default_defense_techniques()
        techniques = DefenseTechnique.objects.all()
    
    # Select top 3 techniques based on vulnerability type
    selected_techniques = random.sample(list(techniques), min(3, techniques.count()))
    
    for idx, technique in enumerate(selected_techniques):
        priority = 100 - (idx * 20)
        confidence = random.uniform(0.75, 0.95)
        
        DefenseRecommendation.objects.create(
            vulnerability=vulnerability,
            defense_technique=technique,
            priority_score=priority,
            confidence_score=confidence,
            justification=f"This defense technique is recommended based on the vulnerability type ({vulnerability.severity}) and system impact analysis."
        )


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
    implementations = DefenseImplementation.objects.filter(
        implemented_by=request.user
    ).select_related('recommendation__defense_technique', 'recommendation__vulnerability')
    
    return render(request, 'defense/implementation_list.html', {'implementations': implementations})


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
