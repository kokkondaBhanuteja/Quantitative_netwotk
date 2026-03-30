from django.db import models
from django.contrib.auth.models import User
from vulnerability.models import Vulnerability

class DefenseTechnique(models.Model):
    CATEGORY_CHOICES = [
        ('firewall', 'Firewall'),
        ('ids_ips', 'IDS/IPS'),
        ('encryption', 'Encryption'),
        ('access_control', 'Access Control'),
        ('patch_management', 'Patch Management'),
        ('security_monitoring', 'Security Monitoring'),
    ]
    
    name = models.CharField(max_length=200)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    description = models.TextField()
    effectiveness_score = models.FloatField(help_text='Score from 0-100')
    implementation_difficulty = models.CharField(max_length=20, choices=[
        ('easy', 'Easy'),
        ('moderate', 'Moderate'),
        ('difficult', 'Difficult')
    ])
    estimated_cost = models.DecimalField(max_digits=10, decimal_places=2)
    implementation_time = models.CharField(max_length=100)
    prerequisites = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'defense_technique'


class DefenseRecommendation(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='defense_recommendations')
    defense_technique = models.ForeignKey(DefenseTechnique, on_delete=models.CASCADE)
    priority_score = models.FloatField()
    recommended_by = models.CharField(max_length=100, default='ML Model')
    confidence_score = models.FloatField()
    justification = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.defense_technique.name} for {self.vulnerability.cve_id}"
    
    class Meta:
        db_table = 'defense_recommendation'
        ordering = ['-priority_score']


class DefenseImplementation(models.Model):
    STATUS_CHOICES = [
        ('planned', 'Planned'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    recommendation = models.ForeignKey(DefenseRecommendation, on_delete=models.CASCADE)
    implemented_by = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='planned')
    start_date = models.DateTimeField(null=True, blank=True)
    completion_date = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    success_rate = models.FloatField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.recommendation.defense_technique.name} - {self.status}"
    
    class Meta:
        db_table = 'defense_implementation'
