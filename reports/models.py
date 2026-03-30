from django.db import models
from django.contrib.auth.models import User

class Report(models.Model):
    REPORT_TYPES = [
        ('security_assessment', 'Security Assessment'),
        ('vulnerability_summary', 'Vulnerability Summary'),
        ('defense_recommendations', 'Defense Recommendations'),
        ('mitigation_results', 'Mitigation Results'),
        ('comprehensive', 'Comprehensive Report'),
    ]
    
    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES)
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    generated_at = models.DateTimeField(auto_now_add=True)
    file_path = models.FileField(upload_to='reports/', null=True, blank=True)
    content = models.JSONField(default=dict)
    
    def __str__(self):
        return f"{self.title} - {self.generated_at.strftime('%Y-%m-%d')}"
    
    class Meta:
        db_table = 'report'
        ordering = ['-generated_at']
