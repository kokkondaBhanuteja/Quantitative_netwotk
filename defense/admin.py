from django.contrib import admin
from .models import DefenseTechnique, DefenseRecommendation, DefenseImplementation

@admin.register(DefenseTechnique)
class DefenseTechniqueAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'effectiveness_score', 'implementation_difficulty', 'estimated_cost']
    list_filter = ['category', 'implementation_difficulty']
    search_fields = ['name', 'description']

@admin.register(DefenseRecommendation)
class DefenseRecommendationAdmin(admin.ModelAdmin):
    list_display = ['defense_technique', 'vulnerability', 'priority_score', 'confidence_score']
    list_filter = ['priority_score', 'confidence_score']
    search_fields = ['defense_technique__name', 'vulnerability__cve_id']

@admin.register(DefenseImplementation)
class DefenseImplementationAdmin(admin.ModelAdmin):
    list_display = ['recommendation', 'implemented_by', 'status', 'start_date', 'completion_date']
    list_filter = ['status', 'start_date']
    search_fields = ['recommendation__defense_technique__name']
