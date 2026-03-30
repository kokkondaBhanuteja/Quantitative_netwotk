from django.urls import path
from . import views

app_name = 'defense'

urlpatterns = [
    path('', views.defense_dashboard, name='dashboard'),
    path('recommendations/', views.recommendation_list, name='recommendation_list'),
    path('techniques/', views.technique_list, name='technique_list'),
    path('techniques/<int:pk>/', views.technique_detail, name='technique_detail'),
    path('implement/<int:recommendation_id>/', views.implement_defense, name='implement_defense'),
    path('implementations/', views.implementation_list, name='implementation_list'),
    path('implementations/<int:pk>/update/', views.update_implementation_status, name='update_implementation_status'),
]
