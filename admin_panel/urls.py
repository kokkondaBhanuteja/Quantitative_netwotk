from django.urls import path
from . import views

app_name = 'admin_panel'

urlpatterns = [
    path('', views.admin_dashboard, name='dashboard'),
    path('users/', views.user_management, name='user_management'),
    path('users/<int:user_id>/', views.user_detail, name='user_detail'),
    path('users/<int:user_id>/toggle-role/', views.toggle_user_role, name='toggle_user_role'),
    path('analytics/', views.system_analytics, name='system_analytics'),
    path('network-config/', views.network_config_management, name='network_config_management'),
    path('maintenance/', views.system_maintenance, name='system_maintenance'),
]
