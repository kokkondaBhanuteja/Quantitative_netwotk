"""
ML Model Diagnostic Script
Run this to check if your project is using ML models or simulation
"""

import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_security_project.settings')
django.setup()

from defense.models import DefenseRecommendation
from vulnerability.models import VulnerabilityScan, Vulnerability
from django.db.models import Count

def check_ml_model_status():
    """Check if ML model is being used"""
    
    print("=" * 80)
    print("ML MODEL DIAGNOSTIC REPORT")
    print("=" * 80)
    print()
    
    # 1. Check if ML model file exists
    print("1. CHECKING ML MODEL FILES:")
    print("-" * 80)
    model_path = 'ml_models/trained_models/defense_recommender_real.pkl'
    if os.path.exists(model_path):
        print(f"   ✅ ML Model Found: {model_path}")
        file_size = os.path.getsize(model_path)
        print(f"   📊 Model Size: {file_size / 1024:.2f} KB")
        from datetime import datetime
        mod_time = datetime.fromtimestamp(os.path.getmtime(model_path))
        print(f"   📅 Last Modified: {mod_time}")
    else:
        print(f"   ❌ ML Model NOT Found: {model_path}")
        print(f"   ⚠️  Using SIMULATION MODE")
    print()
    
    # 2. Check if ML recommender module exists
    print("2. CHECKING ML RECOMMENDER MODULE:")
    print("-" * 80)
    try:
        from defense.ml_recommender import DefenseRecommender
        print("   ✅ ML Recommender Module: INSTALLED")
        
        # Check if model is loaded
        recommender = DefenseRecommender()
        if recommender.load_model():
            print("   ✅ ML Model: LOADED SUCCESSFULLY")
            print(f"   🤖 Model Type: Random Forest Classifier")
        else:
            print("   ⚠️  ML Model: NOT LOADED (needs training)")
    except ImportError as e:
        print(f"   ❌ ML Recommender Module: NOT FOUND")
        print(f"   📝 Error: {e}")
    print()
    
    # 3. Check scanner module
    print("3. CHECKING VULNERABILITY SCANNER:")
    print("-" * 80)
    try:
        from vulnerability.scanner import VulnerabilityScanner
        print("   ✅ Scanner Module: INSTALLED")
    except ImportError:
        print("   ❌ Scanner Module: NOT FOUND")
        print("   ⚠️  Using SIMULATION MODE for scans")
    print()
    
    # 4. Check defense recommendations source
    print("4. ANALYZING DEFENSE RECOMMENDATIONS:")
    print("-" * 80)
    total_recommendations = DefenseRecommendation.objects.count()
    print(f"   📊 Total Recommendations: {total_recommendations}")
    
    if total_recommendations > 0:
        # Check recommendation sources
        ml_recommendations = DefenseRecommendation.objects.filter(
            recommended_by__icontains='ML'
        ).count()
        simulation_recommendations = DefenseRecommendation.objects.filter(
            recommended_by__icontains='Simulation'
        ).count()
        
        print(f"   🤖 ML-Based: {ml_recommendations}")
        print(f"   🎭 Simulation: {simulation_recommendations}")
        
        # Show sample recommendations
        print()
        print("   📋 Recent Recommendations Sample:")
        samples = DefenseRecommendation.objects.select_related(
            'defense_technique', 'vulnerability'
        )[:3]
        
        for i, rec in enumerate(samples, 1):
            print(f"      {i}. {rec.defense_technique.name}")
            print(f"         Vulnerability: {rec.vulnerability.cve_id}")
            print(f"         Source: {rec.recommended_by}")
            print(f"         Confidence: {rec.confidence_score * 100:.1f}%")
            print(f"         Priority: {rec.priority_score:.0f}")
            print()
    else:
        print("   ⚠️  No recommendations found yet")
    print()
    
    # 5. Check vulnerability detection method
    print("5. CHECKING VULNERABILITY DETECTION METHOD:")
    print("-" * 80)
    
    # Check the actual code to see which mode is active
    try:
        with open('vulnerability/views.py', 'r', encoding='utf-8') as f:
            content = f.read()
            if 'use_real_scan = True' in content:
                print("   ✅ Mode: REAL SCANNING (Production)")
                print("   🔍 Using: VulnerabilityScanner with nmap, SQL injection tests, XSS detection")
            elif 'use_real_scan = False' in content:
                print("   🎭 Mode: SIMULATION (Development/Demo)")
                print("   🔍 Using: Hardcoded vulnerability templates")
            else:
                print("   ⚠️  Mode: UNKNOWN")
    except FileNotFoundError:
        print("   ❌ Cannot read vulnerability/views.py")
    print()
    
    # 6. Check scans performed
    print("6. SCAN STATISTICS:")
    print("-" * 80)
    total_scans = VulnerabilityScan.objects.count()
    completed_scans = VulnerabilityScan.objects.filter(status='completed').count()
    total_vulns = Vulnerability.objects.count()
    
    print(f"   📊 Total Scans: {total_scans}")
    print(f"   ✅ Completed: {completed_scans}")
    print(f"   🐛 Vulnerabilities Found: {total_vulns}")
    print()
    
    # 7. Final verdict
    print("=" * 80)
    print("FINAL VERDICT:")
    print("=" * 80)
    
    if os.path.exists(model_path):
        print("✅ Your project IS using ML models")
        print("🤖 Model: Random Forest Classifier for defense recommendations")
    else:
        print("❌ Your project is NOT using ML models")
        print("🎭 Current Mode: SIMULATION/DEMO")
        print()
        print("TO ENABLE ML MODELS:")
        print("1. Run: python manage.py train_ml_model")
        print("2. Verify model file exists at: ml_models/trained_models/defense_recommender_real.pkl")
        print("3. Run this diagnostic again")
    
    print("=" * 80)

if __name__ == '__main__':
    check_ml_model_status()
