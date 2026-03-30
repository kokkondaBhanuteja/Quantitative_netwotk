"""
Create a realistic training dataset for ML model
Based on real vulnerability patterns and defense strategies
IMPROVED VERSION with better data distribution
"""
import json
import os
import random

def create_training_dataset():
    """Create comprehensive training dataset with better distribution"""
    
    training_data = []
    
    # Enhanced vulnerability to defense mappings
    vulnerability_defenses = {
        'SQL Injection': [
            ('Parameterized Queries', 0.95),
            ('Web Application Firewall', 0.80),
            ('Input Validation', 0.75),
            ('Database Security Hardening', 0.70),
        ],
        'XSS': [
            ('Content Security Policy', 0.90),
            ('Output Encoding', 0.88),
            ('Web Application Firewall', 0.75),
            ('Input Validation', 0.70),
        ],
        'Remote Code Execution': [
            ('Patch Management System', 0.95),
            ('Network Segmentation', 0.85),
            ('Intrusion Detection System', 0.82),
            ('Application Whitelisting', 0.80),
        ],
        'Privilege Escalation': [
            ('Access Control Lists', 0.88),
            ('Patch Management System', 0.85),
            ('Security Monitoring', 0.75),
        ],
        'Weak Encryption': [
            ('Encryption Upgrade', 0.93),
            ('TLS Configuration', 0.90),
            ('Certificate Management', 0.82),
        ],
        'Default Credentials': [
            ('Multi-Factor Authentication', 0.98),
            ('Password Policy Enforcement', 0.92),
            ('Account Lockout Policies', 0.85),
        ],
        'Path Traversal': [
            ('Input Validation', 0.90),
            ('Web Application Firewall', 0.82),
            ('File System Permissions', 0.78),
        ],
        'XXE': [
            ('XML Parser Configuration', 0.93),
            ('Input Validation', 0.85),
            ('Web Application Firewall', 0.78),
        ],
        'Insecure Deserialization': [
            ('Secure Coding Practices', 0.90),
            ('Input Validation', 0.85),
            ('Intrusion Detection System', 0.80),
        ],
        'Server-Side Request Forgery': [
            ('URL Whitelisting', 0.88),
            ('Network Segmentation', 0.85),
            ('Input Validation', 0.78),
        ],
        'Command Injection': [
            ('Input Sanitization', 0.92),
            ('Application Sandboxing', 0.85),
            ('Web Application Firewall', 0.80),
        ],
        'Broken Authentication': [
            ('Multi-Factor Authentication', 0.95),
            ('Session Management', 0.88),
            ('Password Policy Enforcement', 0.82),
        ],
    }
    
    # Severity distributions for each vulnerability type
    severity_distributions = {
        'SQL Injection': {'critical': 0.7, 'high': 0.3},
        'XSS': {'high': 0.7, 'medium': 0.3},
        'Remote Code Execution': {'critical': 1.0},
        'Privilege Escalation': {'high': 0.6, 'medium': 0.4},
        'Weak Encryption': {'medium': 0.7, 'low': 0.3},
        'Default Credentials': {'critical': 0.8, 'high': 0.2},
        'Path Traversal': {'high': 0.6, 'medium': 0.4},
        'XXE': {'high': 1.0},
        'Insecure Deserialization': {'critical': 1.0},
        'Server-Side Request Forgery': {'medium': 0.6, 'high': 0.4},
        'Command Injection': {'critical': 1.0},
        'Broken Authentication': {'high': 1.0},
    }
    
    # CVSS score ranges
    cvss_ranges = {
        'critical': (9.0, 10.0),
        'high': (7.0, 8.9),
        'medium': (4.0, 6.9),
        'low': (0.1, 3.9),
    }
    
    # Generate balanced training samples
    samples_per_vuln = 200  # Increased from 100
    
    for vuln_type, defenses in vulnerability_defenses.items():
        severity_dist = severity_distributions[vuln_type]
        
        for i in range(samples_per_vuln):
            # Select severity based on distribution
            severity = random.choices(
                list(severity_dist.keys()),
                weights=list(severity_dist.values())
            )[0]
            
            # Generate CVSS score based on severity
            cvss_min, cvss_max = cvss_ranges[severity]
            cvss_score = round(random.uniform(cvss_min, cvss_max), 1)
            
            # Determine if exploit is available (higher for critical/high)
            exploit_rate = {'critical': 0.9, 'high': 0.75, 'medium': 0.5, 'low': 0.3}
            has_exploit = random.random() < exploit_rate.get(severity, 0.5)
            
            # For each defense, create training sample with proper weighting
            for defense_name, base_probability in defenses:
                # Should we include this defense for this sample?
                # Higher probability defenses appear more often
                if random.random() < base_probability:
                    effectiveness = random.gauss(base_probability * 100, 5)
                    effectiveness = max(60, min(100, effectiveness))  # Clamp between 60-100
                    
                    training_data.append({
                        'vulnerability_type': vuln_type,
                        'severity': severity,
                        'cvss_score': cvss_score,
                        'has_exploit': has_exploit,
                        'defense_technique': defense_name,
                        'effectiveness': round(effectiveness, 2),
                    })
    
    # Shuffle the data
    random.shuffle(training_data)
    
    return training_data


def save_training_dataset():
    """Save training dataset to file"""
    
    print("="*80)
    print("CREATING IMPROVED TRAINING DATASET")
    print("="*80)
    print()
    
    data = create_training_dataset()
    
    os.makedirs('datasets', exist_ok=True)
    
    # Save as JSON
    output_file = 'datasets/training_dataset.json'
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"✓ Created {len(data)} training samples")
    print(f"✓ Saved to: {output_file}")
    print()
    
    # Statistics
    vuln_types = {}
    defense_types = {}
    severity_counts = {}
    
    for item in data:
        vtype = item['vulnerability_type']
        dtype = item['defense_technique']
        sev = item['severity']
        
        vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        defense_types[dtype] = defense_types.get(dtype, 0) + 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"Dataset Statistics:")
    print(f"  - Unique Vulnerability Types: {len(vuln_types)}")
    print(f"  - Unique Defense Techniques: {len(defense_types)}")
    print(f"  - Total Training Samples: {len(data)}")
    print()
    
    print("Severity Distribution:")
    for sev, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / len(data)) * 100
        print(f"  - {sev.capitalize()}: {count} samples ({percentage:.1f}%)")
    print()
    
    print("Top 10 Vulnerability Types:")
    for i, (vtype, count) in enumerate(sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:10], 1):
        print(f"  {i}. {vtype}: {count} samples")
    print()
    
    print("Top 10 Defense Techniques:")
    for i, (dtype, count) in enumerate(sorted(defense_types.items(), key=lambda x: x[1], reverse=True)[:10], 1):
        print(f"  {i}. {dtype}: {count} samples")
    
    print()
    print("="*80)


if __name__ == '__main__':
    save_training_dataset()
