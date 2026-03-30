import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os

class DefenseRecommender:
    def __init__(self):
        self.model = None
        self.label_encoders = {}
        self.model_path = 'ml_models/trained_models/defense_recommender.pkl'
        
    def prepare_training_data(self):
        """Create training dataset from historical data"""
        # This would come from your database in production
        data = {
            'vulnerability_type': [
                'SQL Injection', 'SQL Injection', 'SQL Injection',
                'XSS', 'XSS', 'XSS',
                'RCE', 'RCE', 'RCE',
                'Weak Encryption', 'Weak Encryption',
                'Default Credentials', 'Default Credentials'
            ],
            'severity': [
                'critical', 'critical', 'critical',
                'high', 'high', 'high',
                'critical', 'critical', 'critical',
                'medium', 'medium',
                'critical', 'critical'
            ],
            'cvss_score': [
                9.8, 9.5, 9.7,
                7.5, 8.0, 7.8,
                9.9, 9.6, 9.8,
                5.3, 5.5,
                10.0, 9.8
            ],
            'has_exploit': [
                True, True, True,
                True, False, True,
                True, True, True,
                False, False,
                True, True
            ],
            'defense_technique': [
                'Patch Management', 'Firewall', 'IDS/IPS',
                'Content Security Policy', 'Input Validation', 'WAF',
                'Patch Management', 'Access Control', 'Network Segmentation',
                'Encryption Upgrade', 'TLS Configuration',
                'Password Policy', 'MFA'
            ],
            'effectiveness': [
                95, 85, 90,
                92, 88, 94,
                98, 85, 87,
                90, 88,
                95, 99
            ]
        }
        
        return pd.DataFrame(data)
    
    def train_model(self):
        """Train the ML model"""
        print("Training defense recommendation model...")
        
        # Get training data
        df = self.prepare_training_data()
        
        # Encode categorical variables
        for column in ['vulnerability_type', 'severity', 'defense_technique']:
            le = LabelEncoder()
            df[f'{column}_encoded'] = le.fit_transform(df[column])
            self.label_encoders[column] = le
        
        # Features and target
        X = df[['vulnerability_type_encoded', 'severity_encoded', 
                'cvss_score', 'has_exploit']].values
        y = df['defense_technique_encoded'].values
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X, y)
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'label_encoders': self.label_encoders
        }, self.model_path)
        
        print("Model training completed!")
        
    def load_model(self):
        """Load trained model"""
        if os.path.exists(self.model_path):
            data = joblib.load(self.model_path)
            self.model = data['model']
            self.label_encoders = data['label_encoders']
            return True
        return False
    
    def predict_defense(self, vulnerability):
        """Predict best defense technique for a vulnerability"""
        if not self.model:
            if not self.load_model():
                self.train_model()
        
        # Encode input
        vuln_type_encoded = self.label_encoders['vulnerability_type'].transform([vulnerability['type']])[0]
        severity_encoded = self.label_encoders['severity'].transform([vulnerability['severity']])[0]
        
        # Prepare features
        features = np.array([[
            vuln_type_encoded,
            severity_encoded,
            vulnerability['cvss_score'],
            vulnerability.get('has_exploit', False)
        ]])
        
        # Predict
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        
        # Get top 3 recommendations
        top_indices = np.argsort(probabilities)[-3:][::-1]
        
        recommendations = []
        for idx in top_indices:
            defense_name = self.label_encoders['defense_technique'].inverse_transform([idx])[0]
            confidence = probabilities[idx]
            
            recommendations.append({
                'defense_technique': defense_name,
                'confidence_score': confidence,
                'priority_score': confidence * 100
            })
        
        return recommendations
