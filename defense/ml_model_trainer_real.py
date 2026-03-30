import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error
import joblib
import json
import os

class RealDefenseRecommender:
    def __init__(self):
        self.model = None
        self.label_encoders = {}
        self.defense_techniques = []
        self.vulnerability_types = []
        self.model_path = 'ml_models/trained_models/defense_recommender_real.pkl'
        
    def load_training_dataset(self):
        """Load training dataset from local file"""
        dataset_file = 'datasets/training_dataset.json'
        
        if not os.path.exists(dataset_file):
            print(f"Training dataset not found: {dataset_file}")
            from scripts.create_training_dataset import save_training_dataset
            save_training_dataset()
        
        with open(dataset_file, 'r') as f:
            data = json.load(f)
        
        return pd.DataFrame(data)
    
    def train_model(self):
        """Train Random Forest regression model to predict defense effectiveness"""
        
        print("\n" + "="*80)
        print("TRAINING ML MODEL - RANDOM FOREST DEFENSE RECOMMENDER")
        print("="*80 + "\n")
        
        # Load training data
        print("Loading training dataset...")
        df = self.load_training_dataset()
        
        if df.empty:
            raise ValueError("No training data available")
        
        print(f"Loaded {len(df)} training samples")
        print()
        
        # Store unique values
        self.defense_techniques = sorted(df['defense_technique'].unique())
        self.vulnerability_types = sorted(df['vulnerability_type'].unique())
        
        # Encode categorical variables
        print("Encoding features...")
        le_vuln = LabelEncoder()
        df['vulnerability_encoded'] = le_vuln.fit_transform(df['vulnerability_type'])
        self.label_encoders['vulnerability_type'] = le_vuln
        
        le_severity = LabelEncoder()
        df['severity_encoded'] = le_severity.fit_transform(df['severity'])
        self.label_encoders['severity'] = le_severity
        
        le_defense = LabelEncoder()
        df['defense_encoded'] = le_defense.fit_transform(df['defense_technique'])
        self.label_encoders['defense_technique'] = le_defense
        
        # Prepare features and target
        # Features: vulnerability type, severity, CVSS, exploit available, defense technique
        # Target: effectiveness
        feature_cols = ['vulnerability_encoded', 'severity_encoded', 'cvss_score', 
                       'has_exploit', 'defense_encoded']
        X = df[feature_cols].values
        y = df['effectiveness'].values
        
        # CRITICAL: Proper train/test split to avoid overfitting
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, shuffle=True
        )
        
        print(f"Training set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        print()
        
        # Train Random Forest with regularization to prevent overfitting
        print("Training Random Forest Regressor...")
        self.model = RandomForestRegressor(
            n_estimators=100,          # Number of trees
            max_depth=10,              # Limit depth to prevent overfitting
            min_samples_split=10,      # Require more samples to split
            min_samples_leaf=5,        # Require more samples in leaf nodes
            max_features='sqrt',       # Use subset of features
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate on BOTH training and test sets
        print("\n" + "="*80)
        print("MODEL EVALUATION")
        print("="*80 + "\n")
        
        # Training metrics
        y_train_pred = self.model.predict(X_train)
        train_r2 = r2_score(y_train, y_train_pred)
        train_mae = mean_absolute_error(y_train, y_train_pred)
        train_rmse = np.sqrt(mean_squared_error(y_train, y_train_pred))
        
        # Test metrics (MOST IMPORTANT)
        y_test_pred = self.model.predict(X_test)
        test_r2 = r2_score(y_test, y_test_pred)
        test_mae = mean_absolute_error(y_test, y_test_pred)
        test_rmse = np.sqrt(mean_squared_error(y_test, y_test_pred))
        
        print("Training Set Performance:")
        print(f"  R² Score:  {train_r2*100:.2f}%")
        print(f"  MAE:       {train_mae:.2f}")
        print(f"  RMSE:      {train_rmse:.2f}")
        print()
        
        print("Test Set Performance (Generalization):")
        print(f"  R² Score:  {test_r2*100:.2f}%")
        print(f"  MAE:       {test_mae:.2f}")
        print(f"  RMSE:      {test_rmse:.2f}")
        print()
        
        # Check for overfitting
        overfitting_gap = (train_r2 - test_r2) * 100
        if overfitting_gap > 15:
            print(f"⚠️  WARNING: Potential overfitting detected!")
            print(f"   Gap between train and test: {overfitting_gap:.2f}%")
        elif test_r2 > 0.7:
            print(f"✓ Model shows good generalization")
            print(f"   Train-Test gap: {overfitting_gap:.2f}%")
        print()
        
        # Feature importance
        feature_names = ['Vulnerability Type', 'Severity', 'CVSS Score', 'Has Exploit', 'Defense Technique']
        feature_importance = pd.DataFrame({
            'Feature': feature_names,
            'Importance': self.model.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        print("Feature Importance:")
        print("-"*80)
        for _, row in feature_importance.iterrows():
            bar_length = int(row['Importance'] * 50)
            bar = '█' * bar_length
            print(f"  {row['Feature']:25s} {bar} {row['Importance']*100:.1f}%")
        print()
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'label_encoders': self.label_encoders,
            'defense_techniques': self.defense_techniques,
            'vulnerability_types': self.vulnerability_types,
            'feature_importance': feature_importance,
            'training_date': pd.Timestamp.now().isoformat(),
            'train_r2': train_r2,
            'test_r2': test_r2,
            'train_mae': train_mae,
            'test_mae': test_mae,
            'n_samples': len(df),
            'model_type': 'Random Forest Regressor'
        }, self.model_path)
        
        print("="*80)
        print(f"✅ Model saved to: {self.model_path}")
        print("="*80)
        
        return {
            'train_accuracy': train_r2,
            'test_accuracy': test_r2,
            'n_samples': len(df)
        }
    
    def load_model(self):
        """Load trained model"""
        if os.path.exists(self.model_path):
            data = joblib.load(self.model_path)
            self.model = data['model']
            self.label_encoders = data['label_encoders']
            self.defense_techniques = data['defense_techniques']
            self.vulnerability_types = data['vulnerability_types']
            return True
        return False
    
    def predict_defense(self, vulnerability):
        """Predict best defense techniques for a vulnerability"""
        
        if not self.model:
            if not self.load_model():
                raise ValueError("Model not trained. Run train_model() first.")
        
        vuln_type = vulnerability.get('type', vulnerability.get('vulnerability_type', 'Other'))
        severity = vulnerability.get('severity', 'medium')
        cvss_score = vulnerability.get('cvss_score', 5.0)
        has_exploit = vulnerability.get('has_exploit', False)
        
        # Encode vulnerability type
        try:
            vuln_encoded = self.label_encoders['vulnerability_type'].transform([vuln_type])[0]
        except ValueError:
            vuln_encoded = 0
        
        # Encode severity
        try:
            severity_encoded = self.label_encoders['severity'].transform([severity])[0]
        except ValueError:
            severity_encoded = self.label_encoders['severity'].transform(['medium'])[0]
        
        # Predict effectiveness for each defense technique
        recommendations = []
        
        for defense in self.defense_techniques:
            try:
                defense_encoded = self.label_encoders['defense_technique'].transform([defense])[0]
                
                # Prepare features
                features = np.array([[
                    vuln_encoded,
                    severity_encoded,
                    cvss_score,
                    1 if has_exploit else 0,
                    defense_encoded
                ]])
                
                # Predict effectiveness
                effectiveness = self.model.predict(features)[0]
                effectiveness = max(60, min(100, effectiveness))  # Clamp to realistic range
                
                confidence = effectiveness / 100.0
                
                recommendations.append({
                    'defense_technique': defense,
                    'confidence_score': confidence,
                    'priority_score': effectiveness,
                    'effectiveness': effectiveness,
                    'model_type': 'Random Forest ML Model'
                })
            except Exception:
                continue
        
        # Sort by effectiveness and return top 5
        recommendations.sort(key=lambda x: x['effectiveness'], reverse=True)
        
        return recommendations[:5]


def main():
    """Main training function"""
    recommender = RealDefenseRecommender()
    
    try:
        results = recommender.train_model()
        print(f"\n✅ Training completed successfully!")
        print(f"   - Train R² Score: {results['train_accuracy']*100:.2f}%")
        print(f"   - Test R² Score: {results['test_accuracy']*100:.2f}%")
        print(f"   - Training Samples: {results['n_samples']}")
        
    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
