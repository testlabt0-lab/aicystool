"""
Brute Force and Credential Stuffing Detection System
Monitors login attempts and uses AI to detect abnormal patterns
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from collections import defaultdict
import joblib
import os


class LoginAttemptAnalyzer:
    """Analyze login attempts for suspicious patterns"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            class_weight='balanced',
            random_state=42
        )
        self.ip_history = defaultdict(list)
        self.user_history = defaultdict(list)
        self.is_trained = False
    
    def extract_features(self, login_attempts):
        """
        Extract features from login attempts
        
        Args:
            login_attempts: List of login attempt dictionaries
            
        Returns:
            Feature matrix
        """
        features = []
        
        for attempt in login_attempts:
            feature_vector = {
                'time_since_last_attempt': attempt.get('time_since_last_attempt', 0),
                'attempts_last_minute': attempt.get('attempts_last_minute', 0),
                'attempts_last_hour': attempt.get('attempts_last_hour', 0),
                'unique_ips_for_user': attempt.get('unique_ips_for_user', 1),
                'failed_attempts_ratio': attempt.get('failed_attempts_ratio', 0),
                'password_variations': attempt.get('password_variations', 0),
                'geographic_distance': attempt.get('geographic_distance', 0),
                'unusual_time': attempt.get('unusual_time', 0),
                'user_agent_change': attempt.get('user_agent_change', 0),
                'keyboard_pattern': attempt.get('keyboard_pattern', 0),
                'common_password_used': attempt.get('common_password_used', 0),
                'username_exists': attempt.get('username_exists', 1),
                'ip_reputation_score': attempt.get('ip_reputation_score', 50),
                'request_rate': attempt.get('request_rate', 0),
            }
            features.append(list(feature_vector.values()))
        
        return np.array(features)
    
    def analyze_ip_pattern(self, ip_address, timestamp, username):
        """
        Analyze pattern for a specific IP address
        
        Args:
            ip_address: Source IP address
            timestamp: Attempt timestamp
            username: Target username
            
        Returns:
            Dictionary with IP-based features
        """
        current_time = timestamp if isinstance(timestamp, datetime) else datetime.now()
        
        # Get recent attempts from this IP
        recent_attempts = [
            t for t in self.ip_history[ip_address]
            if (current_time - t).total_seconds() < 3600  # Last hour
        ]
        
        self.ip_history[ip_address].append(current_time)
        
        # Clean old entries
        self.ip_history[ip_address] = [
            t for t in self.ip_history[ip_address]
            if (current_time - t).total_seconds() < 86400  # Keep 24h
        ]
        
        return {
            'attempts_from_ip_last_hour': len(recent_attempts),
            'rapid_fire_detected': len(recent_attempts) > 10,
        }
    
    def analyze_user_pattern(self, username, timestamp, ip_address):
        """
        Analyze pattern for a specific user account
        
        Args:
            username: Username being accessed
            timestamp: Attempt timestamp
            ip_address: Source IP address
            
        Returns:
            Dictionary with user-based features
        """
        current_time = timestamp if isinstance(timestamp, datetime) else datetime.now()
        
        # Get recent attempts for this user
        recent_attempts = [
            (t, ip) for t, ip in self.user_history[username]
            if (current_time - t).total_seconds() < 3600
        ]
        
        self.user_history[username].append((current_time, ip_address))
        
        # Clean old entries
        self.user_history[username] = [
            (t, ip) for t, ip in self.user_history[username]
            if (current_time - t).total_seconds() < 86400
        ]
        
        # Count unique IPs trying this user
        unique_ips = set(ip for _, ip in recent_attempts)
        
        return {
            'attempts_on_user_last_hour': len(recent_attempts),
            'unique_ips_for_user': len(unique_ips),
            'credential_stuffing_indicator': len(unique_ips) > 5,
        }
    
    def create_training_sample(self, is_attack=False, attack_type='brute_force'):
        """
        Create a synthetic training sample
        
        Args:
            is_attack: Whether this is an attack sample
            attack_type: Type of attack ('brute_force' or 'credential_stuffing')
            
        Returns:
            Feature dictionary
        """
        if is_attack:
            if attack_type == 'brute_force':
                return {
                    'time_since_last_attempt': np.random.uniform(0.1, 2),
                    'attempts_last_minute': np.random.randint(10, 60),
                    'attempts_last_hour': np.random.randint(50, 300),
                    'unique_ips_for_user': 1,
                    'failed_attempts_ratio': np.random.uniform(0.9, 1.0),
                    'password_variations': np.random.randint(10, 50),
                    'geographic_distance': 0,
                    'unusual_time': np.random.choice([0, 1], p=[0.3, 0.7]),
                    'user_agent_change': 0,
                    'keyboard_pattern': np.random.randint(1, 5),
                    'common_password_used': 1,
                    'username_exists': 1,
                    'ip_reputation_score': np.random.uniform(10, 40),
                    'request_rate': np.random.uniform(5, 20),
                }
            else:  # credential_stuffing
                return {
                    'time_since_last_attempt': np.random.uniform(1, 10),
                    'attempts_last_minute': np.random.randint(5, 20),
                    'attempts_last_hour': np.random.randint(20, 100),
                    'unique_ips_for_user': np.random.randint(10, 50),
                    'failed_attempts_ratio': np.random.uniform(0.8, 1.0),
                    'password_variations': 1,
                    'geographic_distance': np.random.uniform(100, 5000),
                    'unusual_time': np.random.choice([0, 1], p=[0.5, 0.5]),
                    'user_agent_change': np.random.choice([0, 1], p=[0.3, 0.7]),
                    'keyboard_pattern': 0,
                    'common_password_used': np.random.choice([0, 1], p=[0.3, 0.7]),
                    'username_exists': np.random.choice([0, 1], p=[0.5, 0.5]),
                    'ip_reputation_score': np.random.uniform(20, 60),
                    'request_rate': np.random.uniform(1, 5),
                }
        else:  # Normal login
            return {
                'time_since_last_attempt': np.random.uniform(60, 10000),
                'attempts_last_minute': np.random.randint(0, 2),
                'attempts_last_hour': np.random.randint(0, 5),
                'unique_ips_for_user': 1,
                'failed_attempts_ratio': np.random.uniform(0, 0.3),
                'password_variations': 0,
                'geographic_distance': np.random.uniform(0, 100),
                'unusual_time': np.random.choice([0, 1], p=[0.9, 0.1]),
                'user_agent_change': 0,
                'keyboard_pattern': 0,
                'common_password_used': 0,
                'username_exists': 1,
                'ip_reputation_score': np.random.uniform(60, 100),
                'request_rate': np.random.uniform(0, 0.5),
            }
    
    def generate_training_data(self, n_samples=1000):
        """Generate synthetic training data"""
        samples = []
        labels = []
        
        # Normal logins
        for _ in range(n_samples // 2):
            samples.append(self.create_training_sample(is_attack=False))
            labels.append(0)
        
        # Brute force attacks
        for _ in range(n_samples // 4):
            samples.append(self.create_training_sample(is_attack=True, attack_type='brute_force'))
            labels.append(1)
        
        # Credential stuffing attacks
        for _ in range(n_samples // 4):
            samples.append(self.create_training_sample(is_attack=True, attack_type='credential_stuffing'))
            labels.append(1)
        
        return samples, labels
    
    def train(self, samples=None, labels=None):
        """
        Train the detection models
        
        Args:
            samples: Training samples (optional, will generate if not provided)
            labels: Training labels (optional)
        """
        if samples is None or labels is None:
            print("Generating synthetic training data...")
            samples, labels = self.generate_training_data(2000)
        
        # Convert to feature matrix
        X = self.extract_features(samples)
        y = np.array(labels)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train anomaly detector (unsupervised)
        self.anomaly_detector.fit(X_scaled)
        
        # Train classifier (supervised)
        self.classifier.fit(X_train, y_train)
        self.is_trained = True
        
        # Evaluate
        y_pred = self.classifier.predict(X_test)
        print("Model Training Results:")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
        
        return self.classifier
    
    def predict(self, login_attempt):
        """
        Predict if a login attempt is malicious
        
        Args:
            login_attempt: Dictionary with login attempt information
            
        Returns:
            Prediction (0=normal, 1=attack), confidence, and analysis
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        # Extract features
        X = self.extract_features([login_attempt])
        X_scaled = self.scaler.transform(X)
        
        # Classifier prediction
        pred_class = self.classifier.predict(X_scaled)[0]
        pred_proba = self.classifier.predict_proba(X_scaled)[0]
        
        # Anomaly detection score
        anomaly_score = self.anomaly_detector.score_samples(X_scaled)[0]
        is_anomaly = anomaly_score < -0.5
        
        # Analysis
        analysis = {
            'anomaly_score': float(anomaly_score),
            'is_anomaly': bool(is_anomaly),
            'confidence_normal': float(pred_proba[0]),
            'confidence_attack': float(pred_proba[1]),
            'risk_level': 'HIGH' if pred_class == 1 else 'LOW'
        }
        
        return pred_class, float(max(pred_proba)), analysis
    
    def save_model(self, filepath='brute_force_model.pkl'):
        """Save trained models"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        
        model_data = {
            'classifier': self.classifier,
            'anomaly_detector': self.anomaly_detector,
            'scaler': self.scaler,
        }
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath='brute_force_model.pkl'):
        """Load pre-trained models"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file {filepath} not found")
        
        model_data = joblib.load(filepath)
        self.classifier = model_data['classifier']
        self.anomaly_detector = model_data['anomaly_detector']
        self.scaler = model_data['scaler']
        self.is_trained = True
        print(f"Model loaded from {filepath}")


class RealTimeMonitor:
    """Real-time monitoring of login attempts"""
    
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.alerts = []
        self.blocked_ips = set()
    
    def process_login_attempt(self, login_data):
        """
        Process a login attempt in real-time
        
        Args:
            login_data: Dictionary with login attempt details
            
        Returns:
            Decision (allow/block) and risk assessment
        """
        # Check if IP is blocked
        if login_data.get('ip_address') in self.blocked_ips:
            return 'BLOCKED', {'reason': 'IP blocked'}
        
        # Analyze patterns
        ip_analysis = self.analyzer.analyze_ip_pattern(
            login_data.get('ip_address', 'unknown'),
            login_data.get('timestamp', datetime.now()),
            login_data.get('username', '')
        )
        
        user_analysis = self.analyzer.analyze_user_pattern(
            login_data.get('username', ''),
            login_data.get('timestamp', datetime.now()),
            login_data.get('ip_address', '')
        )
        
        # Combine features
        login_features = {**login_data, **ip_analysis, **user_analysis}
        
        # Make prediction
        try:
            prediction, confidence, analysis = self.analyzer.predict(login_features)
        except:
            prediction, confidence, analysis = 0, 0.5, {}
        
        # Generate alert if attack detected
        if prediction == 1:
            alert = {
                'timestamp': datetime.now(),
                'type': 'BRUTE_FORCE' if analysis.get('is_anomaly') else 'CREDENTIAL_STUFFING',
                'ip_address': login_data.get('ip_address'),
                'username': login_data.get('username'),
                'confidence': confidence,
                'risk_level': analysis.get('risk_level', 'UNKNOWN')
            }
            self.alerts.append(alert)
            
            # Block IP if high confidence
            if confidence > 0.9:
                self.blocked_ips.add(login_data.get('ip_address'))
                decision = 'BLOCKED'
            else:
                decision = 'FLAGGED'
        else:
            decision = 'ALLOWED'
        
        return decision, {
            'prediction': prediction,
            'confidence': confidence,
            'analysis': analysis,
            'alerts_count': len(self.alerts),
            'blocked_ips_count': len(self.blocked_ips)
        }


if __name__ == "__main__":
    print("=" * 60)
    print("Brute Force / Credential Stuffing Detection System")
    print("=" * 60)
    
    # Initialize analyzer
    analyzer = LoginAttemptAnalyzer()
    
    # Train model
    print("\nTraining detection model...")
    analyzer.train()
    
    # Save model
    analyzer.save_model('brute_force_model.pkl')
    
    # Initialize real-time monitor
    monitor = RealTimeMonitor(analyzer)
    
    # Test with sample login attempts
    print("\n" + "=" * 60)
    print("Testing with sample login attempts:")
    print("=" * 60)
    
    test_attempts = [
        {
            'ip_address': '192.168.1.100',
            'username': 'admin',
            'timestamp': datetime.now(),
            'time_since_last_attempt': 300,
            'attempts_last_minute': 1,
            'attempts_last_hour': 3,
            'failed_attempts_ratio': 0.1,
        },
        {
            'ip_address': '10.0.0.50',
            'username': 'admin',
            'timestamp': datetime.now(),
            'time_since_last_attempt': 0.5,
            'attempts_last_minute': 45,
            'attempts_last_hour': 200,
            'failed_attempts_ratio': 0.98,
            'password_variations': 35,
        },
        {
            'ip_address': '203.0.113.42',
            'username': 'john.doe',
            'timestamp': datetime.now(),
            'time_since_last_attempt': 2,
            'attempts_last_minute': 15,
            'attempts_last_hour': 80,
            'unique_ips_for_user': 25,
            'failed_attempts_ratio': 0.95,
            'geographic_distance': 2500,
        }
    ]
    
    for i, attempt in enumerate(test_attempts, 1):
        decision, info = monitor.process_login_attempt(attempt)
        print(f"\nAttempt {i}:")
        print(f"  IP: {attempt['ip_address']}")
        print(f"  Username: {attempt['username']}")
        print(f"  Decision: {decision}")
        print(f"  Confidence: {info.get('confidence', 0):.2%}")
        print(f"  Risk Level: {info.get('analysis', {}).get('risk_level', 'N/A')}")
    
    print(f"\nTotal Alerts Generated: {len(monitor.alerts)}")
    print(f"Blocked IPs: {len(monitor.blocked_ips)}")
    
    print("\n" + "=" * 60)
    print("System ready for deployment!")
    print("=" * 60)
