import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import pickle
import os
import logging

logger = logging.getLogger(__name__)


class BruteForceDetector:
    """
    AI-powered detection of brute force and credential stuffing attacks.
    Uses behavioral analysis and anomaly detection.
    """
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or "./models/bruteforce_model.pkl"
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Sliding window for tracking login attempts
        self.login_history = defaultdict(lambda: deque(maxlen=100))
        self.ip_history = defaultdict(lambda: deque(maxlen=1000))
        
        # Thresholds
        self.max_attempts_per_user = 5
        self.max_attempts_per_ip = 20
        self.time_window_seconds = 300  # 5 minutes
        
    def extract_features(self, login_attempts: List[Dict]) -> np.ndarray:
        """
        Extract features from login attempt history.
        
        Args:
            login_attempts: List of login attempt records
            
        Returns:
            Feature vector
        """
        if not login_attempts:
            return np.zeros(15)
        
        features = []
        
        # Temporal features
        timestamps = [attempt.get('timestamp', datetime.utcnow()) for attempt in login_attempts]
        if len(timestamps) > 1:
            time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                         for i in range(len(timestamps)-1)]
            features.append(np.mean(time_diffs) if time_diffs else 0)
            features.append(np.std(time_diffs) if len(time_diffs) > 1 else 0)
            features.append(min(time_diffs) if time_diffs else 0)
        else:
            features.extend([0, 0, 0])
        
        # Success/failure patterns
        successes = [1 if attempt.get('success', False) else 0 for attempt in login_attempts]
        features.append(sum(successes) / len(successes))  # Success rate
        features.append(len([s for s in successes if s == 0]))  # Failure count
        features.append(self._count_consecutive_failures(successes))  # Consecutive failures
        
        # Username diversity
        usernames = [attempt.get('username', '') for attempt in login_attempts]
        unique_usernames = len(set(usernames))
        features.append(unique_usernames)  # Unique usernames tried
        features.append(unique_usernames / len(login_attempts))  # Username diversity ratio
        
        # IP diversity
        ips = [attempt.get('ip_address', '') for attempt in login_attempts]
        unique_ips = len(set(ips))
        features.append(unique_ips)
        features.append(unique_ips / len(login_attempts))
        
        # User agent diversity
        user_agents = [attempt.get('user_agent', '') for attempt in login_attempts]
        unique_uas = len(set(user_agents))
        features.append(unique_uas)
        
        # Time-based features
        hours = [t.hour if isinstance(t, datetime) else datetime.utcnow().hour for t in timestamps]
        features.append(np.std(hours) if len(hours) > 1 else 0)
        
        # Geographic indicators (if available)
        countries = [attempt.get('country', 'unknown') for attempt in login_attempts]
        unique_countries = len(set(countries))
        features.append(unique_countries)
        
        # Padding to ensure fixed size
        while len(features) < 15:
            features.append(0)
        
        return np.array(features[:15])
    
    def _count_consecutive_failures(self, successes: List[int]) -> int:
        """Count maximum consecutive failures."""
        max_consecutive = 0
        current_consecutive = 0
        
        for success in successes:
            if success == 0:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0
        
        return max_consecutive
    
    def train(self, X: np.ndarray, y: np.ndarray):
        """
        Train the detection models.
        
        Args:
            X: Feature matrix
            y: Labels (0=normal, 1=attack)
        """
        X_scaled = self.scaler.fit_transform(X)
        
        # Train anomaly detector
        self.anomaly_detector.fit(X_scaled)
        
        # Train classifier
        self.classifier.fit(X_scaled, y)
        
        self.is_trained = True
        logger.info(f"Brute force detection model trained with {len(X)} samples")
    
    def detect(self, login_attempt: Dict) -> Dict:
        """
        Analyze a login attempt for brute force patterns.
        
        Args:
            login_attempt: Login attempt data
            
        Returns:
            Detection result
        """
        username = login_attempt.get('username', 'unknown')
        ip_address = login_attempt.get('ip_address', 'unknown')
        timestamp = login_attempt.get('timestamp', datetime.utcnow())
        
        # Update history
        self.login_history[username].append(login_attempt)
        self.ip_history[ip_address].append(login_attempt)
        
        # Get recent attempts for this user and IP
        user_attempts = list(self.login_history[username])
        ip_attempts = list(self.ip_history[ip_address])
        
        # Feature extraction
        user_features = self.extract_features(user_attempts)
        ip_features = self.extract_features(ip_attempts)
        
        # Combine features
        combined_features = np.hstack([user_features, ip_features])
        
        # Check simple thresholds first
        threshold_result = self._check_thresholds(user_attempts, ip_attempts)
        if threshold_result['is_attack'] and threshold_result['confidence'] > 0.9:
            return threshold_result
        
        # ML-based detection
        if self.is_trained:
            try:
                X_scaled = self.scaler.transform(combined_features.reshape(1, -1))
                
                # Anomaly detection
                anomaly_score = self.anomaly_detector.score_samples(X_scaled)[0]
                is_anomaly = anomaly_score < -0.5
                
                # Classification
                prediction = self.classifier.predict(X_scaled)[0]
                probabilities = self.classifier.predict_proba(X_scaled)[0]
                ml_confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
                
                # Combine results
                is_attack = prediction == 1 or is_anomaly or threshold_result['is_attack']
                confidence = max(ml_confidence, threshold_result['confidence'], 
                               0.8 if is_anomaly else 0.0)
                
            except Exception as e:
                logger.error(f"Error in ML detection: {e}")
                return threshold_result
        else:
            self._load_or_initialize()
            return self.detect(login_attempt)
        
        # Determine risk level
        if confidence > 0.9:
            risk_level = "critical"
        elif confidence > 0.75:
            risk_level = "high"
        elif confidence > 0.5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Classify attack type
        attack_type = self._classify_attack_type(user_attempts, ip_attempts)
        
        return {
            "is_attack": bool(is_attack),
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "attack_type": attack_type,
            "details": {
                "attempts_last_5min": len(user_attempts),
                "unique_ips": len(set(a.get('ip_address', '') for a in user_attempts)),
                "failure_rate": round(1 - user_features[3], 4) if len(user_features) > 3 else 0,
                "is_anomaly": bool(anomaly_score < -0.5) if self.is_trained else False
            },
            "recommendations": self._get_recommendations(is_attack, attack_type)
        }
    
    def _check_thresholds(self, user_attempts: List[Dict], ip_attempts: List[Dict]) -> Dict:
        """Check simple threshold-based rules."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.time_window_seconds)
        
        # Filter recent attempts
        recent_user = [a for a in user_attempts if a.get('timestamp', now) >= window_start]
        recent_ip = [a for a in ip_attempts if a.get('timestamp', now) >= window_start]
        
        failures_user = sum(1 for a in recent_user if not a.get('success', True))
        failures_ip = sum(1 for a in recent_ip if not a.get('success', True))
        
        is_attack = False
        confidence = 0.0
        reasons = []
        
        # Check user-based threshold
        if failures_user >= self.max_attempts_per_user:
            is_attack = True
            confidence = min(0.5 + (failures_user - self.max_attempts_per_user) * 0.1, 0.95)
            reasons.append(f"User lockout threshold exceeded ({failures_user} failures)")
        
        # Check IP-based threshold
        if failures_ip >= self.max_attempts_per_ip:
            is_attack = True
            confidence = max(confidence, min(0.6 + (failures_ip - self.max_attempts_per_ip) * 0.05, 0.95))
            reasons.append(f"IP threshold exceeded ({failures_ip} failures)")
        
        # Check for credential stuffing (many usernames from same IP)
        unique_usernames_from_ip = len(set(a.get('username', '') for a in recent_ip))
        if unique_usernames_from_ip > 10:
            is_attack = True
            confidence = max(confidence, 0.85)
            reasons.append(f"Credential stuffing detected ({unique_usernames_from_ip} usernames)")
        
        return {
            "is_attack": is_attack,
            "confidence": round(confidence, 4),
            "risk_level": "critical" if confidence > 0.8 else "high" if confidence > 0.6 else "medium" if is_attack else "low",
            "reasons": reasons,
            "attack_type": self._classify_attack_type(user_attempts, ip_attempts) if is_attack else None
        }
    
    def _classify_attack_type(self, user_attempts: List[Dict], ip_attempts: List[Dict]) -> str:
        """Classify the type of attack."""
        unique_usernames = len(set(a.get('username', '') for a in ip_attempts))
        unique_ips = len(set(a.get('ip_address', '') for a in user_attempts))
        
        if unique_usernames > 10:
            return "Credential Stuffing"
        elif unique_ips > 5:
            return "Distributed Brute Force"
        elif len([a for a in user_attempts if not a.get('success', True)]) > 10:
            return "Brute Force Attack"
        else:
            return "Password Guessing"
    
    def _get_recommendations(self, is_attack: bool, attack_type: str) -> List[str]:
        """Get security recommendations based on detection."""
        recommendations = []
        
        if is_attack:
            recommendations.append("Implement rate limiting on login endpoints")
            recommendations.append("Enable account lockout after failed attempts")
            
            if attack_type == "Credential Stuffing":
                recommendations.append("Implement CAPTCHA after multiple failures")
                recommendations.append("Check credentials against known breach databases")
            elif attack_type == "Distributed Brute Force":
                recommendations.append("Consider IP-based blocking or geo-fencing")
                recommendations.append("Implement behavioral biometrics")
            else:
                recommendations.append("Enforce strong password policies")
                recommendations.append("Enable multi-factor authentication")
        
        return recommendations
    
    def _load_or_initialize(self):
        """Load model or initialize with defaults."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.anomaly_detector = data['anomaly_detector']
                    self.classifier = data['classifier']
                    self.scaler = data['scaler']
                    self.is_trained = True
                logger.info(f"Loaded brute force model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self._initialize_default_model()
        else:
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize default model with synthetic data."""
        np.random.seed(42)
        
        # Normal login patterns
        normal_X = np.random.randn(200, 30) * 0.5
        normal_X[:, 3] = np.random.uniform(0.7, 1.0, 200)  # High success rate
        normal_X[:, 4] = np.random.uniform(0, 2, 200)  # Low failure count
        
        # Attack patterns
        attack_X = np.random.randn(200, 30) * 0.5
        attack_X[:, 3] = np.random.uniform(0.0, 0.3, 200)  # Low success rate
        attack_X[:, 4] = np.random.uniform(10, 50, 200)  # High failure count
        attack_X[:, 5] = np.random.uniform(10, 30, 200)  # Many consecutive failures
        
        X = np.vstack([normal_X, attack_X])
        y = np.array([0] * 200 + [1] * 200)
        
        self.train(X, y)
        logger.info("Initialized default brute force detection model")
    
    def save_model(self):
        """Save trained model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'anomaly_detector': self.anomaly_detector,
                'classifier': self.classifier,
                'scaler': self.scaler
            }, f)
        logger.info(f"Saved brute force model to {self.model_path}")


# Global instance
bruteforce_detector = BruteForceDetector()
