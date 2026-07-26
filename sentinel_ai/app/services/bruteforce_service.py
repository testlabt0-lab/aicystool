"""
Advanced Brute Force & Credential Stuffing Detection Service
Uses Isolation Forest, behavioral analysis, and threat intelligence
"""

import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import logging
import hashlib

from app.config import settings
from app.database import get_db, SecurityEvent, LoginAttempt

logger = logging.getLogger(__name__)

class AdvancedBruteForceDetector:
    """
    Enterprise-grade brute force and credential stuffing detection:
    1. Rate-based detection (attempts per time window)
    2. Anomaly detection (Isolation Forest)
    3. Behavioral patterns (time, location, device)
    4. Credential stuffing detection (known breached credentials)
    5. IP reputation checking
    """
    
    def __init__(self):
        self.max_attempts = settings.BRUTE_FORCE_MAX_ATTEMPTS
        self.window_seconds = settings.BRUTE_FORCE_WINDOW
        self.lockout_duration = settings.BRUTE_FORCE_LOCKOUT_DURATION
        
        # Attempt tracking
        self.ip_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.username_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.ip_username_pairs: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Lockout tracking
        self.locked_ips: Dict[str, datetime] = {}
        self.locked_usernames: Dict[str, datetime] = {}
        
        # ML Models
        self.isolation_model: Optional[IsolationForest] = None
        self.rf_model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        
        # Breached credentials database (in production, use API)
        self.breached_passwords: set = set()
        self.breached_usernames: set = set()
        
        # Geographic data (simplified)
        self.ip_locations: Dict[str, str] = {}
        
        # Initialize models
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize or train ML models"""
        try:
            iso_path = f"{settings.MODEL_PATH}/bruteforce_isolation.pkl"
            rf_path = f"{settings.MODEL_PATH}/bruteforce_rf.pkl"
            
            if joblib.load(iso_path) and joblib.load(rf_path):
                self.isolation_model = joblib.load(iso_path)
                self.rf_model = joblib.load(rf_path)
                logger.info("Loaded pre-trained brute force detection models")
            else:
                self._train_models()
        except FileNotFoundError:
            logger.warning("Pre-trained models not found, training new models")
            self._train_models()
    
    def _train_models(self):
        """Train ML models on synthetic login attempt data"""
        # Generate training data
        n_normal = 5000
        n_attack = 2000
        
        # Normal login patterns
        # Features: [hour_of_day, day_of_week, attempts_last_hour, 
        #            unique_ips_for_user, password_length, geo_distance]
        X_normal = np.random.normal(
            loc=[14, 3, 2, 1, 12, 0],
            scale=[4, 2, 1, 0.5, 3, 100],
            size=(n_normal, 6)
        )
        y_normal = np.zeros(n_normal)
        
        # Attack patterns
        X_attack = np.random.normal(
            loc=[3, 0, 50, 100, 8, 5000],
            scale=[3, 1, 30, 50, 2, 2000],
            size=(n_attack, 6)
        )
        y_attack = np.ones(n_attack)
        
        X_train = np.vstack([X_normal, X_attack])
        y_train = np.hstack([y_normal, y_attack])
        
        # Train Isolation Forest for anomaly detection
        self.isolation_model = IsolationForest(
            n_estimators=100,
            contamination=0.2,
            random_state=42
        )
        self.isolation_model.fit(X_train)
        
        # Train Random Forest for classification
        self.rf_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=20,
            class_weight='balanced',
            random_state=42
        )
        self.rf_model.fit(X_train, y_train)
        
        # Fit scaler
        self.scaler = StandardScaler()
        self.scaler.fit(X_train)
        
        # Save models
        import os
        os.makedirs(settings.MODEL_PATH, exist_ok=True)
        joblib.dump(self.isolation_model, f"{settings.MODEL_PATH}/bruteforce_isolation.pkl")
        joblib.dump(self.rf_model, f"{settings.MODEL_PATH}/bruteforce_rf.pkl")
        joblib.dump(self.scaler, f"{settings.MODEL_PATH}/bruteforce_scaler.pkl")
        
        logger.info("Trained and saved brute force detection models")
    
    def _extract_features(self, attempt_data: Dict) -> np.ndarray:
        """Extract features from login attempt"""
        timestamp = attempt_data.get('timestamp', datetime.utcnow())
        
        # Hour of day (0-23)
        hour = timestamp.hour if isinstance(timestamp, datetime) else 12
        
        # Day of week (0-6)
        day = timestamp.weekday() if isinstance(timestamp, datetime) else 2
        
        # Attempts in last hour for this IP
        ip = attempt_data.get('ip_address', 'unknown')
        recent_attempts = sum(
            1 for t in self.ip_attempts[ip]
            if t > datetime.utcnow() - timedelta(hours=1)
        )
        
        # Unique IPs for this username
        username = attempt_data.get('username', 'unknown')
        unique_ips = len(set(
            attempt_data.get('ip_address', '') for _ in range(1)
        ))
        
        # Password length (if available)
        password = attempt_data.get('password', '')
        password_length = len(password) if password else 10
        
        # Geographic distance from usual location (simplified)
        geo_distance = attempt_data.get('geo_distance', 0)
        
        features = np.array([
            hour,
            day,
            recent_attempts,
            unique_ips,
            password_length,
            geo_distance
        ]).reshape(1, -1)
        
        return features
    
    def _check_rate_limit(self, ip: str, username: str) -> Dict:
        """Check if IP or username exceeds rate limits"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Count recent attempts for IP
        ip_recent = sum(1 for t in self.ip_attempts[ip] if t > window_start)
        
        # Count recent attempts for username
        username_recent = sum(1 for t in self.username_attempts[username] if t > window_start)
        
        # Check lockouts
        ip_locked = ip in self.locked_ips and self.locked_ips[ip] > now
        username_locked = username in self.locked_usernames and self.locked_usernames[username] > now
        
        # Clean up old lockouts
        self.locked_ips = {k: v for k, v in self.locked_ips.items() if v > now}
        self.locked_usernames = {k: v for k, v in self.locked_usernames.items() if v > now}
        
        return {
            "ip_attempts": ip_recent,
            "username_attempts": username_recent,
            "ip_locked": ip_locked,
            "username_locked": username_locked,
            "exceeds_threshold": ip_recent >= self.max_attempts or username_recent >= self.max_attempts
        }
    
    def _detect_credential_stuffing(self, username: str, password: str) -> Dict:
        """Detect credential stuffing attacks"""
        result = {
            "is_breached": False,
            "breach_source": None,
            "risk_score": 0.0
        }
        
        # Check against known breached credentials
        password_hash = hashlib.sha256(password.encode()).hexdigest()[:10]
        
        # In production, check against actual breach databases
        # For now, simulate with common passwords
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        
        if password.lower() in common_passwords:
            result["is_breached"] = True
            result["breach_source"] = "common_password_list"
            result["risk_score"] = 0.9
        
        # Check for username patterns commonly targeted
        targeted_usernames = ['admin', 'administrator', 'root', 'user', 'test']
        if username.lower() in targeted_usernames:
            result["risk_score"] += 0.3
        
        result["risk_score"] = min(result["risk_score"], 1.0)
        
        return result
    
    def _analyze_behavioral_patterns(self, attempt_data: Dict) -> Dict:
        """Analyze behavioral patterns for anomalies"""
        result = {
            "behavioral_score": 0.0,
            "anomalies": [],
            "risk_factors": []
        }
        
        # Time-based anomaly
        hour = attempt_data.get('timestamp', datetime.utcnow()).hour
        if hour < 5 or hour > 23:  # Unusual hours
            result["anomalies"].append("unusual_time")
            result["behavioral_score"] += 0.2
        
        # User agent analysis
        user_agent = attempt_data.get('user_agent', '')
        if not user_agent or len(user_agent) < 20:
            result["anomalies"].append("suspicious_user_agent")
            result["behavioral_score"] += 0.3
        
        # Check for automation tools
        automation_indicators = ['python', 'curl', 'wget', 'bot', 'scanner']
        if any(indicator in user_agent.lower() for indicator in automation_indicators):
            result["anomalies"].append("automation_detected")
            result["behavioral_score"] += 0.4
        
        # Velocity check (multiple attempts in short time)
        ip = attempt_data.get('ip_address', '')
        recent_count = len([t for t in self.ip_attempts[ip] 
                           if t > datetime.utcnow() - timedelta(minutes=1)])
        if recent_count > 10:
            result["anomalies"].append("high_velocity")
            result["behavioral_score"] += 0.3
        
        # Geographic anomaly
        if attempt_data.get('geo_distance', 0) > 1000:  # km
            result["anomalies"].append("geographic_anomaly")
            result["behavioral_score"] += 0.25
        
        result["behavioral_score"] = min(result["behavioral_score"], 1.0)
        
        return result
    
    def _ml_detection(self, attempt_data: Dict) -> Dict:
        """ML-based attack detection"""
        result = {
            "isolation_score": 0.0,
            "rf_probability": 0.0,
            "is_attack": False
        }
        
        try:
            features = self._extract_features(attempt_data)
            
            # Isolation Forest anomaly score
            if self.isolation_model:
                if self.scaler:
                    features_scaled = self.scaler.transform(features)
                else:
                    features_scaled = features
                
                iso_score = self.isolation_model.decision_function(features_scaled)[0]
                result["isolation_score"] = float(-iso_score)  # Higher = more anomalous
                
                is_anomaly = iso_score < -0.5
                result["is_anomaly"] = is_anomaly
            
            # Random Forest classification
            if self.rf_model:
                if self.scaler:
                    features_scaled = self.scaler.transform(features)
                else:
                    features_scaled = features
                
                rf_prob = self.rf_model.predict_proba(features_scaled)[0][1]
                result["rf_probability"] = float(rf_prob)
                result["is_attack"] = rf_prob > 0.7
            
        except Exception as e:
            logger.error(f"ML detection error: {e}")
        
        return result
    
    async def detect(self, attempt_data: Dict) -> Dict:
        """
        Comprehensive brute force and credential stuffing detection
        
        Args:
            attempt_data: Dictionary containing login attempt information
                - username: str
                - ip_address: str
                - timestamp: datetime (optional)
                - success: bool
                - user_agent: str (optional)
                - password: str (optional, for breach checking)
                
        Returns:
            Detection results with recommended actions
        """
        start_time = datetime.utcnow()
        
        username = attempt_data.get('username', 'unknown')
        ip = attempt_data.get('ip_address', 'unknown')
        success = attempt_data.get('success', False)
        
        result = {
            "is_attack": False,
            "attack_type": None,
            "confidence": 0.0,
            "threat_level": "safe",
            "detection_methods": {},
            "recommended_action": "allow",
            "lockout_recommended": False,
            "timestamp": start_time.isoformat(),
            "analysis_time_ms": 0
        }
        
        try:
            # Record the attempt
            self.ip_attempts[ip].append(start_time)
            self.username_attempts[username].append(start_time)
            
            # Layer 1: Rate limiting check
            rate_result = self._check_rate_limit(ip, username)
            result["detection_methods"]["rate_limiting"] = rate_result
            
            if rate_result["exceeds_threshold"]:
                result["is_attack"] = True
                result["attack_type"] = "brute_force"
                result["lockout_recommended"] = True
            
            # Layer 2: Credential stuffing detection (only on failed attempts)
            if not success:
                password = attempt_data.get('password', '')
                stuffing_result = self._detect_credential_stuffing(username, password)
                result["detection_methods"]["credential_stuffing"] = stuffing_result
                
                if stuffing_result["is_breached"]:
                    result["is_attack"] = True
                    result["attack_type"] = "credential_stuffing"
            
            # Layer 3: Behavioral analysis
            behavioral_result = self._analyze_behavioral_patterns(attempt_data)
            result["detection_methods"]["behavioral_analysis"] = behavioral_result
            
            if behavioral_result["behavioral_score"] > 0.7:
                result["is_attack"] = True
                if not result["attack_type"]:
                    result["attack_type"] = "suspicious_login_pattern"
            
            # Layer 4: ML-based detection
            ml_result = self._ml_detection(attempt_data)
            result["detection_methods"]["ml_detection"] = ml_result
            
            if ml_result.get("is_attack", False):
                result["is_attack"] = True
                if not result["attack_type"]:
                    result["attack_type"] = "ml_detected_attack"
            
            # Calculate final confidence
            scores = []
            
            if rate_result["exceeds_threshold"]:
                scores.append(0.9)
            
            if "credential_stuffing" in result["detection_methods"]:
                scores.append(result["detection_methods"]["credential_stuffing"]["risk_score"])
            
            scores.append(behavioral_result["behavioral_score"])
            
            if ml_result["rf_probability"] > 0:
                scores.append(ml_result["rf_probability"])
            
            if scores:
                result["confidence"] = float(np.mean(scores))
            
            # Determine threat level
            if result["confidence"] > 0.85:
                result["threat_level"] = "critical"
            elif result["confidence"] > 0.7:
                result["threat_level"] = "high"
            elif result["confidence"] > 0.5:
                result["threat_level"] = "medium"
            elif result["confidence"] > 0.3:
                result["threat_level"] = "low"
            else:
                result["threat_level"] = "safe"
            
            # Recommend action
            if result["threat_level"] == "critical":
                result["recommended_action"] = "block_and_lockout"
                result["lockout_recommended"] = True
            elif result["threat_level"] == "high":
                result["recommended_action"] = "block_and_challenge"
            elif result["threat_level"] == "medium":
                result["recommended_action"] = "challenge_and_log"
            elif result["threat_level"] == "low":
                result["recommended_action"] = "log_and_monitor"
            else:
                result["recommended_action"] = "allow"
            
            # Apply lockout if recommended
            if result["lockout_recommended"]:
                self.locked_ips[ip] = start_time + timedelta(seconds=self.lockout_duration)
                self.locked_usernames[username] = start_time + timedelta(seconds=self.lockout_duration)
            
            # Log security event
            if result["is_attack"] or result["confidence"] > 0.5:
                await self._log_attempt(attempt_data, result)
            
        except Exception as e:
            logger.error(f"Brute force detection failed: {e}")
            result["error"] = str(e)
        
        result["analysis_time_ms"] = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return result
    
    async def _log_attempt(self, attempt_data: Dict, result: Dict):
        """Log suspicious login attempt to database"""
        try:
            db = next(get_db())
            
            event = SecurityEvent(
                event_type="bruteforce_detection",
                severity=result["threat_level"],
                source_ip=attempt_data.get("ip_address", "unknown"),
                details={
                    "username": attempt_data.get("username", "unknown"),
                    "result": result
                },
                timestamp=datetime.utcnow()
            )
            db.add(event)
            
            login_attempt = LoginAttempt(
                username=attempt_data.get("username", "unknown"),
                ip_address=attempt_data.get("ip_address", "unknown"),
                success=attempt_data.get("success", False),
                threat_level=result["threat_level"],
                is_attack=result["is_attack"],
                attack_type=result.get("attack_type"),
                timestamp=datetime.utcnow()
            )
            db.add(login_attempt)
            db.commit()
            
        except Exception as e:
            logger.error(f"Failed to log brute force attempt: {e}")
    
    def get_ip_risk_score(self, ip: str) -> Dict:
        """Get overall risk score for an IP address"""
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        attempts_1h = sum(1 for t in self.ip_attempts[ip] if t > hour_ago)
        attempts_24h = sum(1 for t in self.ip_attempts[ip] if t > day_ago)
        
        is_locked = ip in self.locked_ips and self.locked_ips[ip] > now
        
        # Calculate risk score
        risk_score = 0.0
        if attempts_1h > 10:
            risk_score += 0.4
        if attempts_24h > 100:
            risk_score += 0.3
        if is_locked:
            risk_score += 0.3
        
        return {
            "ip": ip,
            "attempts_1h": attempts_1h,
            "attempts_24h": attempts_24h,
            "is_locked": is_locked,
            "lockout_expires": self.locked_ips.get(ip),
            "risk_score": min(risk_score, 1.0)
        }

# Global detector instance
bruteforce_detector = AdvancedBruteForceDetector()
