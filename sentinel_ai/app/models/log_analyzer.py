import re
from typing import Dict, List, Optional
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
import pickle
import os
import logging

logger = logging.getLogger(__name__)


class LogAnalysisEngine:
    """
    AI-powered log analysis engine for real-time threat detection.
    Analyzes various log types: system logs, application logs, security logs, access logs.
    """
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or "./models/log_analysis_model.pkl"
        self.anomaly_detector = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100
        )
        self.classifier = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            class_weight='balanced',
            random_state=42
        )
        self.vectorizer = TfidfVectorizer(
            max_features=300,
            ngram_range=(1, 2),
            analyzer='word'
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Threat patterns
        self.threat_patterns = {
            'privilege_escalation': [
                r'sudo\s+.*',
                r'su\s+-',
                r'chmod\s+[47][0-7][0-7]',
                r'chown\s+root',
                r'passwd\s+',
                r'usermod\s+.*-aG\s+sudo',
            ],
            'malware_indicators': [
                r'wget\s+http',
                r'curl\s+.*\|.*sh',
                r'/tmp/.*\.sh',
                r'base64\s+-d',
                r'nc\s+-[elp]',
                r'python\s+-c\s+.*import\s+socket',
            ],
            'data_exfiltration': [
                r'scp\s+.*@',
                r'rsync\s+.*:',
                r'ftp\s+put',
                r'curl\s+.*-d\s+@',
                r'tar\s+.*\|.*nc',
            ],
            'reconnaissance': [
                r'nmap\s+',
                r'masscan\s+',
                r'nikto\s+',
                r'dirb\s+',
                r'gobuster\s+',
                r'wpscan\s+',
            ],
            'lateral_movement': [
                r'ssh\s+.*@',
                r'psexec\s+',
                r'wmic\s+',
                r'net\s+use\s+\\\\',
            ],
            'persistence': [
                r'crontab\s+-e',
                r'systemctl\s+enable',
                r'/etc/rc\.local',
                r'\.bashrc',
                r'\.profile',
            ]
        }
        
        # Compile patterns
        self.compiled_patterns = {}
        for category, patterns in self.threat_patterns.items():
            self.compiled_patterns[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
        
        # Log history for context
        self.log_history = defaultdict(list)
        
    def parse_log_entry(self, log_line: str) -> Dict:
        """
        Parse a log entry into structured data.
        
        Args:
            log_line: Raw log line
            
        Returns:
            Parsed log data
        """
        parsed = {
            'raw': log_line,
            'timestamp': None,
            'level': 'INFO',
            'source': 'unknown',
            'message': log_line,
            'ip_address': None,
            'user': None,
            'action': None
        }
        
        # Try to extract timestamp (common formats)
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, log_line)
            if match:
                parsed['timestamp'] = match.group(1)
                break
        
        # Extract log level
        level_patterns = [
            (r'\b(ERROR|ERR)\b', 'ERROR'),
            (r'\b(WARNING|WARN)\b', 'WARNING'),
            (r'\b(CRITICAL|CRIT|FATAL)\b', 'CRITICAL'),
            (r'\b(DEBUG|DBG)\b', 'DEBUG'),
            (r'\b(INFO|INF)\b', 'INFO'),
        ]
        
        for pattern, level in level_patterns:
            if re.search(pattern, log_line, re.IGNORECASE):
                parsed['level'] = level
                break
        
        # Extract IP address
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log_line)
        if ip_match:
            parsed['ip_address'] = ip_match.group(1)
        
        # Extract username
        user_patterns = [
            r'user[=:\s]+([a-zA-Z0-9_-]+)',
            r'for\s+(?:invalid\s+)?user\s+([a-zA-Z0-9_-]+)',
            r'USER=([a-zA-Z0-9_-]+)',
        ]
        
        for pattern in user_patterns:
            match = re.search(pattern, log_line, re.IGNORECASE)
            if match:
                parsed['user'] = match.group(1)
                break
        
        return parsed
    
    def extract_features(self, log_entries: List[str]) -> np.ndarray:
        """
        Extract features from log entries for ML analysis.
        
        Args:
            log_entries: List of log lines
            
        Returns:
            Feature matrix
        """
        features_list = []
        
        for log_line in log_entries:
            features = []
            
            # Text features (length, special chars, etc.)
            features.append(len(log_line))
            features.append(log_line.count('!'))
            features.append(log_line.count('@'))
            features.append(log_line.count('#'))
            features.append(log_line.count('$'))
            
            # Numeric features
            numbers = re.findall(r'\d+', log_line)
            features.append(len(numbers))
            features.append(sum(len(n) for n in numbers) / (len(log_line) + 1))
            
            # Pattern matches
            for category, patterns in self.compiled_patterns.items():
                match_count = sum(1 for p in patterns if p.search(log_line))
                features.append(match_count)
            
            # Word count and unique words
            words = log_line.split()
            features.append(len(words))
            features.append(len(set(w.lower() for w in words)))
            
            # Uppercase ratio
            uppercase_count = sum(1 for c in log_line if c.isupper())
            features.append(uppercase_count / (len(log_line) + 1))
            
            # Padding to ensure fixed size (15 features total)
            while len(features) < 15:
                features.append(0)
            
            features_list.append(features[:15])
        
        return np.array(features_list)
    
    def analyze(self, log_lines: List[str]) -> Dict:
        """
        Analyze log entries for threats.
        
        Args:
            log_lines: List of log lines to analyze
            
        Returns:
            Analysis results with detected threats
        """
        if not log_lines:
            return {"threats_detected": 0, "entries_analyzed": 0, "results": []}
        
        results = []
        total_threats = 0
        
        for log_line in log_lines:
            result = self._analyze_single_log(log_line)
            results.append(result)
            if result.get('is_threat', False):
                total_threats += 1
        
        # Aggregate statistics
        threat_categories = defaultdict(int)
        severity_distribution = defaultdict(int)
        
        for result in results:
            if result.get('is_threat'):
                for category in result.get('categories', []):
                    threat_categories[category] += 1
                severity_distribution[result.get('severity', 'low')] += 1
        
        return {
            "threats_detected": total_threats,
            "entries_analyzed": len(log_lines),
            "threat_rate": round(total_threats / len(log_lines), 4),
            "results": results,
            "summary": {
                "by_category": dict(threat_categories),
                "by_severity": dict(severity_distribution),
                "top_ips": self._get_top_ips(results),
                "top_users": self._get_top_users(results)
            }
        }
    
    def _analyze_single_log(self, log_line: str) -> Dict:
        """Analyze a single log entry."""
        parsed = self.parse_log_entry(log_line)
        
        # Pattern-based detection
        matched_categories = []
        confidence_scores = []
        
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(log_line):
                    matched_categories.append(category)
                    confidence_scores.append(0.7)  # Base confidence for pattern match
        
        # ML-based anomaly detection
        if self.is_trained:
            try:
                features = self.extract_features([log_line])
                X_scaled = self.scaler.transform(features)
                
                # Anomaly score
                anomaly_score = self.anomaly_detector.score_samples(X_scaled)[0]
                is_anomaly = anomaly_score < -0.3
                
                if is_anomaly:
                    if 'anomaly' not in matched_categories:
                        matched_categories.append('anomaly')
                    confidence_scores.append(0.6)
                    
            except Exception as e:
                logger.error(f"Error in ML analysis: {e}")
        
        # Determine if threat
        is_threat = len(matched_categories) > 0
        avg_confidence = np.mean(confidence_scores) if confidence_scores else 0.0
        
        # Determine severity
        if len(matched_categories) >= 3 or avg_confidence > 0.85:
            severity = "critical"
        elif len(matched_categories) >= 2 or avg_confidence > 0.7:
            severity = "high"
        elif len(matched_categories) >= 1 or avg_confidence > 0.5:
            severity = "medium"
        else:
            severity = "low"
        
        # Generate alert message
        alert_message = self._generate_alert_message(parsed, matched_categories)
        
        return {
            "is_threat": is_threat,
            "confidence": round(avg_confidence, 4),
            "severity": severity,
            "categories": list(set(matched_categories)),
            "parsed": parsed,
            "alert_message": alert_message,
            "recommendations": self._get_recommendations(matched_categories)
        }
    
    def _generate_alert_message(self, parsed: Dict, categories: List[str]) -> str:
        """Generate human-readable alert message."""
        if not categories:
            return "No threats detected"
        
        parts = []
        if parsed.get('ip_address'):
            parts.append(f"IP: {parsed['ip_address']}")
        if parsed.get('user'):
            parts.append(f"User: {parsed['user']}")
        
        activity = ", ".join(categories)
        base_msg = f"Suspicious activity detected: {activity}"
        
        if parts:
            return f"{base_msg} ({'; '.join(parts)})"
        return base_msg
    
    def _get_recommendations(self, categories: List[str]) -> List[str]:
        """Get security recommendations based on detected categories."""
        recommendations = []
        
        if 'privilege_escalation' in categories:
            recommendations.append("Review sudo and privilege escalation policies")
            recommendations.append("Audit user permissions and group memberships")
        
        if 'malware_indicators' in categories:
            recommendations.append("Isolate affected system immediately")
            recommendations.append("Run full malware scan")
            recommendations.append("Check for persistence mechanisms")
        
        if 'data_exfiltration' in categories:
            recommendations.append("Block suspicious outbound connections")
            recommendations.append("Audit data access logs")
            recommendations.append("Review DLP policies")
        
        if 'reconnaissance' in categories:
            recommendations.append("Block source IP at firewall")
            recommendations.append("Enable enhanced logging")
        
        if 'lateral_movement' in categories:
            recommendations.append("Segment network to limit lateral movement")
            recommendations.append("Review SSH and remote access policies")
        
        if 'persistence' in categories:
            recommendations.append("Audit startup scripts and scheduled tasks")
            recommendations.append("Check for unauthorized services")
        
        if not recommendations:
            recommendations.append("Continue monitoring for suspicious activity")
        
        return recommendations
    
    def _get_top_ips(self, results: List[Dict], top_n: int = 10) -> List[Dict]:
        """Get top IPs by threat count."""
        ip_counts = defaultdict(int)
        
        for result in results:
            if result.get('is_threat') and result.get('parsed', {}).get('ip_address'):
                ip_counts[result['parsed']['ip_address']] += 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "count": count} for ip, count in sorted_ips[:top_n]]
    
    def _get_top_users(self, results: List[Dict], top_n: int = 10) -> List[Dict]:
        """Get top users by threat count."""
        user_counts = defaultdict(int)
        
        for result in results:
            if result.get('is_threat') and result.get('parsed', {}).get('user'):
                user_counts[result['parsed']['user']] += 1
        
        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"user": user, "count": count} for user, count in sorted_users[:top_n]]
    
    def train(self, log_lines: List[str], labels: List[int]):
        """
        Train the log analysis models.
        
        Args:
            log_lines: List of log entries
            labels: Labels (0=normal, 1=threat)
        """
        # Vectorize text
        X_tfidf = self.vectorizer.fit_transform(log_lines).toarray()
        
        # Extract additional features
        X_extra = self.extract_features(log_lines)
        
        # Combine features
        X = np.hstack([X_tfidf, X_extra])
        X_scaled = self.scaler.fit_transform(X)
        
        # Train models
        self.anomaly_detector.fit(X_scaled)
        self.classifier.fit(X_scaled, labels)
        
        self.is_trained = True
        logger.info(f"Log analysis model trained with {len(log_lines)} entries")
    
    def save_model(self):
        """Save trained model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'anomaly_detector': self.anomaly_detector,
                'classifier': self.classifier,
                'vectorizer': self.vectorizer,
                'scaler': self.scaler
            }, f)
        logger.info(f"Saved log analysis model to {self.model_path}")
    
    def load_model(self):
        """Load pre-trained model from disk."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.anomaly_detector = data['anomaly_detector']
                    self.classifier = data['classifier']
                    self.vectorizer = data['vectorizer']
                    self.scaler = data['scaler']
                    self.is_trained = True
                logger.info(f"Loaded log analysis model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")


# Global instance
log_analyzer = LogAnalysisEngine()
