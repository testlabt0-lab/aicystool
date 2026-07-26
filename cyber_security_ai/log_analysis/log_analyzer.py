"""
Log Analysis System using AI
Analyzes log files to detect suspicious activities and threats in real-time
"""

import numpy as np
import re
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from collections import Counter, defaultdict
import joblib
import os


class LogEntryParser:
    """Parse different log formats"""
    
    # Common log patterns
    PATTERNS = {
        'apache': r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+)',
        'nginx': r'(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"',
        'syslog': r'(\w+)\s+(\d+)\s+(\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)',
        'auth': r'(\w+)\s+(\d+)\s+(\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)',
        'generic': r'(?P<timestamp>[\d\-:\s\.]+)\s+(?P<level>\w+)\s+(?P<message>.*)'
    }
    
    def __init__(self):
        self.compiled_patterns = {
            name: re.compile(pattern) for name, pattern in self.PATTERNS.items()
        }
    
    def parse(self, log_line):
        """
        Parse a log line
        
        Args:
            log_line: Raw log line string
            
        Returns:
            Dictionary with parsed fields
        """
        for log_type, pattern in self.compiled_patterns.items():
            match = pattern.match(log_line.strip())
            if match:
                return {
                    'type': log_type,
                    'raw': log_line,
                    'groups': match.groups(),
                    'parsed': True
                }
        
        # Return unparsed if no pattern matches
        return {
            'type': 'unknown',
            'raw': log_line,
            'groups': (),
            'parsed': False
        }
    
    def extract_features(self, log_line):
        """
        Extract features from a log line
        
        Args:
            log_line: Raw log line string
            
        Returns:
            Feature dictionary
        """
        parsed = self.parse(log_line)
        
        # Count various indicators
        features = {
            'length': len(log_line),
            'digit_count': sum(c.isdigit() for c in log_line),
            'special_char_count': sum(not c.isalnum() and not c.isspace() for c in log_line),
            'uppercase_ratio': sum(c.isupper() for c in log_line) / max(len(log_line), 1),
            'has_ip': bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', log_line)),
            'has_url': bool(re.search(r'https?://', log_line, re.IGNORECASE)),
            'has_error_keyword': bool(re.search(r'\b(error|fail|denied|unauthorized|exception|critical|alert)\b', log_line, re.IGNORECASE)),
            'has_success_keyword': bool(re.search(r'\b(success|ok|accepted|allowed|authenticated)\b', log_line, re.IGNORECASE)),
            'has_attack_keyword': bool(re.search(r'\b(attack|injection|xss|exploit|malware|virus|trojan|backdoor)\b', log_line, re.IGNORECASE)),
            'has_sql_keyword': bool(re.search(r'\b(select|insert|update|delete|drop|union|exec)\b', log_line, re.IGNORECASE)),
            'bracket_count': log_line.count('[') + log_line.count(']'),
            'quote_count': log_line.count('"') + log_line.count("'"),
            'slash_count': log_line.count('/'),
        }
        
        return features


class LogAnalyzer:
    """AI-powered Log Analysis System"""
    
    def __init__(self):
        self.parser = LogEntryParser()
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            stop_words='english'
        )
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            class_weight='balanced',
            random_state=42
        )
        self.cluster_model = None
        self.is_trained = False
        self.threat_signatures = self._load_threat_signatures()
    
    def _load_threat_signatures(self):
        """Load known threat signatures"""
        return [
            r'failed\s+password',
            r'invalid\s+user',
            r'authentication\s+fail',
            r'access\s+denied',
            r'unauthorized\s+access',
            r'sql\s+injection',
            r'xss\s+attack',
            r'directory\s+traversal',
            r'command\s+injection',
            r'buffer\s+overflow',
            r'malicious\s+payload',
            r'exploit\s+attempt',
            r'port\s+scan',
            r'brute\s*force',
            r'ddos\s+attack',
            r'suspicious\s+activity',
            r'anomalous\s+behavior',
            r'privilege\s+escalation',
            r'data\s+exfiltration',
            r'malware\s+detection',
        ]
    
    def extract_log_features(self, log_lines):
        """
        Extract features from log lines
        
        Args:
            log_lines: List of log line strings
            
        Returns:
            Feature matrix
        """
        # Text features (TF-IDF)
        X_tfidf = self.vectorizer.fit_transform(log_lines).toarray()
        
        # Statistical features
        stat_features = []
        for line in log_lines:
            features = self.parser.extract_features(line)
            stat_features.append(list(features.values()))
        
        X_stat = np.array(stat_features)
        
        # Combine features
        X = np.hstack([X_tfidf, X_stat])
        
        return X
    
    def check_threat_signature(self, log_line):
        """Check if log line matches known threat signatures"""
        matches = []
        for signature in self.threat_signatures:
            if re.search(signature, log_line, re.IGNORECASE):
                matches.append(signature)
        return matches
    
    def generate_training_data(self, n_samples=1000):
        """Generate synthetic training data"""
        
        normal_logs = [
            "User admin logged in successfully",
            "GET /index.html HTTP/1.1 200 OK",
            "POST /api/login HTTP/1.1 200 OK",
            "Connection established from 192.168.1.100",
            "Session created for user john.doe",
            "File uploaded successfully: report.pdf",
            "Database query executed in 0.05s",
            "Cache cleared successfully",
            "Scheduled task completed",
            "Email sent to user@example.com",
            "API request processed successfully",
            "Configuration updated",
            "Backup completed successfully",
            "Health check passed",
            "Service restarted normally",
        ]
        
        attack_logs = [
            "Failed password for invalid user admin from 10.0.0.1",
            "SQL injection attempt detected: SELECT * FROM users WHERE 1=1",
            "XSS attack blocked: <script>alert('xss')</script>",
            "Directory traversal attempt: ../../etc/passwd",
            "Brute force attack detected from 203.0.113.50",
            "Unauthorized access attempt to /admin/config",
            "Command injection detected: ; rm -rf /",
            "Port scan detected from 198.51.100.25",
            "DDoS attack pattern identified",
            "Malware signature detected in upload",
            "Authentication failure for root from unknown IP",
            "Privilege escalation attempt blocked",
            "Data exfiltration attempt detected",
            "Exploit attempt CVE-2024-1234 blocked",
            "Suspicious payload in HTTP request",
        ]
        
        logs = []
        labels = []
        
        # Generate normal samples
        for _ in range(n_samples // 2):
            base_log = np.random.choice(normal_logs)
            # Add variation
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip = f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}"
            varied_log = f"{timestamp} {base_log} from {ip}"
            logs.append(varied_log)
            labels.append(0)
        
        # Generate attack samples
        for _ in range(n_samples // 2):
            base_log = np.random.choice(attack_logs)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip = f"{np.random.randint(1,223)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,255)}"
            varied_log = f"{timestamp} {base_log} from {ip}"
            logs.append(varied_log)
            labels.append(1)
        
        return logs, labels
    
    def train(self, log_lines=None, labels=None):
        """
        Train the log analysis models
        
        Args:
            log_lines: List of log lines for training
            labels: Corresponding labels (0=normal, 1=threat)
        """
        if log_lines is None or labels is None:
            print("Generating synthetic training data...")
            log_lines, labels = self.generate_training_data(2000)
        
        # Extract features
        X = self.extract_log_features(log_lines)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train anomaly detector
        self.anomaly_detector.fit(X)
        
        # Train classifier
        self.classifier.fit(X_train, y_train)
        
        # Train clustering for pattern discovery
        self.cluster_model = KMeans(n_clusters=5, random_state=42)
        self.cluster_model.fit(X)
        
        self.is_trained = True
        
        # Evaluate
        y_pred = self.classifier.predict(X_test)
        print("Model Training Results:")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Threat']))
        
        return self.classifier
    
    def analyze(self, log_line):
        """
        Analyze a single log line
        
        Args:
            log_line: Log line to analyze
            
        Returns:
            Analysis results dictionary
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before analysis")
        
        # Extract features
        X_tfidf = self.vectorizer.transform([log_line]).toarray()
        stat_features = list(self.parser.extract_features(log_line).values())
        X_stat = np.array([stat_features])
        X = np.hstack([X_tfidf, X_stat])
        
        # Classifier prediction
        pred_class = self.classifier.predict(X)[0]
        pred_proba = self.classifier.predict_proba(X)[0]
        
        # Anomaly detection
        anomaly_score = self.anomaly_detector.score_samples(X)[0]
        is_anomaly = anomaly_score < -0.5
        
        # Cluster assignment
        cluster = self.cluster_model.predict(X)[0]
        
        # Threat signature matching
        matched_signatures = self.check_threat_signature(log_line)
        
        # Risk assessment
        risk_score = 0
        if pred_class == 1:
            risk_score += 40
        if is_anomaly:
            risk_score += 30
        if matched_signatures:
            risk_score += min(len(matched_signatures) * 10, 30)
        
        risk_level = 'LOW' if risk_score < 30 else 'MEDIUM' if risk_score < 60 else 'HIGH'
        
        return {
            'prediction': 'THREAT' if pred_class == 1 else 'NORMAL',
            'confidence': float(max(pred_proba)),
            'anomaly_score': float(anomaly_score),
            'is_anomaly': bool(is_anomaly),
            'cluster': int(cluster),
            'matched_signatures': matched_signatures,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'features': self.parser.extract_features(log_line)
        }
    
    def analyze_batch(self, log_lines, threshold=0.5):
        """
        Analyze multiple log lines
        
        Args:
            log_lines: List of log lines
            threshold: Confidence threshold for alerts
            
        Returns:
            List of alerts
        """
        alerts = []
        
        for i, line in enumerate(log_lines):
            try:
                result = self.analyze(line)
                if result['risk_level'] in ['MEDIUM', 'HIGH']:
                    alerts.append({
                        'line_number': i,
                        'log_line': line[:200],  # Truncate long lines
                        'analysis': result
                    })
            except Exception as e:
                alerts.append({
                    'line_number': i,
                    'log_line': line[:200],
                    'error': str(e)
                })
        
        return alerts
    
    def save_model(self, filepath='log_analyzer_model.pkl'):
        """Save trained models"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        
        model_data = {
            'vectorizer': self.vectorizer,
            'anomaly_detector': self.anomaly_detector,
            'classifier': self.classifier,
            'cluster_model': self.cluster_model,
            'threat_signatures': self.threat_signatures,
        }
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath='log_analyzer_model.pkl'):
        """Load pre-trained models"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file {filepath} not found")
        
        model_data = joblib.load(filepath)
        self.vectorizer = model_data['vectorizer']
        self.anomaly_detector = model_data['anomaly_detector']
        self.classifier = model_data['classifier']
        self.cluster_model = model_data['cluster_model']
        self.threat_signatures = model_data.get('threat_signatures', self.threat_signatures)
        self.is_trained = True
        print(f"Model loaded from {filepath}")


class RealTimeLogMonitor:
    """Real-time log monitoring system"""
    
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.alerts = []
        self.statistics = defaultdict(int)
    
    def process_log(self, log_line):
        """Process a single log line in real-time"""
        result = self.analyzer.analyze(log_line)
        
        # Update statistics
        self.statistics['total_processed'] += 1
        self.statistics[f"risk_{result['risk_level'].lower()}"] += 1
        
        if result['prediction'] == 'THREAT' or result['risk_level'] in ['MEDIUM', 'HIGH']:
            alert = {
                'timestamp': datetime.now(),
                'log_line': log_line[:500],
                'analysis': result
            }
            self.alerts.append(alert)
            self.statistics['total_alerts'] += 1
        
        return result
    
    def get_summary(self):
        """Get monitoring summary"""
        return {
            'total_processed': self.statistics['total_processed'],
            'total_alerts': self.statistics['total_alerts'],
            'risk_distribution': {
                'low': self.statistics['risk_low'],
                'medium': self.statistics['risk_medium'],
                'high': self.statistics['risk_high'],
            },
            'recent_alerts': self.alerts[-10:]  # Last 10 alerts
        }


if __name__ == "__main__":
    print("=" * 60)
    print("AI-Powered Log Analysis System")
    print("=" * 60)
    
    # Initialize analyzer
    analyzer = LogAnalyzer()
    
    # Train model
    print("\nTraining log analysis model...")
    analyzer.train()
    
    # Save model
    analyzer.save_model('log_analyzer_model.pkl')
    
    # Initialize real-time monitor
    monitor = RealTimeLogMonitor(analyzer)
    
    # Test with sample logs
    print("\n" + "=" * 60)
    print("Testing with sample log entries:")
    print("=" * 60)
    
    test_logs = [
        "2024-01-15 10:30:45 INFO User admin logged in successfully from 192.168.1.100",
        "2024-01-15 10:31:02 ERROR Failed password for invalid user root from 10.0.0.50",
        "2024-01-15 10:31:15 WARNING SQL injection attempt detected: SELECT * FROM users WHERE id=1 OR 1=1",
        "2024-01-15 10:32:00 INFO GET /api/data HTTP/1.1 200 OK",
        "2024-01-15 10:32:30 CRITICAL Brute force attack detected from 203.0.113.42",
        "2024-01-15 10:33:00 INFO Scheduled backup completed successfully",
        "2024-01-15 10:33:45 ALERT XSS attack blocked: <script>document.cookie</script>",
        "2024-01-15 10:34:00 DEBUG Database query executed in 0.023s",
    ]
    
    for i, log in enumerate(test_logs, 1):
        result = analyzer.analyze(log)
        print(f"\nLog {i}: {log[:80]}...")
        print(f"  Prediction: {result['prediction']}")
        print(f"  Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
        print(f"  Confidence: {result['confidence']:.2%}")
        if result['matched_signatures']:
            print(f"  Matched Signatures: {result['matched_signatures']}")
    
    # Get summary
    summary = monitor.get_summary()
    print(f"\n\nMonitoring Summary:")
    print(f"  Total Processed: {summary['total_processed']}")
    print(f"  Total Alerts: {summary['total_alerts']}")
    
    print("\n" + "=" * 60)
    print("System ready for deployment!")
    print("=" * 60)
