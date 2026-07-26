import re
from typing import Dict, List, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import pickle
import os
import logging

logger = logging.getLogger(__name__)


class SQLInjectionDetector:
    """
    NLP-based SQL Injection detection using pattern analysis and ML.
    Detects various SQLi techniques: Union-based, Boolean-based, Time-based, Error-based.
    """
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or "./models/sqli_model.pkl"
        self.model = None
        self.vectorizer = TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 3),
            analyzer='char_wb'
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # SQL injection patterns
        self.sqli_patterns = [
            # Classic SQLi
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            
            # Union-based
            r"union\s+(all\s+)?select",
            r"union\s+select\s+\d+",
            
            # Boolean-based
            r"and\s+1\s*=\s*1",
            r"or\s+1\s*=\s*1",
            r"'\s*or\s*'",
            
            # Time-based
            r"sleep\s*\(\s*\d+\s*\)",
            r"waitfor\s+delay",
            r"benchmark\s*\(",
            r"pg_sleep\s*\(",
            
            # Error-based
            r"extractvalue\s*\(",
            r"updatexml\s*\(",
            r"exp\s*\(\s*~",
            
            # Stacked queries
            r";\s*(drop|delete|update|insert|truncate)\s+",
            r";\s*exec\s+",
            r";\s*xp_",
            
            # Comment sequences
            r"/\*.*\*/",
            r"--\s*$",
            r"#\s*$",
            
            # Encoding tricks
            r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}",
            r"&#x[0-9a-fA-F]+;",
            
            # Function calls
            r"(concat|group_concat|version|database|user|schema)\s*\(",
            r"(load_file|into\s+outfile|into\s+dumpfile)\s*\(",
            
            # Information schema
            r"information_schema",
            r"sys\.(tables|columns|objects)",
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.sqli_patterns]
        
    def extract_features(self, query: str) -> Dict:
        """
        Extract features from SQL query for analysis.
        
        Args:
            query: SQL query string
            
        Returns:
            Dictionary of extracted features
        """
        features = {
            'query_length': len(query),
            'special_char_count': len(re.findall(r"[\'\";\-\-=<>!@#$%^&*()\[\]{}|\\]", query)),
            'keyword_count': len(re.findall(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND|FROM|WHERE|EXEC|EXECUTE)\b', query, re.IGNORECASE)),
            'comment_count': len(re.findall(r'(--|#|/\*)', query)),
            'space_ratio': query.count(' ') / (len(query) + 1),
            'has_union': 1 if re.search(r'\bUNION\b', query, re.IGNORECASE) else 0,
            'has_sleep': 1 if re.search(r'\b(SLEEP|WAITFOR|BENCHMARK|PG_SLEEP)\b', query, re.IGNORECASE) else 0,
            'has_information_schema': 1 if re.search(r'information_schema', query, re.IGNORECASE) else 0,
            'has_encoded_chars': 1 if re.search(r'%[0-9a-fA-F]{2}', query) else 0,
            'quote_balance': abs(query.count("'") - query.count('"')),
            'semicolon_count': query.count(';'),
            'parenthesis_balance': abs(query.count('(') - query.count(')')),
            'numeric_ratio': len(re.findall(r'\d', query)) / (len(query) + 1),
            'case_variation': sum(1 for c in query if c.isupper()) / (len(query) + 1),
        }
        
        # Pattern match scores
        pattern_matches = 0
        for pattern in self.compiled_patterns:
            if pattern.search(query):
                pattern_matches += 1
        features['pattern_match_count'] = pattern_matches
        
        return features
    
    def train(self, queries: List[str], labels: List[int]):
        """
        Train the SQL injection detection model.
        
        Args:
            queries: List of SQL queries
            labels: List of labels (0=benign, 1=malicious)
        """
        # Vectorize queries
        X_tfidf = self.vectorizer.fit_transform(queries).toarray()
        
        # Extract additional features
        X_extra = np.array([list(self.extract_features(q).values()) for q in queries])
        
        # Combine features
        X = np.hstack([X_tfidf, X_extra])
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=3,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled, labels)
        self.is_trained = True
        
        logger.info(f"SQLi detection model trained with {len(queries)} queries")
        
    def detect(self, query: str) -> Dict:
        """
        Detect SQL injection in a query.
        
        Args:
            query: SQL query to analyze
            
        Returns:
            Detection result with confidence and attack type
        """
        if not self.is_trained:
            self._load_model()
        
        # Pattern-based detection (fast path)
        pattern_result = self._pattern_detection(query)
        
        if pattern_result['confidence'] > 0.95:
            # High confidence from patterns, return immediately
            return pattern_result
        
        # ML-based detection
        try:
            X_tfidf = self.vectorizer.transform([query]).toarray()
            features = self.extract_features(query)
            X_extra = np.array([list(features.values())])
            X = np.hstack([X_tfidf, X_extra])
            X_scaled = self.scaler.transform(X)
            
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            
            ml_confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
            
            # Combine pattern and ML results
            if prediction == 1:
                final_confidence = max(pattern_result['confidence'], ml_confidence)
            else:
                final_confidence = ml_confidence * (1 - pattern_result['confidence'] * 0.5)
            
            # Determine risk level
            if final_confidence > 0.9:
                risk_level = "critical"
            elif final_confidence > 0.75:
                risk_level = "high"
            elif final_confidence > 0.5:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            # Classify attack type
            attack_type = self._classify_attack_type(query) if prediction == 1 else None
            
            return {
                "is_sqli": bool(prediction),
                "confidence": round(final_confidence, 4),
                "risk_level": risk_level,
                "attack_type": attack_type,
                "patterns_matched": pattern_result.get('patterns_matched', []),
                "query_analysis": {
                    "length": features['query_length'],
                    "special_chars": features['special_char_count'],
                    "keywords": features['keyword_count']
                }
            }
            
        except Exception as e:
            logger.error(f"Error in SQLi detection: {e}")
            return pattern_result
    
    def _pattern_detection(self, query: str) -> Dict:
        """Fast pattern-based detection."""
        matched_patterns = []
        score = 0.0
        
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(query):
                matched_patterns.append(self.sqli_patterns[i])
                score += 0.15  # Each pattern adds to confidence
        
        confidence = min(score, 0.99)
        is_sqli = confidence > 0.5
        
        if is_sqli:
            risk_level = "critical" if confidence > 0.8 else "high" if confidence > 0.6 else "medium"
        else:
            risk_level = "low"
        
        return {
            "is_sqli": is_sqli,
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "patterns_matched": matched_patterns[:5],  # Top 5 patterns
            "attack_type": self._classify_attack_type(query) if is_sqli else None
        }
    
    def _classify_attack_type(self, query: str) -> str:
        """Classify the type of SQL injection attack."""
        query_upper = query.upper()
        
        if 'UNION' in query_upper and 'SELECT' in query_upper:
            return "Union-based SQLi"
        elif re.search(r'\b(OR|AND)\b.*=.*', query, re.IGNORECASE):
            return "Boolean-based SQLi"
        elif re.search(r'\b(SLEEP|WAITFOR|BENCHMARK|PG_SLEEP)\b', query, re.IGNORECASE):
            return "Time-based Blind SQLi"
        elif re.search(r'(EXTRACTVALUE|UPDATEXML|EXP\s*\(\s*~)', query, re.IGNORECASE):
            return "Error-based SQLi"
        elif ';' in query and re.search(r';\s*(DROP|DELETE|UPDATE|INSERT)', query, re.IGNORECASE):
            return "Stacked Queries SQLi"
        elif re.search(r'information_schema', query, re.IGNORECASE):
            return "Information Schema Enumeration"
        else:
            return "Classic SQLi"
    
    def _load_model(self):
        """Load pre-trained model from disk."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.vectorizer = data['vectorizer']
                    self.scaler = data['scaler']
                    self.is_trained = True
                logger.info(f"Loaded SQLi model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self._initialize_default_model()
        else:
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize default model with synthetic data."""
        # Benign queries
        benign_queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT name, email FROM customers WHERE status = 'active'",
            "INSERT INTO orders (user_id, product_id, quantity) VALUES (1, 5, 2)",
            "UPDATE products SET price = 29.99 WHERE id = 10",
            "DELETE FROM cart WHERE user_id = 5",
            "SELECT COUNT(*) FROM transactions WHERE date > '2024-01-01'",
            "SELECT p.name, c.category FROM products p JOIN categories c ON p.cat_id = c.id",
        ]
        
        # Malicious queries
        malicious_queries = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "' UNION SELECT username, password FROM users--",
            "1; DROP TABLE users--",
            "admin'--",
            "1' AND SLEEP(5)--",
            "' OR '1'='1",
            "1 UNION SELECT NULL, table_name FROM information_schema.tables--",
            "'; EXEC xp_cmdshell('dir')--",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, version()))--",
        ]
        
        all_queries = benign_queries + malicious_queries
        labels = [0] * len(benign_queries) + [1] * len(malicious_queries)
        
        self.train(all_queries, labels)
        logger.info("Initialized default SQLi detection model")
    
    def save_model(self):
        """Save trained model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'vectorizer': self.vectorizer,
                'scaler': self.scaler
            }, f)
        logger.info(f"Saved SQLi model to {self.model_path}")


# Global instance
sqli_detector = SQLInjectionDetector()
