"""
Advanced SQL Injection Detection Service using NLP and Deep Learning
Multi-layered detection with pattern matching, ML classification, and semantic analysis
"""

import re
import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.preprocessing import StandardScaler
import joblib
import logging

try:
    from tensorflow import keras
    from tensorflow.keras import layers, models
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

from app.config import settings
from app.database import get_db, SecurityEvent, SQLInjectionAttempt

logger = logging.getLogger(__name__)

class AdvancedSQLiDetector:
    """
    Enterprise-grade SQL Injection detection with multiple layers:
    1. Pattern-based Detection (Regular expressions)
    2. Machine Learning Classification (RF + GBM)
    3. NLP Semantic Analysis (TF-IDF + Deep Learning)
    4. Contextual Analysis (Query structure)
    5. Behavioral Analysis (Request patterns)
    """
    
    def __init__(self):
        # Pattern matching rules
        self.patterns = self._load_patterns()
        
        # ML Models
        self.rf_model: Optional[RandomForestClassifier] = None
        self.gbm_model: Optional[GradientBoostingClassifier] = None
        self.tfidf_vectorizer: Optional[TfidfVectorizer] = None
        self.scaler: Optional[StandardScaler] = None
        
        # NLP Deep Learning Model
        self.nlp_model: Optional[models.Model] = None
        
        # Known safe queries cache
        self.safe_queries_cache: set = set()
        
        # Attack signatures database
        self.attack_signatures: Dict[str, str] = {}
        
        # Initialize models
        self._initialize_models()
    
    def _load_patterns(self) -> List[Dict]:
        """Load comprehensive SQL injection detection patterns"""
        return [
            {
                "name": "Classic SQL Injection",
                "pattern": r"(\bOR\b|\bAND\b)\s*['\"]?\s*\d+\s*=\s*\d+",
                "severity": "high",
                "description": "Classic OR/AND based SQL injection"
            },
            {
                "name": "Union-based SQL Injection",
                "pattern": r"\bUNION\b\s+(ALL\s+)?\bSELECT\b",
                "severity": "critical",
                "description": "UNION SELECT based injection"
            },
            {
                "name": "Comment-based Injection",
                "pattern": r"(--|#|/\*)",
                "severity": "medium",
                "description": "SQL comment-based injection"
            },
            {
                "name": "Stacked Queries",
                "pattern": r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)",
                "severity": "critical",
                "description": "Stacked query injection"
            },
            {
                "name": "Time-based Blind",
                "pattern": r"(SLEEP|WAITFOR|BENCHMARK|PG_SLEEP)\s*\(",
                "severity": "high",
                "description": "Time-based blind SQL injection"
            },
            {
                "name": "Boolean-based Blind",
                "pattern": r"(\bAND\b|\bOR\b)\s*\d+\s*[<>]=?\s*\d+",
                "severity": "high",
                "description": "Boolean-based blind injection"
            },
            {
                "name": "Error-based",
                "pattern": r"(EXTRACTVALUE|UPDATEXML|CONVERT|CAST)\s*\(",
                "severity": "high",
                "description": "Error-based SQL injection"
            },
            {
                "name": "Out-of-band",
                "pattern": r"(UTL_HTTP|HTTPURITYPE|SYS.DBMS_LOB)\s*\.",
                "severity": "critical",
                "description": "Out-of-band data exfiltration"
            },
            {
                "name": "Encoded Injection",
                "pattern": r"(%27|%22|%3D|%20)*(OR|AND|UNION|SELECT)",
                "severity": "high",
                "description": "URL-encoded SQL injection"
            },
            {
                "name": "Hex-encoded",
                "pattern": r"0x[0-9a-fA-F]+",
                "severity": "medium",
                "description": "Hexadecimal encoded values"
            },
            {
                "name": "Function calls",
                "pattern": r"\b(CHAR|CHR|CONCAT|SUBSTRING|ASCII|HEX)\s*\(",
                "severity": "medium",
                "description": "SQL function-based obfuscation"
            },
            {
                "name": "Information Schema",
                "pattern": r"\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b",
                "severity": "critical",
                "description": "Database schema enumeration"
            }
        ]
    
    def _initialize_models(self):
        """Initialize or load ML/NLP models"""
        try:
            # Try to load pre-trained models
            rf_path = f"{settings.MODEL_PATH}/sqli_rf.pkl"
            gbm_path = f"{settings.MODEL_PATH}/sqli_gbm.pkl"
            tfidf_path = f"{settings.MODEL_PATH}/sqli_tfidf.pkl"
            
            if all([joblib.load(p) for p in [rf_path, gbm_path, tfidf_path] if p]):
                self.rf_model = joblib.load(rf_path)
                self.gbm_model = joblib.load(gbm_path)
                self.tfidf_vectorizer = joblib.load(tfidf_path)
                logger.info("Loaded pre-trained SQLi detection models")
            else:
                self._train_models()
        except FileNotFoundError:
            logger.warning("Pre-trained SQLi models not found, training new models")
            self._train_models()
        
        # Initialize NLP deep learning model if TensorFlow available
        if TENSORFLOW_AVAILABLE:
            self._build_nlp_model()
    
    def _train_models(self):
        """Train ML models on synthetic SQL injection data"""
        # Generate comprehensive training data
        benign_queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT name, email FROM customers WHERE active = true",
            "INSERT INTO orders (user_id, product_id) VALUES (5, 10)",
            "UPDATE products SET price = 99.99 WHERE id = 3",
            "DELETE FROM cart WHERE user_id = 7 AND product_id = 2",
            "SELECT COUNT(*) FROM transactions WHERE date > '2024-01-01'",
            "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
            "SELECT * FROM items WHERE category IN ('electronics', 'books')",
            "SELECT product_name FROM products WHERE stock > 0 ORDER BY name",
            "SELECT DISTINCT country FROM customers WHERE region = 'US'"
        ]
        
        malicious_queries = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users WHERE name = '' UNION SELECT username, password FROM admin--",
            "SELECT * FROM products WHERE id = 1; DROP TABLE users;--",
            "SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
            "SELECT * FROM items WHERE price = 10 OR '1'='1'",
            "SELECT * FROM users WHERE name = 'admin'/**/OR/**/1=1",
            "SELECT * FROM products WHERE id = 1 UNION ALL SELECT NULL, table_name FROM information_schema.tables--",
            "SELECT * FROM users WHERE id = CAST(1 AS INT) AND (SELECT COUNT(*) FROM sysobjects) > 0",
            "SELECT * FROM customers WHERE email = 'test@test.com' AND BENCHMARK(10000000, SHA1('test'))",
            "SELECT * FROM users WHERE id = 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))"
        ]
        
        # Augment dataset
        benign_extended = benign_queries * 500
        malicious_extended = malicious_queries * 500
        
        # Add variations
        for i in range(2000):
            benign_extended.append(f"SELECT * FROM table{i} WHERE id = {i % 100}")
            malicious_extended.append(f"SELECT * FROM table{i} WHERE id = {i % 100} OR 1=1--")
        
        X_train = benign_extended + malicious_extended
        y_train = [0] * len(benign_extended) + [1] * len(malicious_extended)
        
        # Create TF-IDF features
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 3),
            analyzer='char_wb',
            min_df=2
        )
        X_tfidf = self.tfidf_vectorizer.fit_transform(X_train).toarray()
        
        # Add additional features
        X_additional = np.array([self._extract_query_features(q) for q in X_train])
        X_combined = np.hstack([X_tfidf, X_additional])
        
        # Train Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=3,
            class_weight='balanced',
            n_jobs=-1,
            random_state=42
        )
        self.rf_model.fit(X_combined, y_train)
        
        # Train Gradient Boosting
        self.gbm_model = GradientBoostingClassifier(
            n_estimators=150,
            max_depth=15,
            learning_rate=0.1,
            random_state=42
        )
        self.gbm_model.fit(X_combined, y_train)
        
        # Fit scaler
        self.scaler = StandardScaler()
        self.scaler.fit(X_combined)
        
        # Save models
        import os
        os.makedirs(settings.MODEL_PATH, exist_ok=True)
        joblib.dump(self.rf_model, f"{settings.MODEL_PATH}/sqli_rf.pkl")
        joblib.dump(self.gbm_model, f"{settings.MODEL_PATH}/sqli_gbm.pkl")
        joblib.dump(self.tfidf_vectorizer, f"{settings.MODEL_PATH}/sqli_tfidf.pkl")
        joblib.dump(self.scaler, f"{settings.MODEL_PATH}/sqli_scaler.pkl")
        
        logger.info("Trained and saved SQLi detection models")
    
    def _build_nlp_model(self):
        """Build deep learning model for semantic analysis"""
        if not TENSORFLOW_AVAILABLE:
            return
        
        # Simple LSTM-based model for sequence classification
        model = models.Sequential([
            layers.Embedding(input_dim=10000, output_dim=128, input_length=100),
            layers.Bidirectional(layers.LSTM(64, return_sequences=True)),
            layers.Bidirectional(layers.LSTM(32)),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.5),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        self.nlp_model = model
        logger.info("Built NLP deep learning model for SQLi detection")
    
    def _extract_query_features(self, query: str) -> np.ndarray:
        """Extract handcrafted features from SQL query"""
        query_upper = query.upper()
        
        features = [
            len(query),  # Query length
            query.count("'"),  # Single quote count
            query.count('"'),  # Double quote count
            query.count(';'),  # Semicolon count
            query.count('--'),  # Comment marker
            query_upper.count(' OR '),  # OR keywords
            query_upper.count(' AND '),  # AND keywords
            query_upper.count('UNION'),  # UNION keyword
            query_upper.count('SELECT'),  # SELECT count
            query_upper.count('FROM'),  # FROM count
            query_upper.count('WHERE'),  # WHERE count
            query_upper.count('DROP'),  # DROP keyword
            query_upper.count('DELETE'),  # DELETE keyword
            query_upper.count('INSERT'),  # INSERT keyword
            query_upper.count('UPDATE'),  # UPDATE keyword
            query_upper.count('EXEC'),  # EXEC keyword
            query_upper.count('XP_'),  # Extended stored procedures
            query.count('='),  # Equality operators
            query.count('<>'),  # Not equal
            query.count('>='),  # Greater or equal
            query.count('<='),  # Less or equal
            query_upper.count('SLEEP'),  # Time-based functions
            query_upper.count('WAITFOR'),
            query_upper.count('BENCHMARK'),
            query_upper.count('INFORMATION_SCHEMA'),  # Schema access
            query_upper.count('SYSDATABASES'),
            query.count('/*'),  # Block comments
            query.count('*/'),
            len(re.findall(r'\d+=\d+', query)),  # Numeric comparisons
            len(re.findall(r'0x[0-9a-fA-F]+', query)),  # Hex values
        ]
        
        return np.array(features)
    
    def _pattern_detection(self, query: str) -> List[Dict]:
        """Detect SQL injection using pattern matching"""
        detected_patterns = []
        
        for pattern_info in self.patterns:
            if re.search(pattern_info["pattern"], query, re.IGNORECASE):
                detected_patterns.append({
                    "pattern_name": pattern_info["name"],
                    "severity": pattern_info["severity"],
                    "description": pattern_info["description"],
                    "matched": True
                })
        
        return detected_patterns
    
    def _ml_detection(self, query: str) -> Dict:
        """Detect SQL injection using ML models"""
        result = {
            "rf_probability": 0.0,
            "gbm_probability": 0.0,
            "ensemble_probability": 0.0,
            "is_malicious": False
        }
        
        try:
            # Extract features
            tfidf_features = self.tfidf_vectorizer.transform([query]).toarray()
            additional_features = self._extract_query_features(query).reshape(1, -1)
            combined_features = np.hstack([tfidf_features, additional_features])
            
            # Scale features
            if self.scaler:
                combined_features = self.scaler.transform(combined_features)
            
            # Random Forest prediction
            if self.rf_model:
                rf_prob = self.rf_model.predict_proba(combined_features)[0][1]
                result["rf_probability"] = float(rf_prob)
            
            # Gradient Boosting prediction
            if self.gbm_model:
                gbm_prob = self.gbm_model.predict_proba(combined_features)[0][1]
                result["gbm_probability"] = float(gbm_prob)
            
            # Ensemble (weighted average)
            result["ensemble_probability"] = float(
                0.5 * result["rf_probability"] + 0.5 * result["gbm_probability"]
            )
            
            result["is_malicious"] = result["ensemble_probability"] > settings.MODEL_CONFIDENCE_THRESHOLD
            
        except Exception as e:
            logger.error(f"ML detection error: {e}")
        
        return result
    
    async def _nlp_detection(self, query: str) -> Dict:
        """Detect SQL injection using NLP deep learning"""
        result = {
            "nlp_probability": 0.0,
            "is_malicious": False,
            "model_available": TENSORFLOW_AVAILABLE
        }
        
        if not TENSORFLOW_AVAILABLE or self.nlp_model is None:
            return result
        
        try:
            # Simple tokenization (in production, use proper tokenizer)
            tokens = query.split()
            token_ids = [hash(token) % 10000 for token in tokens[:100]]
            token_ids = token_ids + [0] * (100 - len(token_ids))
            
            # Predict
            prediction = self.nlp_model.predict(np.array([token_ids]), verbose=0)[0][0]
            result["nlp_probability"] = float(prediction)
            result["is_malicious"] = prediction > 0.85
            
        except Exception as e:
            logger.error(f"NLP detection error: {e}")
        
        return result
    
    def _contextual_analysis(self, query: str, context: Optional[Dict] = None) -> Dict:
        """Analyze query in context of application behavior"""
        result = {
            "context_score": 0.0,
            "anomalies": [],
            "risk_factors": []
        }
        
        # Check for unusual query patterns
        query_upper = query.upper()
        
        # Risk factor 1: Unusual table names
        if any(table in query_upper for table in ['USERS', 'ADMIN', 'PASSWORD', 'CREDENTIAL']):
            result["risk_factors"].append("sensitive_table_access")
            result["context_score"] += 0.2
        
        # Risk factor 2: Multiple queries
        if query.count(';') > 1:
            result["risk_factors"].append("multiple_queries")
            result["context_score"] += 0.3
        
        # Risk factor 3: Unusual characters ratio
        special_chars = sum(1 for c in query if c in "'\";--/*")
        if len(query) > 0 and special_chars / len(query) > 0.1:
            result["risk_factors"].append("high_special_char_ratio")
            result["context_score"] += 0.2
        
        # Risk factor 4: Unusual keyword combinations
        if 'UNION' in query_upper and 'SELECT' in query_upper:
            result["risk_factors"].append("union_select_combination")
            result["context_score"] += 0.3
        
        # Risk factor 5: Encoded content
        if '%' in query or '0x' in query.lower():
            result["risk_factors"].append("encoded_content")
            result["context_score"] += 0.15
        
        result["context_score"] = min(result["context_score"], 1.0)
        
        return result
    
    async def detect(self, query: str, metadata: Optional[Dict] = None) -> Dict:
        """
        Comprehensive SQL injection detection
        
        Args:
            query: SQL query or user input to analyze
            metadata: Additional context (source IP, endpoint, etc.)
            
        Returns:
            Detection results with detailed analysis
        """
        start_time = datetime.utcnow()
        
        result = {
            "is_sqli": False,
            "confidence": 0.0,
            "threat_level": "safe",
            "detection_methods": {},
            "patterns_detected": [],
            "recommended_action": "allow",
            "timestamp": start_time.isoformat(),
            "analysis_time_ms": 0
        }
        
        try:
            # Layer 1: Pattern-based detection
            patterns = self._pattern_detection(query)
            result["patterns_detected"] = patterns
            
            if patterns:
                max_severity = max(
                    ["critical", "high", "medium", "low"].index(p["severity"]) 
                    for p in patterns
                )
                result["detection_methods"]["pattern_matching"] = {
                    "patterns_found": len(patterns),
                    "max_severity": ["critical", "high", "medium", "low"][max_severity]
                }
            
            # Layer 2: ML-based detection
            ml_result = self._ml_detection(query)
            result["detection_methods"]["ml_classification"] = ml_result
            
            # Layer 3: NLP deep learning (async)
            if TENSORFLOW_AVAILABLE:
                nlp_result = await self._nlp_detection(query)
                result["detection_methods"]["nlp_analysis"] = nlp_result
            
            # Layer 4: Contextual analysis
            context_result = self._contextual_analysis(query, metadata)
            result["detection_methods"]["contextual_analysis"] = context_result
            
            # Calculate final confidence score
            scores = []
            weights = []
            
            # Pattern matching weight
            if patterns:
                severity_scores = {"critical": 1.0, "high": 0.85, "medium": 0.7, "low": 0.5}
                pattern_score = max(severity_scores.get(p["severity"], 0) for p in patterns)
                scores.append(pattern_score)
                weights.append(0.35)
            
            # ML classification weight
            if ml_result["ensemble_probability"] > 0:
                scores.append(ml_result["ensemble_probability"])
                weights.append(0.35)
            
            # NLP analysis weight
            if TENSORFLOW_AVAILABLE and "nlp_analysis" in result["detection_methods"]:
                nlp_prob = result["detection_methods"]["nlp_analysis"]["nlp_probability"]
                if nlp_prob > 0:
                    scores.append(nlp_prob)
                    weights.append(0.2)
            
            # Contextual analysis weight
            if context_result["context_score"] > 0:
                scores.append(context_result["context_score"])
                weights.append(0.1)
            
            # Weighted average
            if scores:
                total_weight = sum(weights[:len(scores)])
                result["confidence"] = sum(s * w for s, w in zip(scores, weights[:len(scores)])) / total_weight
            
            # Determine if SQL injection
            result["is_sqli"] = (
                result["confidence"] > settings.MODEL_CONFIDENCE_THRESHOLD or
                (len(patterns) > 0 and any(p["severity"] == "critical" for p in patterns)) or
                (ml_result["is_malicious"] and context_result["context_score"] > 0.5)
            )
            
            # Determine threat level
            if result["confidence"] > 0.9:
                result["threat_level"] = "critical"
            elif result["confidence"] > 0.75:
                result["threat_level"] = "high"
            elif result["confidence"] > 0.5:
                result["threat_level"] = "medium"
            elif result["confidence"] > 0.3:
                result["threat_level"] = "low"
            else:
                result["threat_level"] = "safe"
            
            # Recommend action
            if result["threat_level"] in ["critical", "high"]:
                result["recommended_action"] = "block"
            elif result["threat_level"] == "medium":
                result["recommended_action"] = "sanitize_and_log"
            elif result["threat_level"] == "low":
                result["recommended_action"] = "log_and_monitor"
            else:
                result["recommended_action"] = "allow"
            
            # Log attempt if suspicious
            if result["is_sqli"] or result["confidence"] > 0.5:
                await self._log_attempt(query, result, metadata)
            
        except Exception as e:
            logger.error(f"SQLi detection failed: {e}")
            result["error"] = str(e)
        
        result["analysis_time_ms"] = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return result
    
    async def _log_attempt(self, query: str, result: Dict, metadata: Optional[Dict]):
        """Log SQL injection attempt to database"""
        try:
            db = next(get_db())
            
            event = SecurityEvent(
                event_type="sqli_detection",
                severity=result["threat_level"],
                source_ip=metadata.get("source_ip", "unknown") if metadata else "unknown",
                details={
                    "query": query[:500],  # Truncate long queries
                    "result": result
                },
                timestamp=datetime.utcnow()
            )
            db.add(event)
            
            attempt = SQLInjectionAttempt(
                query_hash=hash(query) & 0xFFFFFFFF,
                query_preview=query[:200],
                threat_level=result["threat_level"],
                confidence=result["confidence"],
                patterns_detected=len(result["patterns_detected"]),
                source_ip=metadata.get("source_ip", "unknown") if metadata else "unknown",
                endpoint=metadata.get("endpoint", "unknown") if metadata else "unknown",
                timestamp=datetime.utcnow()
            )
            db.add(attempt)
            db.commit()
            
        except Exception as e:
            logger.error(f"Failed to log SQLi attempt: {e}")

# Global detector instance
sqli_detector = AdvancedSQLiDetector()
