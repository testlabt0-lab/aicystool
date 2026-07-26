"""
SQL Injection Detection System using NLP
Analyzes database queries to detect SQL injection attacks using Natural Language Processing
"""

import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os


class SQLQueryAnalyzer:
    """Analyze SQL queries for potential injection attacks"""
    
    # SQL Injection patterns and keywords
    INJECTION_PATTERNS = [
        r"(\bOR\b\s+\d+\s*=\s*\d+)",  # OR 1=1
        r"(\bAND\b\s+\d+\s*=\s*\d+)",  # AND 1=1
        r"(--\s*$)",  # SQL comment
        r"(;\s*DROP\s+TABLE)",  # DROP TABLE
        r"(;\s*DELETE\s+FROM)",  # DELETE FROM
        r"(UNION\s+SELECT)",  # UNION SELECT
        r"(INSERT\s+INTO)",  # INSERT INTO
        r"(UPDATE\s+.*\s+SET)",  # UPDATE SET
        r"(\bEXEC\s+\()",  # EXEC()
        r"(\bxp_cmdshell\b)",  # xp_cmdshell
        r"(\bWAITFOR\b\s+\bDELAY\b)",  # Time-based injection
        r"(\bBENCHMARK\b\s*\()",  # BENCHMARK()
        r"(\bSLEEP\b\s*\()",  # SLEEP()
        r"(\bLOAD_FILE\b\s*\()",  # LOAD_FILE()
        r"(\bINTO\s+OUTFILE\b)",  # INTO OUTFILE
        r"(\'.*\bOR\b.*\')",  # String-based OR
        r"(\'.*\bAND\b.*\')",  # String-based AND
    ]
    
    SUSPICIOUS_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION',
        'EXEC', 'EXECUTE', 'xp_', 'sp_', 'WAITFOR', 'BENCHMARK',
        'SLEEP', 'LOAD_FILE', 'OUTFILE', 'DUMPFILE', 'CHAR(',
        'CONCAT(', 'SUBSTRING(', 'ASCII(', 'HEX(', 'UNHEX('
    ]
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 3),
            analyzer='char_wb'
        )
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
        self.is_trained = False
    
    def extract_features(self, query):
        """
        Extract features from SQL query
        
        Args:
            query: SQL query string
            
        Returns:
            Dictionary of features
        """
        features = {
            'query_length': len(query),
            'special_char_count': len(re.findall(r'[\'";\-_=<>]', query)),
            'comment_count': len(re.findall(r'(--|#|/\*)', query)),
            'keyword_count': sum(1 for kw in self.SUSPICIOUS_KEYWORDS 
                               if kw.upper() in query.upper()),
            'pattern_matches': sum(1 for pattern in self.INJECTION_PATTERNS 
                                  if re.search(pattern, query, re.IGNORECASE)),
            'quote_balance': query.count("'") % 2,  # Unbalanced quotes
            'semicolon_count': query.count(';'),
            'space_ratio': query.count(' ') / max(len(query), 1),
            'uppercase_ratio': sum(1 for c in query if c.isupper()) / max(len(query), 1),
        }
        
        return features
    
    def has_injection_pattern(self, query):
        """Check if query matches known injection patterns"""
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                return True
        return False
    
    def prepare_dataset(self, queries, labels):
        """
        Prepare dataset for training
        
        Args:
            queries: List of SQL query strings
            labels: List of labels (0=safe, 1=injection)
            
        Returns:
            Feature matrix and labels
        """
        # Extract text features using TF-IDF
        X_tfidf = self.vectorizer.fit_transform(queries).toarray()
        
        # Extract statistical features
        stat_features = []
        for query in queries:
            features = self.extract_features(query)
            stat_features.append(list(features.values()))
        
        X_stat = np.array(stat_features)
        
        # Combine features
        X = np.hstack([X_tfidf, X_stat])
        
        return X, np.array(labels)
    
    def train(self, queries, labels):
        """
        Train the SQL injection detection model
        
        Args:
            queries: List of SQL query strings
            labels: List of labels (0=safe, 1=injection)
            
        Returns:
            Trained model
        """
        X, y = self.prepare_dataset(queries, labels)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        print("Model Training Results:")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        return self.model
    
    def predict(self, query):
        """
        Predict if a query is SQL injection
        
        Args:
            query: SQL query string
            
        Returns:
            Prediction (0=safe, 1=injection), confidence, and risk analysis
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        # Check for known patterns first
        has_pattern = self.has_injection_pattern(query)
        
        # Transform query using trained vectorizer
        X_tfidf = self.vectorizer.transform([query]).toarray()
        
        # Extract statistical features
        stat_features = list(self.extract_features(query).values())
        X_stat = np.array([stat_features])
        
        # Combine features
        X = np.hstack([X_tfidf, X_stat])
        
        # Make prediction
        prediction = self.model.predict(X)[0]
        confidence = self.model.predict_proba(X)[0][prediction]
        
        # Risk analysis
        risk_analysis = {
            'has_known_pattern': has_pattern,
            'features': self.extract_features(query),
            'matched_patterns': [p for p in self.INJECTION_PATTERNS 
                                if re.search(p, query, re.IGNORECASE)]
        }
        
        return prediction, confidence, risk_analysis
    
    def save_model(self, filepath='sql_injection_model.pkl'):
        """Save the trained model"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer,
        }
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath='sql_injection_model.pkl'):
        """Load a pre-trained model"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file {filepath} not found")
        
        model_data = joblib.load(filepath)
        self.model = model_data['model']
        self.vectorizer = model_data['vectorizer']
        self.is_trained = True
        print(f"Model loaded from {filepath}")


def generate_sample_queries():
    """Generate sample SQL queries for training"""
    
    # Safe queries
    safe_queries = [
        "SELECT * FROM users WHERE id = 1",
        "SELECT name, email FROM customers WHERE city = 'New York'",
        "INSERT INTO orders (user_id, product_id) VALUES (5, 10)",
        "UPDATE products SET price = 99.99 WHERE id = 3",
        "DELETE FROM cart WHERE user_id = 7",
        "SELECT COUNT(*) FROM transactions WHERE date > '2024-01-01'",
        "SELECT * FROM articles WHERE category = 'technology' ORDER BY date DESC",
        "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
        "SELECT AVG(price) FROM products WHERE stock > 0",
        "SELECT DISTINCT country FROM customers",
        "SELECT * FROM employees WHERE department = 'IT' AND salary > 50000",
        "UPDATE users SET last_login = NOW() WHERE id = 42",
        "SELECT title, content FROM posts WHERE author_id = 15 LIMIT 10",
        "INSERT INTO logs (action, timestamp) VALUES ('login', '2024-01-15')",
        "SELECT * FROM inventory WHERE quantity < 100",
    ]
    
    # SQL injection queries
    injection_queries = [
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "SELECT * FROM users WHERE name = '' OR '1'='1'",
        "SELECT * FROM products WHERE id = 1; DROP TABLE users--",
        "SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin",
        "SELECT * FROM items WHERE price = 100; DELETE FROM orders--",
        "SELECT * FROM users WHERE name = 'admin'--",
        "SELECT * FROM data WHERE id = 1 AND 1=1 UNION SELECT * FROM passwords",
        "'; EXEC xp_cmdshell('dir'); --",
        "SELECT * FROM users WHERE id = 1 WAITFOR DELAY '0:0:5'",
        "SELECT * FROM products WHERE name = '' UNION SELECT table_name, NULL FROM information_schema.tables--",
        "1'; INSERT INTO users (username, password) VALUES ('hacker', 'pass123');--",
        "SELECT * FROM users WHERE id = 1 BENCHMARK(10000000, SHA1('test'))",
        "SELECT LOAD_FILE('/etc/passwd')",
        "SELECT * FROM users INTO OUTFILE '/tmp/users.txt'",
        "admin' AND '1'='1' UNION SELECT username, password FROM users--",
        "SELECT * FROM orders WHERE id = 1; UPDATE users SET role='admin' WHERE username='hacker'--",
        "1' OR '1'='1' /*",
        "SELECT * FROM users WHERE id = CHAR(49)",
        "' OR 1=1--",
        "admin'--",
    ]
    
    queries = safe_queries + injection_queries
    labels = [0] * len(safe_queries) + [1] * len(injection_queries)
    
    return queries, labels


if __name__ == "__main__":
    print("=" * 60)
    print("SQL Injection Detection System using NLP")
    print("=" * 60)
    
    # Initialize analyzer
    analyzer = SQLQueryAnalyzer()
    
    # Generate training data
    print("\nGenerating sample SQL queries...")
    queries, labels = generate_sample_queries()
    
    # Augment data (repeat for better training)
    queries *= 10
    labels *= 10
    
    # Train model
    print("Training model...")
    analyzer.train(queries, labels)
    
    # Save model
    analyzer.save_model('sql_injection_model.pkl')
    
    # Test with sample queries
    print("\n" + "=" * 60)
    print("Testing with sample queries:")
    print("=" * 60)
    
    test_queries = [
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "SELECT name FROM customers WHERE city = 'Boston'",
        "'; DROP TABLE users;--",
        "UPDATE products SET price = 50 WHERE id = 5",
        "admin' UNION SELECT password FROM users--"
    ]
    
    for query in test_queries:
        prediction, confidence, analysis = analyzer.predict(query)
        status = "⚠️  SQL INJECTION DETECTED" if prediction == 1 else "✓ Safe Query"
        print(f"\nQuery: {query}")
        print(f"Prediction: {status}")
        print(f"Confidence: {confidence:.2%}")
        print(f"Has Known Pattern: {analysis['has_known_pattern']}")
    
    print("\n" + "=" * 60)
    print("System ready for deployment!")
    print("=" * 60)
