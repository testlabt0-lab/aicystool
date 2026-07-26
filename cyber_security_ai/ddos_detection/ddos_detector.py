"""
DDoS Detection System using Machine Learning
Uses Random Forest classifier to detect DDoS attacks in network traffic
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

class DDoSDetector:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        self.feature_columns = [
            'packet_size', 'packet_rate', 'source_ip_count',
            'destination_port_variance', 'protocol_distribution',
            'syn_flag_count', 'ack_flag_count', 'fin_flag_count',
            'avg_packet_interval', 'entropy_source_ip'
        ]
        self.is_trained = False
    
    def extract_features(self, network_data):
        """
        Extract features from network traffic data
        
        Args:
            network_data: dict or DataFrame containing network traffic information
            
        Returns:
            Feature array for model prediction
        """
        if isinstance(network_data, dict):
            features = np.array([[
                network_data.get('packet_size', 0),
                network_data.get('packet_rate', 0),
                network_data.get('source_ip_count', 0),
                network_data.get('destination_port_variance', 0),
                network_data.get('protocol_distribution', 0),
                network_data.get('syn_flag_count', 0),
                network_data.get('ack_flag_count', 0),
                network_data.get('fin_flag_count', 0),
                network_data.get('avg_packet_interval', 0),
                network_data.get('entropy_source_ip', 0)
            ]])
        else:
            features = network_data[self.feature_columns].values
        
        return features
    
    def train(self, training_data, labels):
        """
        Train the DDoS detection model
        
        Args:
            training_data: Features matrix (n_samples, n_features)
            labels: Target vector (n_samples,) - 0 for normal, 1 for DDoS
        """
        X_train, X_test, y_train, y_test = train_test_split(
            training_data, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        print("Model Training Results:")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        return self.model
    
    def predict(self, network_data):
        """
        Predict if network traffic is a DDoS attack
        
        Args:
            network_data: Network traffic data
            
        Returns:
            Prediction (0=normal, 1=DDoS) and confidence score
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        features = self.extract_features(network_data)
        prediction = self.model.predict(features)[0]
        confidence = self.model.predict_proba(features)[0][prediction]
        
        return prediction, confidence
    
    def save_model(self, filepath='ddos_model.pkl'):
        """Save the trained model to disk"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        joblib.dump(self.model, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath='ddos_model.pkl'):
        """Load a pre-trained model from disk"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file {filepath} not found")
        self.model = joblib.load(filepath)
        self.is_trained = True
        print(f"Model loaded from {filepath}")


def generate_sample_data(n_samples=1000):
    """
    Generate synthetic network traffic data for training
    
    Returns:
        Features matrix and labels
    """
    np.random.seed(42)
    
    # Normal traffic characteristics
    normal_data = {
        'packet_size': np.random.normal(500, 200, n_samples//2),
        'packet_rate': np.random.normal(100, 30, n_samples//2),
        'source_ip_count': np.random.normal(50, 20, n_samples//2),
        'destination_port_variance': np.random.normal(10, 5, n_samples//2),
        'protocol_distribution': np.random.normal(0.6, 0.1, n_samples//2),
        'syn_flag_count': np.random.normal(30, 10, n_samples//2),
        'ack_flag_count': np.random.normal(50, 15, n_samples//2),
        'fin_flag_count': np.random.normal(20, 8, n_samples//2),
        'avg_packet_interval': np.random.normal(0.1, 0.03, n_samples//2),
        'entropy_source_ip': np.random.normal(3.5, 0.5, n_samples//2)
    }
    
    # DDoS traffic characteristics
    ddos_data = {
        'packet_size': np.random.normal(200, 100, n_samples//2),
        'packet_rate': np.random.normal(1000, 300, n_samples//2),
        'source_ip_count': np.random.normal(500, 150, n_samples//2),
        'destination_port_variance': np.random.normal(2, 1, n_samples//2),
        'protocol_distribution': np.random.normal(0.9, 0.05, n_samples//2),
        'syn_flag_count': np.random.normal(400, 100, n_samples//2),
        'ack_flag_count': np.random.normal(50, 20, n_samples//2),
        'fin_flag_count': np.random.normal(5, 3, n_samples//2),
        'avg_packet_interval': np.random.normal(0.01, 0.005, n_samples//2),
        'entropy_source_ip': np.random.normal(5.5, 0.3, n_samples//2)
    }
    
    # Combine datasets
    normal_df = pd.DataFrame(normal_data)
    ddos_df = pd.DataFrame(ddos_data)
    
    X = pd.concat([normal_df, ddos_df], ignore_index=True)
    y = np.array([0] * (n_samples//2) + [1] * (n_samples//2))
    
    return X.values, y


if __name__ == "__main__":
    print("=" * 60)
    print("DDoS Detection System using Random Forest")
    print("=" * 60)
    
    # Initialize detector
    detector = DDoSDetector()
    
    # Generate training data
    print("\nGenerating synthetic training data...")
    X, y = generate_sample_data(2000)
    
    # Train model
    print("Training model...")
    detector.train(X, y)
    
    # Save model
    detector.save_model('ddos_model.pkl')
    
    # Test with sample data
    print("\nTesting with sample network traffic...")
    test_traffic = {
        'packet_size': 150,
        'packet_rate': 1200,
        'source_ip_count': 600,
        'destination_port_variance': 1.5,
        'protocol_distribution': 0.95,
        'syn_flag_count': 450,
        'ack_flag_count': 40,
        'fin_flag_count': 3,
        'avg_packet_interval': 0.008,
        'entropy_source_ip': 5.8
    }
    
    prediction, confidence = detector.predict(test_traffic)
    status = "DDoS ATTACK DETECTED" if prediction == 1 else "Normal Traffic"
    print(f"\nPrediction: {status}")
    print(f"Confidence: {confidence:.2%}")
    
    print("\n" + "=" * 60)
    print("System ready for deployment!")
    print("=" * 60)
