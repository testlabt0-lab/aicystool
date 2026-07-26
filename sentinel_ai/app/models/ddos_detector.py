import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


class DDoSDetectionModel:
    """
    Production-ready DDoS detection using Random Forest with ensemble methods.
    Detects various attack types: SYN Flood, UDP Flood, HTTP Flood, etc.
    """
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or "./models/ddos_model.pkl"
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Feature names for network traffic analysis
        self.feature_names = [
            'packet_rate', 'byte_rate', 'unique_sources', 'unique_destinations',
            'syn_ratio', 'ack_ratio', 'fin_ratio', 'rst_ratio',
            'avg_packet_size', 'variance_packet_size',
            'entropy_source_ip', 'entropy_dest_port',
            'connection_rate', 'failed_connection_ratio',
            'icmp_ratio', 'udp_ratio', 'tcp_ratio'
        ]
        
    def extract_features(self, traffic_data: Dict) -> np.ndarray:
        """
        Extract features from raw network traffic data.
        
        Args:
            traffic_data: Dictionary containing network metrics
            
        Returns:
            Feature vector as numpy array
        """
        features = []
        
        # Packet statistics
        features.append(traffic_data.get('packets_per_second', 0))
        features.append(traffic_data.get('bytes_per_second', 0))
        features.append(traffic_data.get('unique_source_ips', 1))
        features.append(traffic_data.get('unique_dest_ips', 1))
        
        # TCP flag ratios
        flags = traffic_data.get('flags', {})
        total_flags = sum(flags.values()) + 1e-6
        features.append(flags.get('SYN', 0) / total_flags)
        features.append(flags.get('ACK', 0) / total_flags)
        features.append(flags.get('FIN', 0) / total_flags)
        features.append(flags.get('RST', 0) / total_flags)
        
        # Packet size statistics
        features.append(traffic_data.get('avg_packet_size', 0))
        features.append(traffic_data.get('variance_packet_size', 0))
        
        # Entropy calculations (measure of randomness)
        features.append(traffic_data.get('source_ip_entropy', 0))
        features.append(traffic_data.get('dest_port_entropy', 0))
        
        # Connection metrics
        features.append(traffic_data.get('connections_per_second', 0))
        features.append(traffic_data.get('failed_connections_ratio', 0))
        
        # Protocol distribution
        features.append(traffic_data.get('icmp_ratio', 0))
        features.append(traffic_data.get('udp_ratio', 0))
        features.append(traffic_data.get('tcp_ratio', 0))
        
        return np.array(features).reshape(1, -1)
    
    def train(self, X: np.ndarray, y: np.ndarray):
        """
        Train the Random Forest model.
        
        Args:
            X: Feature matrix
            y: Labels (0=benign, 1=attack)
        """
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled, y)
        self.is_trained = True
        
        logger.info(f"DDoS model trained with {len(X)} samples")
        
    def predict(self, traffic_data: Dict) -> Dict:
        """
        Predict if traffic is a DDoS attack.
        
        Args:
            traffic_data: Network traffic metrics
            
        Returns:
            Prediction result with confidence and risk level
        """
        if not self.is_trained:
            self._load_model()
        
        features = self.extract_features(traffic_data)
        features_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        
        confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
        
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
        attack_type = self._classify_attack_type(features, traffic_data)
        
        return {
            "is_attack": bool(prediction),
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "attack_type": attack_type,
            "details": {
                "packet_rate": traffic_data.get('packets_per_second', 0),
                "byte_rate": traffic_data.get('bytes_per_second', 0),
                "unique_sources": traffic_data.get('unique_source_ips', 0)
            }
        }
    
    def _classify_attack_type(self, features: np.ndarray, traffic_data: Dict) -> str:
        """Classify the specific type of DDoS attack."""
        flags = traffic_data.get('flags', {})
        
        if flags.get('SYN', 0) > flags.get('ACK', 0) * 2:
            return "SYN Flood"
        elif traffic_data.get('udp_ratio', 0) > 0.8:
            return "UDP Flood"
        elif traffic_data.get('packets_per_second', 0) > 10000:
            return "HTTP Flood"
        elif traffic_data.get('icmp_ratio', 0) > 0.5:
            return "ICMP Flood"
        else:
            return "Volumetric Attack"
    
    def _load_model(self):
        """Load pre-trained model from disk."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.scaler = data['scaler']
                    self.is_trained = True
                logger.info(f"Loaded DDoS model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self._initialize_default_model()
        else:
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize a default model for demonstration."""
        # Create synthetic training data for initialization
        np.random.seed(42)
        
        # Benign traffic patterns
        benign_X = np.random.randn(500, len(self.feature_names)) * 0.5
        benign_X[:, 0] = np.random.uniform(100, 1000, 500)  # packet_rate
        benign_X[:, 1] = np.random.uniform(10000, 100000, 500)  # byte_rate
        
        # Attack traffic patterns
        attack_X = np.random.randn(500, len(self.feature_names)) * 0.5
        attack_X[:, 0] = np.random.uniform(5000, 50000, 500)  # high packet_rate
        attack_X[:, 1] = np.random.uniform(500000, 5000000, 500)  # high byte_rate
        attack_X[:, 5] = np.random.uniform(0.7, 1.0, 500)  # high SYN ratio
        
        X = np.vstack([benign_X, attack_X])
        y = np.array([0] * 500 + [1] * 500)
        
        self.train(X, y)
        logger.info("Initialized default DDoS detection model")
    
    def save_model(self):
        """Save trained model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({'model': self.model, 'scaler': self.scaler}, f)
        logger.info(f"Saved DDoS model to {self.model_path}")


# Global instance
ddos_detector = DDoSDetectionModel()
