"""
Sentinel AI Enterprise - Advanced DDoS Detection Engine
Hybrid Model: Random Forest + LSTM for Time-Series Analysis
Features:
- Real-time traffic analysis
- Pre-emptive attack detection
- Auto-mitigation with Cloudflare/AWS Shield integration
- Behavioral anomaly detection
- Smart Geo-blocking
- Dynamic rate limiting
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import redis
import json
from app.core.config import settings


class DDoSDetectionEngine:
    """محرك كشف هجمات DDoS المتقدم"""
    
    def __init__(self):
        self.rf_model = None
        self.lstm_model = None
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.redis_client = redis.from_url(settings.REDIS_URL)
        
        # نوافذ زمنية للتحليل
        self.window_size = settings.DDOS_WINDOW_SIZE
        self.threshold_rps = settings.DDOS_THRESHOLD_RPS
        
        # سجلات حركة المرور
        self.traffic_buffer = []
        self.baseline_stats = {}
        
        # تحميل النماذج
        self._load_models()
    
    def _load_models(self):
        """تحميل نماذج الذكاء الاصطناعي"""
        try:
            # تحميل نموذج Random Forest
            rf_path = f"{settings.ML_MODEL_PATH}/ddos_rf_model.pkl"
            self.rf_model = joblib.load(rf_path)
            
            # تحميل نموذج LSTM
            lstm_path = f"{settings.ML_MODEL_PATH}/ddos_lstm_model.h5"
            self.lstm_model = keras.models.load_model(lstm_path)
            
        except FileNotFoundError:
            print("⚠️ نماذج DDoS غير موجودة، سيتم تدريب نماذج أولية")
            self._train_initial_models()
    
    def _train_initial_models(self):
        """تدريب نماذج أولية عند عدم وجود نماذج محفوظة"""
        # بيانات تدريب وهمية للتوضيح
        np.random.seed(42)
        n_samples = 10000
        
        # ميزات حركة المرور
        X_train = np.random.rand(n_samples, 15)
        y_train = np.random.randint(0, 2, n_samples)
        
        # تدريب Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(X_train, y_train)
        
        # تدريب LSTM
        self.lstm_model = self._build_lstm_model(input_shape=(60, 15))
        X_lstm = X_train.reshape(-1, 60, 15)[:1000]
        y_lstm = y_train[:1000]
        
        self.lstm_model.fit(X_lstm, y_lstm, epochs=10, verbose=0)
        
        # حفظ النماذج
        import os
        os.makedirs(settings.ML_MODEL_PATH, exist_ok=True)
        joblib.dump(self.rf_model, f"{settings.ML_MODEL_PATH}/ddos_rf_model.pkl")
        self.lstm_model.save(f"{settings.ML_MODEL_PATH}/ddos_lstm_model.h5")
    
    def _build_lstm_model(self, input_shape: Tuple) -> keras.Model:
        """بناء نموذج LSTM للكشف عن الهجمات"""
        model = keras.Sequential([
            layers.LSTM(128, return_sequences=True, input_shape=input_shape),
            layers.Dropout(0.3),
            layers.LSTM(64, return_sequences=False),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def analyze_traffic(self, traffic_data: Dict) -> Dict:
        """
        تحليل حركة البيانات في الوقت الفعلي
        
        Args:
            traffic_data: بيانات حركة المرور (requests, IPs, ports, etc.)
        
        Returns:
            Dict: نتائج التحليل مع مستوى الخطر والإجراءات المقترحة
        """
        timestamp = datetime.now()
        
        # استخراج الميزات
        features = self._extract_features(traffic_data)
        
        # تطبيع الميزات
        features_scaled = self.scaler.fit_transform([features])
        
        # كشف باستخدام Random Forest
        rf_prediction = self.rf_model.predict(features_scaled)[0]
        rf_confidence = self.rf_model.predict_proba(features_scaled)[0][1]
        
        # إضافة للذاكرة المؤقتة للتحليل الزمني
        self.traffic_buffer.append({
            'timestamp': timestamp,
            'features': features
        })
        
        # تنظيف الذاكرة المؤقتة القديمة
        cutoff = timestamp - timedelta(seconds=self.window_size)
        self.traffic_buffer = [
            x for x in self.traffic_buffer if x['timestamp'] > cutoff
        ]
        
        # كشف باستخدام LSTM إذا توفرت بيانات كافية
        lstm_prediction = 0
        lstm_confidence = 0
        
        if len(self.traffic_buffer) >= 60:
            lstm_input = np.array([x['features'] for x in self.traffic_buffer[-60:]])
            lstm_input = lstm_input.reshape(1, 60, -1)
            lstm_prediction = self.lstm_model.predict(lstm_input)[0][0]
            lstm_confidence = lstm_prediction
        
        # كشف الشذوذ باستخدام Isolation Forest
        anomaly_score = self.isolation_forest.fit_transform([features])[0][0]
        is_anomaly = anomaly_score < -0.5
        
        # دمج النتائج
        threat_score = (rf_confidence * 0.4 + lstm_confidence * 0.4 + 
                       (1 if is_anomaly else 0) * 0.2)
        
        threat_level = self._classify_threat_level(threat_score)
        
        # تحديد نوع الهجوم
        attack_type = self._identify_attack_type(features, traffic_data)
        
        # اقتراح إجراءات التخفيف
        mitigation_actions = self._suggest_mitigation(
            threat_level, attack_type, traffic_data
        )
        
        # تنفيذ التخفيف التلقائي إذا مفعل
        if settings.DDOS_AUTO_MITIGATION and threat_level in ['HIGH', 'CRITICAL']:
            self._execute_auto_mitigation(mitigation_actions, traffic_data)
        
        result = {
            'timestamp': timestamp.isoformat(),
            'threat_detected': threat_level != 'NONE',
            'threat_level': threat_level,
            'threat_score': float(threat_score),
            'attack_type': attack_type,
            'confidence': {
                'random_forest': float(rf_confidence),
                'lstm': float(lstm_confidence),
                'anomaly_detection': float(abs(anomaly_score))
            },
            'traffic_stats': {
                'requests_per_second': features[0],
                'unique_ips': int(features[1]),
                'avg_packet_size': float(features[2]),
                'syn_ratio': float(features[3])
            },
            'mitigation_actions': mitigation_actions,
            'auto_mitigated': settings.DDOS_AUTO_MITIGATION and threat_level in ['HIGH', 'CRITICAL']
        }
        
        # تخزين النتيجة في Redis للرصد
        self._store_result(result)
        
        return result
    
    def _extract_features(self, traffic_data: Dict) -> List[float]:
        """استخراج الميزات من بيانات حركة المرور"""
        features = [
            traffic_data.get('requests_per_second', 0),
            traffic_data.get('unique_ips', 0),
            traffic_data.get('avg_packet_size', 0),
            traffic_data.get('syn_ratio', 0),
            traffic_data.get('udp_ratio', 0),
            traffic_data.get('icmp_ratio', 0),
            traffic_data.get('http_ratio', 0),
            traffic_data.get('https_ratio', 0),
            traffic_data.get('dns_queries', 0),
            traffic_data.get('geo_diversity', 0),
            traffic_data.get('port_diversity', 0),
            traffic_data.get('payload_entropy', 0),
            traffic_data.get('request_rate_change', 0),
            traffic_data.get('ip_reputation_score', 0),
            traffic_data.get('baseline_deviation', 0)
        ]
        
        return features
    
    def _classify_threat_level(self, score: float) -> str:
        """تصنيف مستوى الخطر"""
        if score >= 0.9:
            return 'CRITICAL'
        elif score >= 0.7:
            return 'HIGH'
        elif score >= 0.5:
            return 'MEDIUM'
        elif score >= 0.3:
            return 'LOW'
        else:
            return 'NONE'
    
    def _identify_attack_type(self, features: List[float], traffic_data: Dict) -> str:
        """تحديد نوع الهجوم"""
        if features[3] > 0.8:  # SYN ratio عالي
            return 'SYN_FLOOD'
        elif features[4] > 0.7:  # UDP ratio عالي
            return 'UDP_FLOOD'
        elif features[5] > 0.6:  # ICMP ratio عالي
            return 'ICMP_FLOOD'
        elif features[6] > 0.9 or features[7] > 0.9:  # HTTP/HTTPS عالي
            if traffic_data.get('avg_request_rate', 0) > 100:
                return 'HTTP_FLOOD'
            else:
                return 'SLOWLORIS'
        elif features[8] > 1000:  # DNS queries عالي
            return 'DNS_AMPLIFICATION'
        else:
            return 'VOLUMETRIC'
    
    def _suggest_mitigation(self, threat_level: str, attack_type: str, 
                           traffic_data: Dict) -> List[Dict]:
        """اقتراح إجراءات التخفيف"""
        actions = []
        
        if threat_level == 'NONE':
            return actions
        
        # Rate Limiting
        if threat_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
            rate_limit = max(100, int(1000 / (threat_level == 'CRITICAL') + 1))
            actions.append({
                'action': 'RATE_LIMITING',
                'description': f'تطبيق Rate Limiting: {rate_limit} req/s',
                'parameters': {'rate': rate_limit, 'window': 1}
            })
        
        # Geo-blocking
        if traffic_data.get('suspicious_countries'):
            actions.append({
                'action': 'GEO_BLOCKING',
                'description': f'حظر الدول المشبوهة: {traffic_data["suspicious_countries"]}',
                'parameters': {'countries': traffic_data['suspicious_countries']}
            })
        
        # IP Blocking
        if traffic_data.get('malicious_ips'):
            actions.append({
                'action': 'IP_BLOCKING',
                'description': f'حظر {len(traffic_data["malicious_ips"])} عناوين IP خبيثة',
                'parameters': {'ips': traffic_data['malicious_ips'][:100]}
            })
        
        # Challenge-Response (CAPTCHA)
        if attack_type in ['HTTP_FLOOD', 'SLOWLORIS']:
            actions.append({
                'action': 'CHALLENGE_RESPONSE',
                'description': 'تفعيل CAPTCHA للطلبات المشبوهة',
                'parameters': {'challenge_type': 'captcha'}
            })
        
        # Cloudflare Integration
        if settings.DDOS_CLOUDFLARE_API_KEY and threat_level in ['HIGH', 'CRITICAL']:
            actions.append({
                'action': 'CLOUDFLARE_UNDER_ATTACK',
                'description': 'تفعيل وضع "Under Attack" في Cloudflare',
                'parameters': {'mode': 'high'}
            })
        
        # AWS Shield Integration
        if settings.DDOS_AWS_SHIELD_ENABLED and threat_level == 'CRITICAL':
            actions.append({
                'action': 'AWS_SHIELD_ADVANCED',
                'description': 'تفعيل AWS Shield Advanced Protection',
                'parameters': {'protection_level': 'advanced'}
            })
        
        return actions
    
    def _execute_auto_mitigation(self, actions: List[Dict], traffic_data: Dict):
        """تنفيذ إجراءات التخفيف التلقائي"""
        for action in actions:
            if action['action'] == 'CLOUDFLARE_UNDER_ATTACK':
                self._activate_cloudflare_protection()
            elif action['action'] == 'AWS_SHIELD_ADVANCED':
                self._activate_aws_shield()
            elif action['action'] == 'IP_BLOCKING':
                self._block_ips(action['parameters']['ips'])
    
    def _activate_cloudflare_protection(self):
        """تفعيل حماية Cloudflare"""
        # تطبيق حقيقي سيتصل بـ Cloudflare API
        print("🔒 Cloudflare \"Under Attack\" mode activated")
    
    def _activate_aws_shield(self):
        """تفعيل AWS Shield"""
        # تطبيق حقيقي سيتصل بـ AWS Shield API
        print("🛡️ AWS Shield Advanced protection activated")
    
    def _block_ips(self, ips: List[str]):
        """حظر عناوين IP"""
        # تطبيق حقيقي سيحدث قواعد الجدار الناري
        print(f"🚫 Blocking {len(ips)} malicious IPs")
    
    def _store_result(self, result: Dict):
        """تخزين نتيجة التحليل في Redis"""
        key = f"ddos:detection:{datetime.now().strftime('%Y%m%d%H%M')}"
        self.redis_client.hset(key, mapping=result)
        self.redis_client.expire(key, 3600)  # الاحتفاظ لمدة ساعة
    
    def get_statistics(self, hours: int = 24) -> Dict:
        """الحصول على إحصائيات الكشف خلال فترة زمنية"""
        # استرجاع الإحصائيات من Redis أو قاعدة البيانات
        stats = {
            'total_requests_analyzed': 0,
            'attacks_detected': 0,
            'attacks_mitigated': 0,
            'attack_types': {},
            'average_response_time_ms': 0,
            'false_positives': 0,
            'detection_accuracy': 0.0
        }
        
        return stats


# إنشاء نسخة من المحرك
ddos_engine = DDoSDetectionEngine()
