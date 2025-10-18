"""
Machine Learning - Anomaly Detection
Detects abnormal network behavior and attack patterns
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
from pathlib import Path
from typing import Dict, List, Tuple

from core.config import settings
from utils.logger import sentinel_logger as logger

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.contamination = 0.1
        self.load_model()
    
    def load_model(self):
        """Load pre-trained anomaly detection model"""
        model_path = settings.MODELS_DIR / "anomaly_detector.pkl"
        try:
            if model_path.exists():
                with open(model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data.get('model')
                    self.scaler = data.get('scaler', StandardScaler())
                logger.info("Anomaly detection model loaded")
            else:
                self.train_default_model()
        except Exception as e:
            logger.error(f"Failed to load anomaly model: {e}")
            self.train_default_model()
    
    def train_default_model(self):
        """Train default model with synthetic data"""
        logger.info("Training default anomaly detection model...")
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        
        # Synthetic normal traffic patterns
        normal_data = np.random.randn(1000, 10)
        self.scaler.fit(normal_data)
        scaled_data = self.scaler.transform(normal_data)
        self.model.fit(scaled_data)
        
        self.save_model()
        logger.info("Default anomaly model trained")
    
    def detect_anomaly(self, features: Dict) -> Tuple[bool, float]:
        """
        Detect if traffic pattern is anomalous
        Returns: (is_anomaly, anomaly_score)
        """
        try:
            feature_vector = self.extract_features(features)
            scaled_features = self.scaler.transform([feature_vector])
            
            prediction = self.model.predict(scaled_features)[0]
            anomaly_score = self.model.score_samples(scaled_features)[0]
            
            is_anomaly = prediction == -1
            confidence = abs(anomaly_score)
            
            return is_anomaly, confidence
        
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return False, 0.0
    
    def extract_features(self, data: Dict) -> List[float]:
        """Extract numerical features from incident data"""
        features = [
            data.get('packet_size', 0),
            data.get('packets_per_second', 0),
            data.get('connection_duration', 0),
            data.get('port', 0),
            data.get('failed_auth_attempts', 0),
            len(data.get('payload', '')),
            data.get('entropy', 0),
            data.get('unique_ips', 1),
            data.get('payload_similarity', 0),
            data.get('time_interval', 0)
        ]
        return features[:10]  # Ensure 10 features
    
    def save_model(self):
        """Save trained model"""
        try:
            model_path = settings.MODELS_DIR / "anomaly_detector.pkl"
            with open(model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler
                }, f)
            logger.info("Anomaly model saved")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

anomaly_detector = AnomalyDetector()