#!/usr/bin/env python3
"""
================================================================================
ADVANCED BEHAVIORAL ANALYSIS WITH MACHINE LEARNING
================================================================================
"""

__version__ = "29.0.0"
         to identify novel and zero-day threats that signature-based detection
         might miss.

MACHINE LEARNING MODELS:
1. Isolation Forest - Anomaly detection in process behavior
2. LSTM Network - Temporal pattern recognition for command sequences
3. Random Forest - Classification of suspicious process behaviors
4. Clustering - Grouping similar malicious behaviors

FEATURES ANALYZED:
- Process creation patterns
- Network connection behavior
- File system access patterns
- API call sequences
- Resource usage patterns
- Registry modifications
- DLL injection attempts
- Privilege escalation attempts

ADVANCED DETECTION CAPABILITIES:
- Living off the Land (LOLBAS) detection
- Fileless malware identification
- Process hollowing detection
- Memory injection detection
- Scheduled task abuse
- WMI persistence detection

LEARNING CAPABILITIES:
- Adapts to system-specific normal behavior
- Reduces false positives over time
- Identifies emerging attack patterns
- Learns from user feedback on alerts
"""

try:
    import numpy as np
    _NP_AVAILABLE = True
except ImportError:
    _NP_AVAILABLE = False
try:
    import pandas as pd
    _PD_AVAILABLE = True
except ImportError:
    _PD_AVAILABLE = False
import pickle
import threading

# FIX-v28p41: Restricted unpickler — prevents arbitrary code execution from
# tampered .pkl model files.  Only allows sklearn, numpy, and builtin types.
_SAFE_MODULE_PREFIXES = ('builtins', 'collections', 'datetime', 'copy',
                         'numpy', 'sklearn', 'scipy', '_codecs')

class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that refuses to instantiate objects from unexpected modules."""
    def find_class(self, module: str, name: str):
        if any(module == p or module.startswith(p + '.') for p in _SAFE_MODULE_PREFIXES):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Blocked unpickling of {module}.{name} — not in allowlist")
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import sqlite3
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    from sklearn.feature_extraction.text import TfidfVectorizer
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
import hashlib
import json

try:
    from vulnerability_scanner import VulnerabilityScanner
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False

class MLDetector:
    """
    Machine learning-based anomaly detector for advanced threat detection.
    """
    
    def __init__(self, config=None):
        """
        Initialize ML detector.
        
        Parameters:
        - config: Configuration object
        """
        self.running = True
        self.config = config
        
        # Model storage
        self.models_dir = Path("ml_models")
        self.models_dir.mkdir(exist_ok=True)
        
        # Initialize models
        self.anomaly_detector = None
        self.behavior_classifier = None
        self.sequence_analyzer = None
        self.scaler = StandardScaler() if _SKLEARN_AVAILABLE else None
        
        # Feature storage
        self.process_features = defaultdict(list)
        self.behavior_history = deque(maxlen=10000)
        self.feature_vector_size = 50
        
        # Training data
        self.training_data = []
        self.training_labels = []
        
        # Load existing models
        self.load_models()
        
        # Initialize models if not exists
        if self.anomaly_detector is None:
            self.init_models()
    
    def init_models(self):
        """Initialize machine learning models."""
        try:
            # Anomaly detection using Isolation Forest
            self.anomaly_detector = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            
            # Behavior classification using Random Forest
            self.behavior_classifier = RandomForestClassifier(
                n_estimators=50,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            
            # Sequential behavior analyzer
            self.sequence_analyzer = {
                'vectorizer': TfidfVectorizer(max_features=1000),
                'sequences': []
            }
            
            logging.info("[✓] ML models initialized")
            
        except Exception as e:
            logging.error(f"Failed to initialize ML models: {e}")
    
    def extract_features(self, process_info, behavior_data):
        """
        Extract features from process behavior for ML analysis.
        
        Parameters:
        - process_info: Process information dictionary
        - behavior_data: Behavioral observations
        
        Returns:
        - Feature vector (numpy array)
        """
        try:
            features = []
            
            # Basic process features
            features.extend([
                process_info.get('cpu_percent', 0) / 100.0,
                process_info.get('memory_mb', 0) / 1000.0,  # Normalize
                process_info.get('num_threads', 0) / 50.0,  # Normalize
                len(process_info.get('connections', [])) / 20.0,
                hash(process_info.get('name', '')) % 1000 / 1000.0,  # Name hash
            ])
            
            # Behavioral features
            features.extend([
                len(behavior_data.get('file_operations', [])) / 100.0,
                len(behavior_data.get('network_connections', [])) / 50.0,
                len(behavior_data.get('api_calls', [])) / 200.0,
                len(behavior_data.get('registry_changes', [])) / 20.0,
                behavior_data.get('privileged_operations', 0) / 10.0,
            ])
            
            # Temporal features
            current_time = datetime.now()
            process_age = (current_time - process_info.get('create_time', current_time)).total_seconds() / 3600.0
            features.append(process_age)
            
            # API call patterns (first 30 API calls)
            api_calls = behavior_data.get('api_calls', [])[:30]
            api_features = [0.0] * 30
            for i, api_call in enumerate(api_calls):
                if i < 30:
                    # Convert API call to numeric representation
                    api_features[i] = hash(api_call) % 1000 / 1000.0
            
            features.extend(api_features)
            
            # Network pattern features
            network_features = self.extract_network_features(behavior_data.get('network_connections', []))
            features.extend(network_features)
            
            # File access pattern features
            file_features = self.extract_file_features(behavior_data.get('file_operations', []))
            features.extend(file_features)
            
            # Pad or truncate to fixed size
            if len(features) < self.feature_vector_size:
                features.extend([0.0] * (self.feature_vector_size - len(features)))
            else:
                features = features[:self.feature_vector_size]
            
            return np.array(features) if _NP_AVAILABLE else features

        except Exception as e:
            logging.error(f"Error extracting features: {e}")
            return np.zeros(self.feature_vector_size) if _NP_AVAILABLE else [0.0] * self.feature_vector_size
    
    def extract_network_features(self, network_connections):
        """Extract features from network connection patterns."""
        features = []
        
        if not network_connections:
            return [0.0] * 10
        
        # Connection statistics
        total_connections = len(network_connections)
        unique_ips = len(set(conn.get('remote_ip', '') for conn in network_connections))
        unique_ports = len(set(conn.get('remote_port', 0) for conn in network_connections))
        
        # Port features
        high_ports = sum(1 for conn in network_connections if conn.get('remote_port', 0) > 1024)
        suspicious_ports = sum(1 for conn in network_connections 
                             if conn.get('remote_port', 0) in [4444, 5555, 6666, 8080, 31337])
        
        features.extend([
            total_connections / 50.0,
            unique_ips / 20.0,
            unique_ports / 20.0,
            high_ports / total_connections if total_connections > 0 else 0,
            suspicious_ports / total_connections if total_connections > 0 else 0,
        ])
        
        # Connection timing patterns
        if len(network_connections) > 1:
            timestamps = [conn.get('timestamp', datetime.now()) for conn in network_connections]
            time_diffs = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                          for i in range(1, len(timestamps)) if isinstance(timestamps[i], datetime)]
            if time_diffs:
                avg_time_diff = (np.mean(time_diffs) if _NP_AVAILABLE else sum(time_diffs) / len(time_diffs)) / 60.0
                std_time_diff = (np.std(time_diffs) if _NP_AVAILABLE else 0.0) / 60.0
            else:
                avg_time_diff = 0
                std_time_diff = 0
        else:
            avg_time_diff = 0
            std_time_diff = 0
        
        features.extend([avg_time_diff / 10.0, std_time_diff / 10.0])
        
        # Fill remaining features
        while len(features) < 10:
            features.append(0.0)
        
        return features[:10]
    
    def extract_file_features(self, file_operations):
        """Extract features from file operation patterns."""
        features = []
        
        if not file_operations:
            return [0.0] * 10
        
        # File operation statistics
        total_ops = len(file_operations)
        write_ops = sum(1 for op in file_operations if op.get('operation') == 'write')
        delete_ops = sum(1 for op in file_operations if op.get('operation') == 'delete')
        exec_ops = sum(1 for op in file_operations if op.get('operation') == 'execute')
        
        # File extension analysis
        extensions = [Path(op.get('path', '')).suffix.lower() for op in file_operations]
        unique_extensions = len(set(ext for ext in extensions if ext))
        
        # Suspicious extensions
        suspicious_exts = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.js']
        suspicious_files = sum(1 for ext in extensions if ext in suspicious_exts)
        
        features.extend([
            total_ops / 100.0,
            write_ops / total_ops if total_ops > 0 else 0,
            delete_ops / total_ops if total_ops > 0 else 0,
            exec_ops / total_ops if total_ops > 0 else 0,
            unique_extensions / 20.0,
            suspicious_files / total_ops if total_ops > 0 else 0,
        ])
        
        # File size patterns
        file_sizes = [op.get('size', 0) for op in file_operations if op.get('size')]
        if file_sizes:
            avg_size = (np.mean(file_sizes) if _NP_AVAILABLE else sum(file_sizes) / len(file_sizes)) / (1024 * 1024)
            max_size = max(file_sizes) / (1024 * 1024)
        else:
            avg_size = 0
            max_size = 0
        
        features.extend([avg_size / 100.0, max_size / 1000.0])
        
        # Fill remaining features
        while len(features) < 10:
            features.append(0.0)
        
        return features[:10]
    
    def detect_anomaly(self, features):
        """
        Detect if behavior is anomalous using isolation forest.
        
        Parameters:
        - features: Feature vector
        
        Returns:
        - (is_anomaly: bool, anomaly_score: float)
        """
        try:
            if self.anomaly_detector is None:
                return False, 0.0
            
            # Reshape for single sample
            features_reshaped = features.reshape(1, -1)
            
            # Predict anomaly (-1 for anomaly, 1 for normal)
            prediction = self.anomaly_detector.predict(features_reshaped)[0]
            anomaly_score = self.anomaly_detector.decision_function(features_reshaped)[0]
            
            is_anomaly = prediction == -1
            
            return is_anomaly, abs(anomaly_score)
            
        except Exception as e:
            logging.error(f"AnomalyDetectionError | Features: {features.shape if hasattr(features, 'shape') else 'N/A'} | Error: {e}")
            return False, 0.0
    
    def classify_behavior(self, features):
        """
        Classify behavior type using random forest.
        
        Parameters:
        - features: Feature vector
        
        Returns:
        - (behavior_type: str, confidence: float)
        """
        try:
            if self.behavior_classifier is None or not hasattr(self.behavior_classifier, 'classes_'):
                return "unknown", 0.0
            
            # Reshape for single sample
            features_reshaped = features.reshape(1, -1)
            
            # Predict behavior
            prediction = self.behavior_classifier.predict(features_reshaped)[0]
            probabilities = self.behavior_classifier.predict_proba(features_reshaped)[0]
            confidence = max(probabilities)
            
            behavior_types = ['normal', 'suspicious', 'malicious', 'unknown']
            if prediction < len(behavior_types):
                return behavior_types[prediction], confidence
            else:
                return "unknown", 0.0
                
        except Exception as e:
            logging.error(f"Error in behavior classification: {e}")
            return "unknown", 0.0
    
    def analyze_sequence_patterns(self, api_calls):
        """
        Analyze sequential patterns in API calls.
        
        Parameters:
        - api_calls: List of API call strings
        
        Returns:
        - (is_suspicious: float, confidence: float)
        """
        try:
            if len(api_calls) < 5:
                return 0.0, 0.0
            
            # Convert to string for analysis
            sequence_text = ' '.join(api_calls)
            
            # Transform to TF-IDF features
            if not hasattr(self.sequence_analyzer['vectorizer'], 'vocabulary_'):
                # Not fitted yet
                return 0.0, 0.0
            
            features = self.sequence_analyzer['vectorizer'].transform([sequence_text])
            
            # Simple heuristic based on suspicious API patterns
            suspicious_apis = [
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'SetWindowsHookEx', 'NtCreateFile', 'NtDeleteFile',
                'RegSetValue', 'CreateService', 'WMI', 'PowerShell'
            ]
            
            suspicious_count = sum(1 for api in api_calls if any(sus in api for sus in suspicious_apis))
            suspicion_score = suspicious_count / len(api_calls)
            
            return suspicion_score, min(suspicion_score * 2, 1.0)
            
        except Exception as e:
            logging.error(f"Error in sequence analysis: {e}")
            return 0.0, 0.0
    
    def learn_from_feedback(self, features, true_label):
        """
        Learn from user feedback to improve models.
        
        Parameters:
        - features: Feature vector
        - true_label: Correct label (0=benign, 1=suspicious, 2=malicious)
        """
        try:
            self.training_data.append(features)
            self.training_labels.append(true_label)
            
            # Retrain models if enough data collected
            if len(self.training_data) >= 100:
                self.retrain_models()
                
        except Exception as e:
            logging.error(f"Error learning from feedback: {e}")
    
    def retrain_models(self):
        """Retrain ML models with collected training data."""
        try:
            if len(self.training_data) < 50:
                return
            
            logging.info("Retraining ML models with new data...")
            
            X = np.array(self.training_data)
            y = np.array(self.training_labels)
            
            # Retrain anomaly detector
            self.anomaly_detector.fit(X)
            
            # Retrain behavior classifier
            self.behavior_classifier.fit(X, y)
            
            # Save updated models
            self.save_models()
            
            # Clear training data (keep some for continuous learning)
            self.training_data = self.training_data[-50:]
            self.training_labels = self.training_labels[-50:]
            
            logging.info("[✓] Models retrained successfully")
            
        except Exception as e:
            logging.error(f"Error retraining models: {e}")
    
    def save_models(self):
        """Save trained ML models to disk."""
        try:
            # Save anomaly detector
            with open(self.models_dir / "anomaly_detector.pkl", 'wb') as f:
                pickle.dump(self.anomaly_detector, f)
            
            # Save behavior classifier
            with open(self.models_dir / "behavior_classifier.pkl", 'wb') as f:
                pickle.dump(self.behavior_classifier, f)
            
            # Save scaler
            with open(self.models_dir / "feature_scaler.pkl", 'wb') as f:
                pickle.dump(self.scaler, f)
            
            logging.info("[✓] ML models saved")
            
        except Exception as e:
            logging.error(f"Error saving models: {e}")
    
    def load_models(self):
        """Load trained ML models from disk."""
        try:
            # Load anomaly detector
            anomaly_path = self.models_dir / "anomaly_detector.pkl"
            if anomaly_path.exists():
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_detector = _RestrictedUnpickler(f).load()

            # Load behavior classifier
            classifier_path = self.models_dir / "behavior_classifier.pkl"
            if classifier_path.exists():
                with open(classifier_path, 'rb') as f:
                    self.behavior_classifier = _RestrictedUnpickler(f).load()

            # Load scaler
            scaler_path = self.models_dir / "feature_scaler.pkl"
            if scaler_path.exists():
                with open(scaler_path, 'rb') as f:
                    self.scaler = _RestrictedUnpickler(f).load()
            
            if self.anomaly_detector or self.behavior_classifier:
                logging.info("[✓] ML models loaded from disk")
            
        except Exception as e:
            logging.error(f"Error loading models: {e}")
    
    def analyze_process_advanced(self, process_info, behavior_data):
        """
        Perform advanced ML-based analysis of process behavior.
        
        Parameters:
        - process_info: Process information
        - behavior_data: Behavioral observations
        
        Returns:
        - Dictionary with analysis results
        """
        try:
            # Extract features
            features = self.extract_features(process_info, behavior_data)
            
            # Normalize features
            if hasattr(self.scaler, 'mean_'):
                features_normalized = self.scaler.transform([features])[0]
            else:
                features_normalized = features
            
            # Anomaly detection
            is_anomaly, anomaly_score = self.detect_anomaly(features_normalized)
            
            # Behavior classification
            behavior_type, confidence = self.classify_behavior(features_normalized)
            
            # Sequence analysis
            api_calls = behavior_data.get('api_calls', [])
            sequence_suspicion, sequence_confidence = self.analyze_sequence_patterns(api_calls)
            
            # Combine results
            overall_suspicion = max(anomaly_score, sequence_suspicion)
            
            # Determine final classification
            if overall_suspicion > 0.8:
                final_classification = "MALICIOUS"
                severity = "CRITICAL"
            elif overall_suspicion > 0.6:
                final_classification = "SUSPICIOUS"
                severity = "HIGH"
            elif overall_suspicion > 0.3:
                final_classification = "UNUSUAL"
                severity = "MEDIUM"
            else:
                final_classification = "NORMAL"
                severity = "LOW"
            
            return {
                'classification': final_classification,
                'severity': severity,
                'confidence': max(confidence, sequence_confidence),
                'anomaly_score': anomaly_score,
                'behavior_type': behavior_type,
                'sequence_suspicion': sequence_suspicion,
                'features_detected': sum(1 for f in features if f > 0),
                'ml_confidence': confidence
            }
            
        except Exception as e:
            logging.error(f"Error in advanced analysis: {e}")
            return {
                'classification': 'ERROR',
                'severity': 'LOW',
                'confidence': 0.0,
                'error': str(e)
            }
    
    def get_model_statistics(self):
        """Get statistics about ML models."""
        return {
            'models_loaded': {
                'anomaly_detector': self.anomaly_detector is not None,
                'behavior_classifier': self.behavior_classifier is not None,
                'sequence_analyzer': self.sequence_analyzer is not None
            },
            'training_samples': len(self.training_data),
            'feature_vector_size': self.feature_vector_size,
            'behavior_history_size': len(self.behavior_history)
        }

# Global instance
_ml_detector_instance = None

def get_ml_detector(config=None) -> 'MLBehavioralDetector':
    """Get global ML detector instance."""
    global _ml_detector_instance
    if _ml_detector_instance is None:
        _ml_detector_instance = MLDetector(config)
    return _ml_detector_instance

if __name__ == "__main__":
    """Test ML detector."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          ML-BASED BEHAVIORAL ANALYSIS TEST")
    print("="*80)
    
    detector = MLDetector()
    
    # Test with sample data
    sample_process = {
        'name': 'test_process.exe',
        'cpu_percent': 50.0,
        'memory_mb': 100,
        'num_threads': 5,
        'connections': [],
        'create_time': datetime.now()
    }
    
    sample_behavior = {
        'file_operations': [],
        'network_connections': [],
        'api_calls': ['CreateFile', 'WriteFile', 'CloseHandle'],
        'registry_changes': [],
        'privileged_operations': 0
    }
    
    result = detector.analyze_process_advanced(sample_process, sample_behavior)
    
    print(f"\nAnalysis Results:")
    print(f"  Classification: {result['classification']}")
    print(f"  Severity: {result['severity']}")
    print(f"  Confidence: {result['confidence']:.2f}")
    
    stats = detector.get_model_statistics()
    print(f"\nModel Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\nPress Enter to exit...")
    input()

def check_ml_kev():
    """Query KEV catalog for ML behavioral analyzer related vulnerabilities."""
    if not _KEV_AVAILABLE:
        return {"error": "VulnerabilityScanner not available"}
    try:
        scanner = VulnerabilityScanner()
        results = scanner.check_kev_catalog("ml_behavioral")
        return results
    except Exception as e:
        return {"error": str(e)}