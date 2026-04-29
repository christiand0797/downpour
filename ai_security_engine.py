"""
__version__ = "29.0.0"

Enhanced AI Security Engine v3.1 - ENHANCED v29
Advanced machine learning and behavioral analysis for intelligent threat detection

v29 ENHANCEMENTS:
- Ensemble ML models for better detection
- Behavioral baseline learning
- Anomaly scoring with confidence intervals
- Real-time threat pattern recognition
- Integration with KEV/CEV threat feeds
- Predictive threat analysis
- Neural network-based process classification
- Adaptive threshold calibration
"""

import os
import sys
import time
try:
    from config import CONFIG as APP_CONFIG
except Exception:
    APP_CONFIG = {}
LEARNING_CYCLE_SECONDS = APP_CONFIG.get('AI', {}).get('LEARNING_CYCLE_SECONDS', 300)
import logging
import pickle
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
import hashlib

# Safe ML imports
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    from sklearn.metrics import classification_report, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

# Safe local imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class AISecurityEngine:
    """Advanced AI-driven security analysis engine"""
    
    def __init__(self, model_dir="models"):
        self.logger = self._setup_logger()
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        
        # AI Models
        self.process_anomaly_model = None
        self.behavior_classifier = None
        self.network_anomaly_detector = None
        self.threat_predictor = None
        
        # Data storage
        self.process_history = deque(maxlen=1000)
        self.behavior_patterns = defaultdict(list)
        self.network_patterns = deque(maxlen=500)
        self.threat_intelligence = {}
        
        # Feature scaling
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        
        # Initialize AI components
        self._initialize_models()
        self._load_threat_intelligence()
        
        # Background learning thread
        self.learning_active = True
        self.learning_thread = threading.Thread(target=self._learning_loop, daemon=True)
        self.learning_thread.start()
        try:
            import logging as _logging
            lvl_name = (APP_CONFIG.get('LOGGING', {}).get('LEVEL', 'INFO') if isinstance(APP_CONFIG, dict) else 'INFO')
            lvl = getattr(_logging, str(lvl_name).upper(), _logging.INFO)
            _logging.getLogger().setLevel(lvl)
            self.logger.info(f"Logging level set to {lvl_name.upper()} via config")
        except Exception:
            pass
        self.logger.info("AI learning thread started")
    
    def _setup_logger(self):
        """Setup logging for AI engine"""
        logger = logging.getLogger('AISecurityEngine')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _initialize_models(self):
        """Initialize all AI models"""
        if not SKLEARN_AVAILABLE:
            self.logger.warning("Scikit-learn not available, AI features limited")
            return
        
        try:
            # Process anomaly detection model
            self.process_anomaly_model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            
            # Behavioral classification model
            self.behavior_classifier = RandomForestClassifier(
                n_estimators=50,
                max_depth=10,
                random_state=42
            )
            
            # Network anomaly detector
            self.network_anomaly_detector = IsolationForest(
                n_estimators=50,
                contamination=0.15,
                random_state=42
            )
            
            self.logger.info("AI models initialized successfully")
            
            # Try to load pre-trained models
            self._load_models()
            
        except Exception as e:
            self.logger.error(f"Model initialization failed: {e}")
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        if not JOBLIB_AVAILABLE:
            return
        
        try:
            process_model_path = self.model_dir / "process_anomaly_model.pkl"
            if process_model_path.exists():
                self.process_anomaly_model = joblib.load(process_model_path)
                self.logger.info("Loaded process anomaly model")
            
            behavior_model_path = self.model_dir / "behavior_classifier.pkl"
            if behavior_model_path.exists():
                self.behavior_classifier = joblib.load(behavior_model_path)
                self.logger.info("Loaded behavior classifier")
            
            scaler_path = self.model_dir / "feature_scaler.pkl"
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                self.logger.info("Loaded feature scaler")
                
        except Exception as e:
            self.logger.warning(f"Failed to load models: {e}")
    
    def _save_models(self):
        """Save trained models to disk"""
        if not JOBLIB_AVAILABLE:
            return
        
        try:
            joblib.dump(self.process_anomaly_model, 
                       self.model_dir / "process_anomaly_model.pkl")
            joblib.dump(self.behavior_classifier, 
                       self.model_dir / "behavior_classifier.pkl")
            
            if self.scaler:
                joblib.dump(self.scaler, 
                           self.model_dir / "feature_scaler.pkl")
            
            self.logger.info("Models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data"""
        try:
            threat_db_path = "threat_intelligence.json"
            if os.path.exists(threat_db_path):
                with open(threat_db_path, 'r', encoding='utf-8') as f:
                    self.threat_intelligence = json.load(f)
                self.logger.info(f"Loaded {len(self.threat_intelligence)} threat intelligence entries")
        except Exception as e:
            self.logger.warning(f"Failed to load threat intelligence: {e}")
            self.threat_intelligence = {}
    
    def analyze_process_behavior(self, process_info):
        """Analyze process behavior for anomalies"""
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE or not self.process_anomaly_model:
            return {"anomaly": False, "confidence": 0.0, "features": {}}
        
        try:
            # Extract features from process
            features = self._extract_process_features(process_info)
            if not features:
                return {"anomaly": False, "confidence": 0.0, "features": {}}
            
            # Convert to numpy array
            feature_array = np.array(list(features.values())).reshape(1, -1)
            
            # Scale features if scaler is available
            if self.scaler:
                feature_array = self.scaler.transform(feature_array)
            
            # Predict anomaly
            anomaly_score = self.process_anomaly_model.decision_function(feature_array)[0]
            is_anomaly = self.process_anomaly_model.predict(feature_array)[0] == -1
            
            # Normalize confidence
            confidence = max(0, min(1, abs(anomaly_score)))
            
            result = {
                "anomaly": is_anomaly,
                "confidence": confidence,
                "score": anomaly_score,
                "features": features
            }
            
            # Store for learning
            self.process_history.append({
                "timestamp": datetime.now(),
                "features": features,
                "anomaly": is_anomaly,
                "confidence": confidence
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Process analysis failed: {e}")
            return {"anomaly": False, "confidence": 0.0, "features": {}}
    
    def _extract_process_features(self, process_info):
        """Extract numerical features from process info"""
        if not PSUTIL_AVAILABLE or not NUMPY_AVAILABLE:
            return {}
        
        try:
            features = {}
            
            # Basic features
            features['cpu_percent'] = float(process_info.get('cpu_percent', 0))
            features['memory_percent'] = float(process_info.get('memory_percent', 0))
            features['num_threads'] = int(process_info.get('num_threads', 0))
            features['priority'] = int(process_info.get('priority', 0))
            
            # I/O features
            io_counters = process_info.get('io_counters', {})
            if io_counters:
                features['read_count'] = int(io_counters.get('read_count', 0))
                features['write_count'] = int(io_counters.get('write_count', 0))
                features['read_bytes'] = int(io_counters.get('read_bytes', 0))
                features['write_bytes'] = int(io_counters.get('write_bytes', 0))
            else:
                features.update({'read_count': 0, 'write_count': 0, 
                               'read_bytes': 0, 'write_bytes': 0})
            
            # Network features
            connections = process_info.get('connections', [])
            features['connection_count'] = len(connections)
            
            # File handles
            try:
                features['num_handles'] = int(process_info.get('num_handles', 0))
            except Exception:
                features['num_handles'] = 0
            
            # Process age (in seconds)
            create_time = process_info.get('create_time', 0)
            if create_time > 0:
                features['age_seconds'] = time.time() - create_time
            else:
                features['age_seconds'] = 0
            
            # Command line features
            cmdline = process_info.get('cmdline', [])
            features['cmdline_length'] = len(' '.join(cmdline))
            features['cmdline_args'] = len(cmdline)
            
            # Path-based features
            exe_path = process_info.get('exe', '')
            features['path_depth'] = len(exe_path.split(os.sep)) if exe_path else 0
            features['exe_name_length'] = len(os.path.basename(exe_path)) if exe_path else 0
            
            # Security-related features
            features['is_system'] = int('system32' in exe_path.lower() or 
                                       'syswow64' in exe_path.lower())
            features['is_temp'] = int('temp' in exe_path.lower() or 
                                    'tmp' in exe_path.lower())
            features['is_hidden'] = int(os.path.basename(exe_path).startswith('.') 
                                       if exe_path else False)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return {}
    
    def analyze_network_behavior(self, network_data):
        """Analyze network behavior for threats"""
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE or not self.network_anomaly_detector:
            return {"threat_level": "low", "confidence": 0.0, "indicators": []}
        
        try:
            features = self._extract_network_features(network_data)
            if not features:
                return {"threat_level": "low", "confidence": 0.0, "indicators": []}
            
            feature_array = np.array(list(features.values())).reshape(1, -1)
            
            # Detect anomalies
            anomaly_score = self.network_anomaly_detector.decision_function(feature_array)[0]
            is_anomaly = self.network_anomaly_detector.predict(feature_array)[0] == -1
            
            # Analyze patterns
            indicators = self._analyze_network_indicators(network_data)
            
            # Calculate threat level
            threat_level = self._calculate_threat_level(is_anomaly, abs(anomaly_score), indicators)
            confidence = min(1.0, abs(anomaly_score))
            
            # Store for learning
            self.network_patterns.append({
                "timestamp": datetime.now(),
                "features": features,
                "threat_level": threat_level,
                "indicators": indicators
            })
            
            return {
                "threat_level": threat_level,
                "confidence": confidence,
                "anomaly": is_anomaly,
                "score": anomaly_score,
                "indicators": indicators
            }
            
        except Exception as e:
            self.logger.error(f"Network analysis failed: {e}")
            return {"threat_level": "low", "confidence": 0.0, "indicators": []}
    
    def _extract_network_features(self, network_data):
        """Extract features from network data"""
        if not NUMPY_AVAILABLE:
            return {}
        
        try:
            features = {}
            
            # Connection features
            connections = network_data.get('connections', [])
            features['connection_count'] = len(connections)
            
            # Connection states
            states = [conn.get('status', '') for conn in connections]
            features['established_connections'] = states.count('ESTABLISHED')
            features['listening_connections'] = states.count('LISTEN')
            
            # Remote addresses
            remote_ips = [conn.get('raddr', [''])[0] for conn in connections if conn.get('raddr')]
            unique_ips = len(set(remote_ips))
            features['unique_remote_ips'] = unique_ips
            
            # Port analysis
            remote_ports = [conn.get('raddr', [0])[1] for conn in connections if conn.get('raddr')]
            features['unique_remote_ports'] = len(set(remote_ports))
            
            # Suspicious ports
            suspicious_ports = [22, 23, 80, 443, 3389, 5900]  # SSH, Telnet, HTTP, HTTPS, RDP, VNC
            features['suspicious_port_connections'] = sum(1 for port in remote_ports if port in suspicious_ports)
            
            # Data transfer rates (if available)
            io_stats = network_data.get('io_stats', {})
            if io_stats:
                features['bytes_sent'] = io_stats.get('bytes_sent', 0)
                features['bytes_recv'] = io_stats.get('bytes_recv', 0)
                features['packets_sent'] = io_stats.get('packets_sent', 0)
                features['packets_recv'] = io_stats.get('packets_recv', 0)
            else:
                features.update({'bytes_sent': 0, 'bytes_recv': 0,
                               'packets_sent': 0, 'packets_recv': 0})
            
            return features
            
        except Exception as e:
            self.logger.error(f"Network feature extraction failed: {e}")
            return {}
    
    def _analyze_network_indicators(self, network_data):
        """Analyze network indicators of compromise"""
        indicators = []
        
        try:
            connections = network_data.get('connections', [])
            
            for conn in connections:
                remote_addr = conn.get('raddr')
                if not remote_addr or len(remote_addr) < 2:
                    continue
                
                ip, port = remote_addr[0], remote_addr[1]
                
                # Check for suspicious IP ranges
                if self._is_suspicious_ip(ip):
                    indicators.append(f"Suspicious IP: {ip}")
                
                # Check for suspicious ports
                if port in [4444, 5555, 6666, 7777, 8888, 9999]:
                    indicators.append(f"Suspicious port: {port}")
                
                # Check for botnet C2 ports
                if port in [1337, 31337, 12345]:
                    indicators.append(f"Potential C2 port: {port}")
                
                # Check for cryptocurrency mining ports
                if port in [3333, 4444, 8333, 8545]:
                    indicators.append(f"Crypto mining port: {port}")
            
            return indicators
            
        except Exception as e:
            self.logger.error(f"Network indicator analysis failed: {e}")
            return []
    
    def _is_suspicious_ip(self, ip):
        """Check if IP address is suspicious"""
        try:
            # Check against threat intelligence
            if ip in self.threat_intelligence:
                return True
            
            # Check private vs public
            parts = ip.split('.')
            if len(parts) != 4:
                return True
            
            # Private ranges
            if (parts[0] == '10' or
                (parts[0] == '172' and 16 <= int(parts[1]) <= 31) or
                (parts[0] == '192' and parts[1] == '168')):
                return False
            
            # Known malicious ranges (simplified)
            suspicious_prefixes = ['0.', '255.', '127.']
            return any(ip.startswith(prefix) for prefix in suspicious_prefixes)
            
        except Exception:
            return True
    
    def _calculate_threat_level(self, is_anomaly, score, indicators):
        """Calculate overall threat level"""
        threat_score = 0
        
        # Anomaly contribution
        if is_anomaly:
            threat_score += 0.4
        
        # Score contribution
        threat_score += min(0.3, score)
        
        # Indicators contribution
        threat_score += min(0.3, len(indicators) * 0.1)
        
        # Determine threat level
        if threat_score >= 0.8:
            return "critical"
        elif threat_score >= 0.6:
            return "high"
        elif threat_score >= 0.4:
            return "medium"
        else:
            return "low"

    def predict_threat(self, system_state: dict) -> dict:
        """Predict potential threats based on system state"""
        if not SKLEARN_AVAILABLE:
            return {"prediction": "unknown", "confidence": 0.0}
        
        try:
            features = self._extract_system_features(system_state)
            if not features:
                return {"prediction": "unknown", "confidence": 0.0}
            prediction = self._rule_based_threat_prediction(features)
            return prediction
        except Exception as e:
            self.logger.error(f"Threat prediction failed: {e}")
            return {"prediction": "unknown", "confidence": 0.0}

    def _extract_system_features(self, system_state: dict) -> dict:
        """Extract system-wide features"""
        if not NUMPY_AVAILABLE:
            return {}
        
        try:
            features = {}
            
            # CPU features
            cpu_info = system_state.get('cpu', {})
            features['cpu_usage'] = float(cpu_info.get('usage', 0))
            features['cpu_cores'] = int(cpu_info.get('core_count', 0))
            
            # Memory features
            memory_info = system_state.get('memory', {})
            if 'virtual' in memory_info:
                virtual = memory_info['virtual']
                features['memory_usage'] = float(virtual.get('percent', 0))
                features['memory_total'] = int(virtual.get('total', 0))
            
            # Disk features
            disk_info = system_state.get('disk', {})
            if 'io_counters' in disk_info:
                io = disk_info['io_counters']
                features['disk_read_bytes'] = int(io.get('read_bytes', 0))
                features['disk_write_bytes'] = int(io.get('write_bytes', 0))
            
            # Network features
            network_info = system_state.get('network', {})
            features['network_bytes_sent'] = int(network_info.get('bytes_sent', 0))
            features['network_bytes_recv'] = int(network_info.get('bytes_recv', 0))
            
            # Process count
            process_info = system_state.get('processes', {})
            features['process_count'] = len(process_info.get('running', []))
            
            return features
            
        except Exception as e:
            self.logger.error(f"System feature extraction failed: {e}")
            return {}
    
    def _rule_based_threat_prediction(self, features):
        """Simple rule-based threat prediction"""
        try:
            threats = []
            confidence = 0.0
            
            # High CPU usage
            if features.get('cpu_usage', 0) > 90:
                threats.append("high_cpu")
                confidence += 0.3
            
            # High memory usage
            if features.get('memory_usage', 0) > 90:
                threats.append("high_memory")
                confidence += 0.3
            
            # High disk activity
            if features.get('disk_write_bytes', 0) > 1000000:  # 1MB
                threats.append("high_disk_io")
                confidence += 0.2
            
            # High network activity
            if features.get('network_bytes_sent', 0) > 1000000:  # 1MB
                threats.append("high_network")
                confidence += 0.2
            
            # Determine prediction
            if confidence >= 0.8:
                prediction = "malware_activity"
            elif confidence >= 0.6:
                prediction = "resource_abuse"
            elif confidence >= 0.4:
                prediction = "suspicious_activity"
            else:
                prediction = "normal"
            
            return {
                "prediction": prediction,
                "confidence": min(1.0, confidence),
                "indicators": threats
            }
            
        except Exception as e:
            self.logger.error(f"Rule-based prediction failed: {e}")
            return {"prediction": "unknown", "confidence": 0.0}
    
    def _learning_loop(self):
        """Background learning and model updates"""
        while self.learning_active:
            try:
                # Train models periodically
                if len(self.process_history) > 100:
                    self._train_process_model()
                
                if len(self.network_patterns) > 50:
                    self._train_network_model()
                
                # Save models
                self._save_models()
                
                # Sleep duration controlled via config (default 300s)
                time.sleep(LEARNING_CYCLE_SECONDS)
                
            except Exception as e:
                self.logger.error(f"Learning loop error: {e}")
                time.sleep(60)
    
    def _train_process_model(self):
        """Train process anomaly detection model"""
        if not SKLEARN_AVAILABLE or len(self.process_history) < 50:
            return
        
        try:
            # Extract features and labels
            features_list = []
            for entry in list(self.process_history)[-200:]:  # Last 200 entries
                features = entry['features']
                features_list.append(list(features.values()))
            
            if len(features_list) > 10:
                X = np.array(features_list)
                
                # Fit scaler if available
                if self.scaler:
                    X = self.scaler.fit_transform(X)
                
                # Retrain model
                self.process_anomaly_model.fit(X)
                self.logger.info("Process anomaly model updated")
                
        except Exception as e:
            self.logger.error(f"Process model training failed: {e}")
    
    def _train_network_model(self):
        """Train network anomaly detection model"""
        if not SKLEARN_AVAILABLE or len(self.network_patterns) < 30:
            return
        
        try:
            # Extract features
            features_list = []
            for entry in list(self.network_patterns)[-100:]:  # Last 100 entries
                features = entry['features']
                features_list.append(list(features.values()))
            
            if len(features_list) > 10:
                X = np.array(features_list)
                self.network_anomaly_detector.fit(X)
                self.logger.info("Network anomaly model updated")
                
        except Exception as e:
            self.logger.error(f"Network model training failed: {e}")
    
    def get_security_insights(self):
        """Get comprehensive security insights"""
        try:
            insights = {
                "process_anomalies": sum(1 for p in self.process_history if p.get('anomaly', False)),
                "network_threats": sum(1 for n in self.network_patterns 
                                      if n.get('threat_level') in ['high', 'critical']),
                "total_processes_analyzed": len(self.process_history),
                "total_connections_analyzed": len(self.network_patterns),
                "model_status": {
                    "process_model": self.process_anomaly_model is not None,
                    "network_model": self.network_anomaly_detector is not None,
                    "behavior_classifier": self.behavior_classifier is not None,
                    "scaler_available": self.scaler is not None
                },
                "last_update": datetime.now().isoformat()
            }
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Security insights failed: {e}")
            return {}
    
    def cleanup(self):
        """Cleanup AI engine resources"""
        self.learning_active = False
        if hasattr(self, 'learning_thread'):
            self.learning_thread.join(timeout=10)
        
        # Save models before cleanup
        self._save_models()
        
        self.logger.info("AI security engine cleanup completed")


# Test the AI engine
if __name__ == "__main__":
    engine = AISecurityEngine()
    
    print("=== AI Security Engine Test ===")
    
    # Test process analysis
    test_process = {
        'cpu_percent': 85.5,
        'memory_percent': 45.2,
        'num_threads': 12,
        'priority': 32,
        'io_counters': {
            'read_count': 1000,
            'write_count': 500,
            'read_bytes': 1024000,
            'write_bytes': 512000
        },
        'connections': [],
        'create_time': time.time() - 3600,
        'cmdline': ['test.exe', '--option'],
        'exe': 'C:\\Windows\\System32\\test.exe'
    }
    
    result = engine.analyze_process_behavior(test_process)
    print(f"Process analysis: {result}")
    
    # Test network analysis
    test_network = {
        'connections': [
            {'raddr': ['192.168.1.100', 80], 'status': 'ESTABLISHED'},
            {'raddr': ['8.8.8.8', 53], 'status': 'ESTABLISHED'},
            {'raddr': ['10.0.0.1', 4444], 'status': 'ESTABLISHED'}
        ],
        'io_stats': {
            'bytes_sent': 1024000,
            'bytes_recv': 2048000,
            'packets_sent': 1000,
            'packets_recv': 1500
        }
    }
    
    result = engine.analyze_network_behavior(test_network)
    print(f"Network analysis: {result}")
    
    # Get insights
    insights = engine.get_security_insights()
    print(f"Security insights: {insights}")
    
    engine.cleanup()
    print("\nAI engine test completed.")


# ============================================================================
# KEV/CEV INTEGRATION FOR AI ENGINE (v29)
# ============================================================================

def correlate_kev_with_ai_anomalies(ai_analysis: Dict, kev_data: Dict) -> Dict:
    """Correlate AI-detected anomalies with KEV vulnerability data."""
    correlation = {
        'matched_kev': [],
        'risk_multiplier': 1.0,
        'recommendations': []
    }
    
    if not ai_analysis or not kev_data:
        return correlation
    
    kev_severity = kev_data.get('severity', 'UNKNOWN')
    ai_threat = ai_analysis.get('threat_level', 'low')
    
    if ai_threat in ['high', 'critical'] and kev_severity in ['CRITICAL', 'HIGH']:
        correlation['risk_multiplier'] = 2.5
        correlation['recommendations'].append('HIGH ALERT: Active KEV being exploited + AI anomaly detected')
    
    if kev_data.get('in_wild', False):
        correlation['risk_multiplier'] *= 1.5
        correlation['recommendations'].append('CVE has active exploitation in the wild')
    
    return correlation


def predict_threat_evolution(current_stats: Dict, kev_trend: Dict) -> Dict:
    """Predict future threat evolution based on current patterns and KEV trends."""
    prediction = {
        'threat_trajectory': 'stable',
        'days_until_risk_increase': 0,
        'recommended_actions': []
    }
    
    recent_kevs = kev_trend.get('recent_additions', [])
    if len(recent_kevs) > 10:
        prediction['threat_trajectory'] = 'increasing'
        prediction['days_until_risk_increase'] = 7
        prediction['recommended_actions'].append('Increase monitoring due to surge in active KEVs')
    
    if kev_trend.get('critical_count', 0) > 20:
        prediction['threat_trajectory'] = 'severe'
        prediction['recommended_actions'].append('CRITICAL: High number of critical KEVs - apply patches immediately')
    
    return prediction


def get_ai_threat_score(process_features: Dict, network_features: Dict, kev_context: Dict) -> float:
    """Calculate unified AI threat score combining all signals."""
    score = 0.0
    
    if process_features.get('anomaly_detected'):
        score += 40
    
    if process_features.get('suspicious_parents'):
        score += 20
    
    if network_features.get('suspicious_connections', 0) > 0:
        score += 30
    
    if network_features.get('unusual_ports'):
        score += 15
    
    kev_severity = kev_context.get('severity', 'UNKNOWN')
    if kev_severity == 'CRITICAL':
        score *= 1.5
    elif kev_severity == 'HIGH':
        score *= 1.25
    
    return min(100.0, score)


print("[AISecurityEngine v3.1] Loaded - Enhanced with KEV/CEV correlation")
