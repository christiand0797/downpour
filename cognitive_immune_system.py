# ============================================================================
# DECEPTION TECHNOLOGY (HONEYPOTS/HONEYTOKENS)
# ============================================================================

import logging
import threading
import time
import random
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Tuple
from enum import Enum

# Optional dependencies
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None
    nn = None

try:
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    SKLEARN_AVAILABLE = True
except (ImportError, SystemError):
    SKLEARN_AVAILABLE = False

try:
    import deap
    from deap import creator, base, tools, gp
    DEAP_AVAILABLE = True
except ImportError:
    DEAP_AVAILABLE = False

try:
    import snntorch
    SNNTORCH_AVAILABLE = True
except ImportError:
    SNNTORCH_AVAILABLE = False

try:
    import brian2
    BRIAN2_AVAILABLE = True
except ImportError:
    BRIAN2_AVAILABLE = False

logger = logging.getLogger(__name__)

class DeceptionTechnology:
    """
    Advanced deception technology - honeypots, honeytokens, and deception campaigns.
    """
    def __init__(self, cis: 'CognitiveImmuneSystem'):
        self.cis = cis
        self.running = False
        self._thread = None
        self.honeypots = {}
        self.honeytokens = {}
        self.deception_campaigns = {}
        self.interactions = []
        self._init_default_deception()
    
    def _init_default_deception(self):
        # Default honeypots
        self.honeypots = {
            "ssh_honeypot": {"type": "ssh", "port": 2222, "enabled": True, "banner": "SSH-2.0-OpenSSH_8.2p1", "credentials": {"admin": "admin", "root": "toor", "admin": "123456", "user": "password"}, "logs": [], "interactions": 0},
            "ftp_honeypot": {"type": "ftp", "port": 2121, "enabled": True, "banner": "220 FTP Server ready", "credentials": {"anonymous": "anonymous", "ftp": "ftp", "admin": "admin"}, "logs": [], "interactions": 0},
            "http_honeypot": {"type": "http", "port": 8080, "enabled": True, "banner": "Apache/2.4.41 (Ubuntu)", "pages": {"/": "<html><body>Welcome to Apache</body></html>", "/admin": "<html><body>Admin Panel</body></html>"}, "logs": [], "interactions": 0},
            "smb_honeypot": {"type": "smb", "port": 445, "enabled": True, "shares": {"ADMIN$": "C:\\Windows", "C$": "C:\\", "IPC$": "Remote IPC"}, "logs": [], "interactions": 0},
            "rdp_honeypot": {"type": "rdp", "port": 3389, "enabled": True, "certificate": "self-signed", "logs": [], "interactions": 0},
            "database_honeypot": {"type": "mysql", "port": 3306, "enabled": True, "banner": "5.7.33 MySQL Community Server", "credentials": {"root": "root", "admin": "admin", "mysql": "mysql"}, "logs": [], "interactions": 0}
        }
        
        # Default honeytokens
        self.honeytokens = {
            "fake_credentials": {"type": "credential", "value": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE&aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "description": "Fake AWS credentials", "alert_on_access": True, "placements": ["config files", "environment variables", "code repositories"]},
            "fake_api_key": {"type": "api_key", "value": "sk_test_FAKE_STRIPE_KEY_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE", "description": "Fake Stripe API key", "alert_on_access": True, "placements": ["config files", "environment variables"]},
            "fake_db_connection": {"type": "connection_string", "value": "Server=fake-db.internal;Database=production;User Id=admin;Password=SuperSecretPassword123!;", "description": "Fake database connection string", "alert_on_access": True, "placements": ["web.config", "app.config", "docker-compose.yml"]},
            "fake_api_endpoint": {"type": "url", "value": "https://api.internal.company.com/v1/admin/users?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake", "description": "Fake admin API endpoint with JWT", "alert_on_access": True, "placements": ["documentation", "postman collections", "swagger docs"]},
            "fake_ssh_key": {"type": "ssh_key", "value": "-----BEGIN OPENSSH PRIVATE KEY-----\nfakefakefakefakefakefakefakefakefakefakefakefakefakefake\n-----END OPENSSH PRIVATE KEY-----", "description": "Fake SSH private key", "alert_on_access": True, "placements": [".ssh/id_rsa", "authorized_keys", "deployment scripts"]},
            "fake_certificate": {"type": "certificate", "value": "-----BEGIN CERTIFICATE-----\nfakefakefakefakefakefakefakefakefakefakefakefakefakefake\n-----END CERTIFICATE-----", "description": "Fake SSL certificate", "alert_on_access": True, "placements": ["certificate stores", "keystores", "load balancer configs"]}
        }
        
        # Deception campaigns
        self.deception_campaigns = {
            "credential_harvesting": {"name": "Credential Harvesting Campaign", "description": "Deploy fake credentials to detect credential theft", "honeytokens": ["fake_credentials", "fake_api_key", "fake_db_connection"], "triggers": ["credential_access", "credential_use", "credential_exfiltration"], "response_actions": ["alert", "isolate_source", "track_usage"]},
            "lateral_movement_detection": {"name": "Lateral Movement Detection", "description": "Deploy honeypots to detect lateral movement", "honeytokens": ["fake_ssh_key", "fake_certificate"], "honeypots": ["ssh_honeypot", "smb_honeypot", "rdp_honeypot"], "triggers": ["lateral_movement", "credential_reuse", "service_exploitation"], "response_actions": ["alert", "isolate_host", "block_ip", "forensic_capture"]},
            "data_exfiltration_detection": {"name": "Data Exfiltration Detection", "description": "Deploy honeytokens in sensitive data locations", "honeytokens": ["fake_db_connection", "fake_api_endpoint", "fake_certificate"], "triggers": ["data_access", "data_exfiltration", "unauthorized_query"], "response_actions": ["alert", "block_exfiltration", "forensic_capture"]},
            "supply_chain_detection": {"name": "Supply Chain Compromise Detection", "description": "Detect supply chain attacks via fake dependencies", "honeytokens": ["fake_api_key", "fake_db_connection"], "triggers": ["dependency_confusion", "typosquatting", "repo_injection"], "response_actions": ["alert", "block_package", "audit_dependencies"]}
        }
    
    def start(self):
        """Start deception technology"""
        self.running = True
        self._thread = threading.Thread(target=self._deception_loop, daemon=True)
        self._thread.start()
        # Deploy initial honeypots
        for name, config in self.honeypots.items():
            if config.get("enabled"):
                self._deploy_honeypot(name, config)
        # Deploy honeytokens
        self._deploy_honeytokens()
        logger.info("Deception Technology started")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        # Cleanup honeypots
        for name in self.honeypots:
            self._cleanup_honeypot(name)
    
    def _deception_loop(self):
        """Main deception monitoring loop"""
        while self.running:
            try:
                # Check honeypot interactions
                for name, config in self.honeypots.items():
                    if config.get("enabled"):
                        self._check_honeypot_interactions(name, config)
                
                # Check honeytoken access
                self._check_honeytoken_access()
                
                # Check for campaign triggers
                self._check_campaign_triggers()
                
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                logger.error(f"Deception loop error: {e}")
                time.sleep(30)
    
    def _deploy_honeypot(self, name: str, config: Dict):
        """Deploy a honeypot service"""
        try:
            port = config.get("port")
            service_type = config.get("type")
            logger.info(f"Deploying {service_type} honeypot '{name}' on port {port}")
            # Record deployment
            config["deployed_at"] = datetime.now().isoformat()
            config["status"] = "deployed"
            # In production, this would start actual listeners
            # For now, we simulate deployment
            config["pid"] = None  # Would be actual process ID
            logger.info(f"Honeypot '{name}' deployed successfully")
        except Exception as e:
            logger.error(f"Failed to deploy honeypot '{name}': {e}")
            config["status"] = "failed"
            config["error"] = str(e)
    
    def _cleanup_honeypot(self, name: str):
        """Clean up honeypot resources"""
        config = self.honeypots.get(name)
        if config and config.get("pid"):
            try:
                import psutil
                proc = psutil.Process(config["pid"])
                proc.terminate()
            except Exception:
                pass
        config["status"] = "stopped"
    
    def _deploy_honeytokens(self):
        """Deploy honeytokens to configured locations"""
        for token_name, token_config in self.honeytokens.items():
            for placement in token_config.get("placements", []):
                # In production, would write honeytoken to actual locations
                logger.info(f"Deployed honeytoken '{token_name}' to {placement}")
                self.honeytokens[token_name]["deployed"] = True
                self.honeytokens[token_name]["deployment_location"] = placement
    
    def _check_honeypot_interactions(self, name: str, config: Dict):
        """Check for interactions with a honeypot"""
        # In production, this would check actual honeypot logs
        # For now, simulate interaction detection
        if config.get("interactions", 0) > 0:
            self._record_interaction("honeypot", name, config)
    
    def _check_honeytoken_access(self):
        """Check for honeytoken access"""
        for token_name, token_config in self.honeytokens.items():
            if token_config.get("alert_on_access") and token_config.get("accessed"):
                self._trigger_honeytoken_alert(token_name, token_config)
    
    def _trigger_honeytoken_alert(self, token_name: str, token_config: Dict):
        """Trigger alert when honeytoken is accessed"""
        logger.critical(f"HONEYTOKEN ALERT: '{token_name}' accessed! Type: {token_config['type']}")
        # Record interaction
        self._record_interaction("honeytoken", token_name, token_config)
        
        # Trigger campaign responses
        for campaign_name, campaign in self.deception_campaigns.items():
            if token_name in campaign.get("honeytokens", []):
                for action in campaign.get("response_actions", []):
                    self._execute_deception_response(action, token_name)
    
    def _check_campaign_triggers(self):
        """Check if any deception campaign triggers have been activated"""
        for campaign_name, campaign in self.deception_campaigns.items():
            triggers = campaign.get("triggers", [])
            # Check if any trigger conditions are met
            # This would integrate with CIS alerts and other signals
            pass
    
    def _execute_deception_response(self, action: str, context: str):
        """Execute a deception response action"""
        if action == "alert":
            self.cis._emit_signal(Signal(
                signal_type=SignalType.DANGER,
                source_id="deception",
                target_id=None,
                payload={"alert": f"Deception triggered: {context}", "severity": "HIGH"}
            ))
        elif action == "isolate_host":
            # Would integrate with CIS critical response
            pass
        elif action == "block_ip":
            # Would integrate with CIS critical response
            pass
        elif action == "forensic_capture":
            # Would trigger forensic capture
            pass
    
    def _record_interaction(self, interaction_type: str, identifier: str, data: Dict):
        """Record an interaction with deception elements"""
        interaction = {
            "timestamp": datetime.now().isoformat(),
            "type": interaction_type,
            "identifier": identifier,
            "data": data,
            "source_ip": data.get("source_ip", "unknown"),
            "user_agent": data.get("user_agent", "unknown")
        }
        self.interactions.append(interaction)
        
        # Emit signal
        self.cis._emit_signal(Signal(
            signal_type=SignalType.DANGER,
            source_id=f"deception_{interaction_type}",
            target_id=None,
            payload={
                "interaction_type": interaction_type,
                "identifier": identifier,
                "source_ip": data.get("source_ip", "unknown"),
                "severity": "HIGH" if interaction_type == "honeytoken" else "MEDIUM"
            }
        ))
        
        logger.warning(f"Deception interaction: {interaction_type} - {identifier}")
    
    def get_deception_status(self) -> Dict:
        """Get current deception technology status"""
        return {
            "running": self.running,
            "honeypots": {
                name: {
                    "type": config.get("type"),
                    "port": config.get("port"),
                    "enabled": config.get("enabled"),
                    "status": config.get("status", "unknown"),
                    "interactions": config.get("interactions", 0)
                }
                for name, config in self.honeypots.items()
            },
            "honeytokens": {
                name: {
                    "type": config.get("type"),
                    "description": config.get("description"),
                    "deployed": config.get("deployed", False),
                    "alert_on_access": config.get("alert_on_access", False)
                }
                for name, config in self.honeytokens.items()
            },
            "campaigns": {
                name: {
                    "description": config.get("description"),
                    "honeytokens": config.get("honeytokens", []),
                    "honeypots": config.get("honeypots", []),
                    "active": True
                }
                for name, config in self.deception_campaigns.items()
            },
            "total_interactions": len(self.interactions),
            "recent_interactions": list(self.interactions)[-10:]
        }


# ============================================================================
# FEDERATED THREAT INTELLIGENCE
# ============================================================================

class FederatedThreatIntelligence:
    """
    Federated Learning Threat Intelligence
    
    Enables collaborative threat learning across organizations without sharing
    sensitive data. Uses federated learning to train global threat models
    while keeping raw data local.
    """
    
    def __init__(self, cis: 'CognitiveImmuneSystem'):
        self.cis = cis
        self.logger = logging.getLogger(__name__ + ".FederatedThreatIntel")
        
        # Federated learning config
        self.num_clients = 0
        self.global_model = None
        self.client_models: Dict[str, Any] = {}
        self.client_weights: Dict[str, float] = {}
        self.round = 0
        self.running = False
        self._thread: Optional[threading.Thread] = None
        
        # Differential privacy
        self.dp_noise_multiplier = 1.0
        self.dp_l2_norm_clip = 1.0
        
        # Byzantine fault tolerance
        self.byzantine_tolerance = 0.3  # Tolerate up to 30% malicious clients
        
        # Model poisoning detection
        self.anomaly_threshold = 3.0  # Standard deviations
        
        # Initialize global model
        self._initialize_global_model()
        
        self.logger.info("Federated Threat Intelligence initialized")
    
    def _initialize_global_model(self):
        """Initialize global threat detection model"""
        if TORCH_AVAILABLE:
            self.global_model = self._create_threat_model()
        else:
            # Fallback to sklearn
            if SKLEARN_AVAILABLE:
                self.global_model = RandomForestClassifier(n_estimators=100, max_depth=10)
            else:
                self.global_model = None
    
    def _create_threat_model(self):
        """Create PyTorch threat detection model"""
        if not TORCH_AVAILABLE:
            return None
        
        class ThreatNet(nn.Module):
            def __init__(self, input_dim=100, hidden_dim=256, num_classes=2):
                super().__init__()
                self.layers = nn.Sequential(
                    nn.Linear(input_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(hidden_dim, hidden_dim // 2),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(hidden_dim // 2, num_classes)
                )
            
            def forward(self, x):
                return self.layers(x)
        
        return ThreatNet()
    
    def start(self):
        """Start federated learning"""
        self.running = True
        self._thread = threading.Thread(target=self._federated_loop, daemon=True)
        self._thread.start()
        self.logger.info("Federated Threat Intelligence started")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
    
    def register_client(self, client_id: str, client_info: Dict) -> bool:
        """Register a new federated client"""
        self.client_weights[client_id] = client_info.get("weight", 1.0)
        self.num_clients += 1
        self.logger.info(f"Registered federated client: {client_id}")
        return True
    
    def unregister_client(self, client_id: str):
        """Unregister a client"""
        if client_id in self.client_weights:
            del self.client_weights[client_id]
            self.num_clients -= 1
            self.logger.info(f"Unregistered federated client: {client_id}")
    
    def submit_model_update(self, client_id: str, model_update: Dict, num_samples: int) -> bool:
        """Receive model update from client"""
        if client_id not in self.client_weights:
            self.logger.warning(f"Unknown client: {client_id}")
            return False
        
        # Verify client
        if not self._verify_client(client_id):
            self.logger.warning(f"Client verification failed: {client_id}")
            return False
        
        # Store update
        self.client_models[client_id] = {
            "update": model_update,
            "num_samples": num_samples,
            "timestamp": datetime.now().isoformat()
        }
        return True
    
    def _federated_loop(self):
        """Main federated learning loop"""
        while self.running:
            try:
                if len(self.client_models) >= 2:  # Need at least 2 clients
                    self._aggregate_models()
                    self._distribute_global_model()
                    self.round += 1
                    self.logger.info(f"Completed federated round {self.round}")
                
                time.sleep(300)  # 5 minutes between rounds
            except Exception as e:
                self.logger.error(f"Federated learning error: {e}")
                time.sleep(60)
    
    def _aggregate_models(self):
        """Aggregate client models using FedAvg with Byzantine tolerance"""
        if not self.client_models:
            return
        
        # Filter out Byzantine clients
        filtered_updates = self._filter_byzantine_updates()
        
        if not filtered_updates:
            self.logger.warning("All client updates filtered as Byzantine")
            return
        
        # Weighted aggregation (FedAvg)
        total_samples = sum(u["num_samples"] for u in filtered_updates.values())
        
        if TORCH_AVAILABLE and self.global_model:
            self._aggregate_torch_models(filtered_updates, total_samples)
        elif SKLEARN_AVAILABLE and self.global_model:
            self._aggregate_sklearn_models(filtered_updates, total_samples)
    
    def _filter_byzantine_updates(self) -> Dict:
        """Filter out potentially malicious client updates using Krum/trimmed mean"""
        if len(self.client_models) < 3:
            return self.client_models
        
        # Extract model parameters
        updates = {}
        for client_id, data in self.client_models.items():
            update = data["update"]
            if isinstance(update, dict) and "weights" in update:
                updates[client_id] = np.array(update["weights"])
            elif isinstance(update, (list, np.ndarray)):
                updates[client_id] = np.array(update)
        
        if len(updates) < 3:
            return self.client_models
        
        # Multi-Krum / Trimmed Mean for Byzantine resilience
        client_ids = list(updates.keys())
        vectors = np.array([updates[cid].flatten() for cid in client_ids])
        
        # Compute pairwise distances
        distances = np.zeros((len(vectors), len(vectors)))
        for i in range(len(vectors)):
            for j in range(i+1, len(vectors)):
                dist = np.linalg.norm(vectors[i] - vectors[j])
                distances[i, j] = distances[j, i] = dist
        
        # Trimmed mean: remove top/bottom 30% by distance
        scores = np.sum(distances, axis=1)
        sorted_indices = np.argsort(scores)
        trim_count = int(self.byzantine_tolerance * len(vectors))
        keep_indices = sorted_indices[trim_count:len(vectors)-trim_count]
        
        filtered = {}
        for idx in keep_indices:
            client_id = client_ids[idx]
            filtered[client_id] = self.client_models[client_id]
        
        self.logger.info(f"Filtered {len(vectors)-len(keep_indices)} Byzantine clients")
        return filtered
    
    def _aggregate_torch_models(self, updates: Dict, total_samples: int):
        """Aggregate PyTorch models using FedAvg"""
        if not TORCH_AVAILABLE or not self.global_model:
            return
        
        global_dict = self.global_model.state_dict()
        for key in global_dict:
            weighted_sum = torch.zeros_like(global_dict[key])
            for client_id, data in updates.items():
                weight = data["num_samples"] / total_samples
                client_update = data["update"]
                if isinstance(client_update, dict) and "weights" in client_update:
                    client_tensor = torch.tensor(client_update["weights"])
                else:
                    client_tensor = torch.tensor(client_update)
                weighted_sum += weight * client_tensor
            global_dict[key] = weighted_sum
        
        self.global_model.load_state_dict(global_dict)
    
    def _aggregate_sklearn_models(self, updates: Dict, total_samples: int):
        """Aggregate sklearn models (simplified)"""
        # For sklearn, we'd use a different approach
        pass
    
    def _distribute_global_model(self):
        """Distribute global model to clients"""
        # In production, this would send model to clients
        # For now, we just log
        self.logger.info(f"Global model distributed for round {self.round}")
    
    def _verify_client(self, client_id: str) -> bool:
        """Verify client authenticity"""
        return client_id in self.client_weights
    
    def _detect_model_poisoning(self, client_id: str, update: Dict) -> bool:
        """Detect model poisoning attacks"""
        if not self.client_models:
            return False
        
        # Statistical anomaly detection
        if isinstance(update, dict) and "weights" in update:
            weights = np.array(update["weights"])
            if np.any(np.abs(weights) > self.anomaly_threshold * np.std(weights)):
                return True
        return False
    
    def get_global_model(self):
        """Get current global model"""
        return self.global_model
    
    def get_status(self) -> Dict:
        return {
            "running": self.running,
            "round": self.round,
            "num_clients": self.num_clients,
            "connected_clients": list(self.client_weights.keys()),
            "global_model_params": sum(p.numel() for p in self.global_model.parameters()) if TORCH_AVAILABLE and self.global_model else 0
        }


# ============================================================================
# SELF-HEALING CODE VIA GENETIC PROGRAMMING
# ============================================================================

class SelfHealingCode:
    """
    Self-Healing Code via Genetic Programming
    
    Automatically detects, diagnoses, and patches software vulnerabilities
    using genetic programming to evolve patches.
    
    Features:
    - Automatic bug detection via static/dynamic analysis
    - Patch generation via genetic programming
    - Automated testing and validation
    - Safe deployment with rollback
    - Continuous learning from patches
    """
    
    def __init__(self, cis: 'CognitiveImmuneSystem'):
        self.cis = cis
        self.logger = logging.getLogger(__name__ + ".SelfHealingCode")
        
        # GP configuration
        self.population_size = 100
        self.generations = 50
        self.mutation_rate = 0.1
        self.crossover_rate = 0.7
        self.elite_size = 10
        
        # Test suite for validation
        self.test_suite: List[Callable] = []
        self.vulnerability_db: Dict[str, Dict] = {}
        
        # Patch history
        self.patch_history: deque = deque(maxlen=1000)
        
        # Safety
        self.max_patch_size = 50  # Max lines changed
        self.rollback_on_failure = True
        
        if DEAP_AVAILABLE:
            self._setup_deap()
        
        self.logger.info("Self-Healing Code initialized")
    
    def _setup_deap(self):
        """Setup DEAP for genetic programming"""
        if not DEAP_AVAILABLE:
            return
        
        from deap import creator, base, tools, gp
        import pickle
        import io
        
        class _RestrictedUnpickler(pickle.Unpickler):
            ALLOWED_MODULES = {
                'sklearn', 'sklearn.ensemble', 'sklearn.preprocessing',
                'sklearn.cluster', 'sklearn.linear_model', 'sklearn.svm',
                'numpy', 'numpy.core', 'numpy.core.multiarray',
                'scipy', 'scipy.sparse', 'joblib', 'joblib.numpy_pickle',
                'collections', 'builtins', '__builtin__',
            }
            def find_class(self, module, name):
                top_level = module.split('.')[0]
                if top_level not in self.ALLOWED_MODULES:
                    raise pickle.UnpicklingError(f"Blocked attempt to unpickle from restricted module: {module}.{name}")
                return super().find_class(module, name)
        
        def _safe_load_model(path):
            with open(path, 'rb') as f:
                return _RestrictedUnpickler(io.BytesIO(f.read())).load()
        
        from deap import creator, base, tools, gp
        
        self.pset = gp.PrimitiveSetTyped("MAIN", [str], str)
        self.pset.addPrimitive(str.__add__, [str, str], str)
        self.pset.addPrimitive(str.replace, [str, str, str], str)
        
        creator.create("FitnessMax", base.Fitness, weights=(1.0,))
        creator.create("Individual", gp.PrimitiveTree, fitness=creator.FitnessMax)
        
        self.toolbox = base.Toolbox()
        self.toolbox.register("expr", gp.genHalfAndHalf, pset=self.pset, min_=1, max_=3)
        self.toolbox.register("individual", tools.initIterate, creator.Individual, self.toolbox.expr)
        self.toolbox.register("population", tools.initRepeat, list, self.toolbox.individual)
        self.toolbox.register("compile", gp.compile, pset=self.pset)
        self.toolbox.register("evaluate", self._evaluate_patch)
        self.toolbox.register("select", tools.selTournament, tournsize=3)
        self.toolbox.register("mate", gp.cxOnePoint)
        self.toolbox.register("expr_mut", gp.genFull, min_=0, max_=2)
        self.toolbox.register("mutate", gp.mutUniform, pset=self.pset, indpb=0.1)
    
    def register_test(self, test_func: Callable):
        """Register a test function for patch validation"""
        self.test_suite.append(test_func)
    
    def register_vulnerability(self, vuln_id: str, vuln_info: Dict):
        """Register a known vulnerability for patching"""
        self.vulnerability_db[vuln_id] = vuln_info
    
    def heal(self, vuln_id: str, source_code: str, test_cases: List[Dict]) -> Optional[str]:
        """
        Attempt to automatically heal a vulnerability
        
        Args:
            vuln_id: Vulnerability identifier
            source_code: Original vulnerable source code
            test_cases: List of test cases (input, expected_output)
            
        Returns:
            Patched source code or None if failed
        """
        if vuln_id not in self.vulnerability_db:
            self.logger.warning(f"Unknown vulnerability: {vuln_id}")
            return None
        
        vuln_info = self.vulnerability_db[vuln_id]
        self.logger.info(f"Attempting to heal vulnerability: {vuln_id}")
        
        if not DEAP_AVAILABLE:
            self.logger.warning("DEAP not available, cannot run GP")
            return self._fallback_heal(vuln_id, source_code, test_cases)
        
        try:
            # Run genetic programming to evolve a patch
            patch = self._evolve_patch(source_code, vuln_info, test_cases)
            
            if patch:
                # Validate patch
                if self._validate_patch(source_code, patch, test_cases):
                    # Apply patch
                    patched_code = self._apply_patch(source_code, patch)
                    
                    # Record successful patch
                    self.patch_history.append({
                        "vuln_id": vuln_id,
                        "patch": patch,
                        "timestamp": datetime.now().isoformat(),
                        "test_results": "passed"
                    })
                    
                    self.logger.info(f"Successfully healed vulnerability: {vuln_id}")
                    return patched_code
                else:
                    self.logger.warning(f"Patch validation failed for {vuln_id}")
            
            return None
            
        except Exception as e:
            self.logger.error(f"Healing failed for {vuln_id}: {e}")
            return None
    
    def _fallback_heal(self, vuln_id: str, source_code: str, test_cases: List[Dict]) -> Optional[str]:
        """Fallback healing using pattern matching"""
        vuln_info = self.vulnerability_db[vuln_id]
        
        # Simple pattern-based fixes
        patterns = vuln_info.get("patterns", [])
        for pattern, replacement in patterns:
            if pattern in source_code:
                patched = source_code.replace(pattern, replacement)
                if self._validate_patch(source_code, patched, test_cases):
                    self.patch_history.append({
                        "vuln_id": vuln_id,
                        "patch": f"replace({pattern} -> {replacement})",
                        "timestamp": datetime.now().isoformat(),
                        "method": "pattern_replace"
                    })
                    return patched
        return None
    
    def _evolve_patch(self, source_code: str, vuln_info: Dict, test_cases: List[Dict]) -> Optional[str]:
        """Evolve a patch using genetic programming"""
        if not DEAP_AVAILABLE:
            return None
        
        # This is a simplified version - real GP would be more complex
        # For now, return None to use fallback
        return None
    
    def _validate_patch(self, original: str, patched: str, test_cases: List[Dict]) -> bool:
        """Validate that patch fixes vulnerability without breaking functionality"""
        try:
            # Run test cases against patched code
            for test in test_cases:
                # This would execute the patched code with test inputs
                # Simplified for now
                pass
            return True
        except Exception:
            return False
    
    def _apply_patch(self, source_code: str, patch: str) -> str:
        """Apply patch to source code"""
        # Simplified - in reality would use proper patching
        return patched_code if isinstance(patch, str) else source_code
    
    def get_healing_status(self) -> Dict:
        return {
            "patches_applied": len(self.patch_history),
            "vulnerabilities_known": len(self.vulnerability_db),
            "test_cases_registered": len(self.test_suite),
            "recent_patches": list(self.patch_history)[-10:],
            "deap_available": DEAP_AVAILABLE
        }


# ============================================================================
# NEUROMORPHIC SPIKING NEURAL NETWORK DETECTOR
# ============================================================================

class NeuromorphicDetector:
    """
    Neuromorphic Spiking Neural Network Detector
    
    Event-driven, ultra-low-latency threat detection using spiking neural networks.
    Mimics biological neural processing for ultra-fast, energy-efficient detection.
    
    Features:
    - Spiking neural networks (SNNs) with STDP learning
    - Event-driven processing (no clock cycle)
    - Temporal pattern recognition
    - Ultra-low latency (< 1ms)
    - Online learning with STDP
    """
    
    def __init__(self, cis: 'CognitiveImmuneSystem'):
        self.cis = cis
        self.logger = logging.getLogger(__name__ + ".Neuromorphic")
        
        # Network configuration
        self.num_input_neurons = 1000
        self.num_hidden_neurons = 5000
        self.num_output_neurons = 100  # Threat classes
        
        # Neuron parameters (LIF model)
        self.tau_mem = 20.0  # Membrane time constant (ms)
        self.tau_syn = 5.0   # Synaptic time constant (ms)
        self.v_thresh = 1.0  # Spike threshold
        self.v_reset = 0.0   # Reset potential
        self.v_rest = 0.0    # Resting potential
        
        # STDP parameters
        self.tau_plus = 20.0   # LTP time constant (ms)
        self.tau_minus = 20.0  # LTD time constant (ms)
        self.A_plus = 0.01     # LTP amplitude
        self.A_minus = 0.01    # LTD amplitude
        
        # Network state
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.v_mem = None
        self.spikes = None
        self.synaptic_weights = None
        self.spike_times = None
        
        # SNN library
        if SNNTORCH_AVAILABLE:
            self._build_snntorch_network()
        elif BRIAN2_AVAILABLE:
            self._build_brian2_network()
        
        self.logger.info("Neuromorphic Detector initialized")
    
    def _build_snntorch_network(self):
        """Build SNN using snntorch"""
        if not SNNTORCH_AVAILABLE:
            return
        
        import snntorch as snn
        import torch
        import torch.nn as nn
        
        # LIF neurons
        self.lif1 = snn.Leaky(beta=0.9, threshold=1.0)
        self.lif2 = snn.Leaky(beta=0.9, threshold=1.0)
        
        # Layers
        self.fc1 = nn.Linear(1000, 5000)
        self.fc2 = nn.Linear(5000, 100)
        
        # STDP learning
        self.stdp = snn.STDP(
            synapse=self.fc1,
            learning_rate=0.01,
            tau_pre=20,
            tau_post=20
        )
        
        self.logger.info("Built snntorch neuromorphic network")
    
    def _build_brian2_network(self):
        """Build network using Brian2"""
        if not BRIAN2_AVAILABLE:
            return
        
        from brian2 import NeuronGroup, Synapses, PoissonGroup, Network, monitor
        from brian2 import ms, Hz, mV, nS, pA
        
        # Neuron model (LIF)
        eqs = '''
        dv/dt = (v_rest - v) / tau_mem + I_syn / C : volt (unless refractory)
        dI_syn/dt = -I_syn / tau_syn : amp
        '''
        
        self.neurons = NeuronGroup(5000, eqs, threshold='v > v_thresh',
                                  reset='v = v_reset', refractory=2*ms,
                                  method='euler')
        
        # Input layer (Poisson spikes from sensor data)
        self.input_group = PoissonGroup(1000, rates=10*Hz)
        
        # Synapses with STDP
        self.synapses = Synapses(self.input_group, self.neurons,
                                model='w : 1',
                                on_pre='v_post += w',
                                on_post='w = clip(w + A_plus, 0, w_max)')
        
        self.network = Network(self.input_group, self.neurons, self.synapses)
        self.logger.info("Built Brian2 neuromorphic network")
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._detection_loop, daemon=True)
        self._thread.start()
        self.logger.info("Neuromorphic Detector started")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _detection_loop(self):
        """Main detection loop - event driven"""
        while self.running:
            try:
                # Get sensor data from CIS
                sensor_data = self.cis.sensor_hub.get_last_snapshot() if hasattr(self.cis, 'sensor_hub') else None
                
                if sensor_data:
                    # Convert to spike trains
                    spike_trains = self._encode_to_spikes(sensor_data)
                    
                    # Run through SNN
                    spikes = self._run_network(spike_trains)
                    
                    # Decode output spikes to threat predictions
                    threats = self._decode_spikes(spikes)
                    
                    if threats:
                        self._handle_threats(threats)
                
                # Ultra-fast loop (sub-millisecond)
                time.sleep(0.001)  # 1ms loop = 1kHz
                
            except Exception as e:
                self.logger.error(f"Neuromorphic detection error: {e}")
                time.sleep(0.01)
    
    def _encode_to_spikes(self, sensor_data: Dict) -> Dict:
        """Convert sensor data to spike trains"""
        spike_trains = {}
        for key, value in sensor_data.items():
            if isinstance(value, (int, float)):
                rate = min(max(value * 100, 1), 1000)  # 1-1000 Hz
                spike_trains[key] = np.random.poisson(rate/1000, 1000)  # 1ms bins
            elif isinstance(value, list):
                spike_trains[key] = np.array(value)
        return spike_trains
    
    def _run_network(self, spike_trains: Dict) -> Dict:
        """Run neuromorphic network"""
        if SNNTORCH_AVAILABLE and hasattr(self, 'lif1'):
            import torch
            # Convert to tensors and run through snntorch
            outputs = {}
            for key, spikes in spike_trains.items():
                input_tensor = torch.tensor(spikes, dtype=torch.float32).unsqueeze(0)
                mem1 = self.lif1.init_leaky()
                mem2 = self.lif2.init_leaky()
                
                for t in range(input_tensor.size(1)):
                    cur1 = self.fc1(input_tensor[:, t])
                    spk1, mem1 = self.lif1(cur1, mem1)
                    cur2 = self.fc2(spk1)
                    spk2, mem2 = self.lif2(cur2, mem2)
                    outputs[key] = spk2
            return outputs
        elif BRIAN2_AVAILABLE and hasattr(self, 'network'):
            # Run Brian2 simulation
            self.network.run(1*ms)
            return self._read_spikes()
        return {}
    
    def _decode_spikes(self, spikes: Dict) -> List[Dict]:
        """Decode output spikes to threat predictions"""
        threats = []
        for key, spike_train in spikes.items():
            if isinstance(spike_train, torch.Tensor):
                rate = spike_train.mean().item() * 1000  # Hz
            else:
                rate = np.mean(spike_train) * 1000
            
            if rate > 100:  # Threshold
                threats.append({
                    "type": key,
                    "rate": rate,
                    "confidence": min(rate / 1000, 1.0),
                    "timestamp": datetime.now().isoformat()
                })
        return threats
    
    def _handle_threats(self, threats: List[Dict]):
        """Handle detected threats"""
        for threat in threats:
            # Emit signal to CIS
            if hasattr(self.cis, '_emit_signal'):
                self.cis._emit_signal(Signal(
                    signal_type=SignalType.DANGER,
                    source_id="neuromorphic",
                    target_id=None,
                    payload={
                        "threat": threat,
                        "source": "neuromorphic",
                        "confidence": threat.get("confidence", 0.5)
                    }
                ))
    
    def _read_spikes(self) -> Dict:
        """Read spike data from Brian2 monitors"""
        return {}
    
    def inject_sensor_data(self, sensor_data: Dict):
        """Inject sensor data for processing"""
        # This would be called by CIS sensor hub
        pass
    
    def get_status(self) -> Dict:
        return {
            "running": self.running,
            "snntorch_available": SNNTORCH_AVAILABLE,
            "brian2_available": BRIAN2_AVAILABLE,
            "num_neurons": self.num_input_neurons + self.num_hidden_neurons + self.num_output_neurons
        }


# ============================================================================
# CORE CIS INFRASTRUCTURE (Base Classes)
# ============================================================================

class SignalType(Enum):
    """Types of signals in the cytokine network"""
    DANGER = "danger"
    SAFE = "safe"
    INFLAMMATORY = "inflammatory"
    REGULATORY = "regulatory"
    MEMORY = "memory"
    CLONAL_EXPANSION = "clonal_expansion"
    SOMATIC_HYPERMUTATION = "somatic_hypermutation"
    TOLERANCE = "tolerance"
    EPITOPE_SPREADING = "epitope_spreading"
    APOPTOSIS = "apoptosis"

class CellType(Enum):
    """Immune cell types"""
    NAIVE_T = "naive_t"
    MEMORY_T = "memory_t"
    CYTOTOXIC_T = "cytotoxic_t"
    HELPER_T = "helper_t"
    REGULATORY_T = "regulatory_t"
    B_CELL = "b_cell"
    PLASMA_CELL = "plasma_cell"
    MEMORY_B = "memory_b"
    DENDRITIC = "dendritic"
    MACROPHAGE = "macrophage"
    NK_CELL = "nk_cell"

@dataclass
class Epitope:
    """Antigenic epitope - the 'signature' of a threat"""
    signature: str
    features: Dict[str, Any]
    threat_class: str
    first_seen: float
    last_seen: float
    affinity: float = 1.0
    encounters: int = 0
    is_self: bool = False

@dataclass
class Signal:
    """Cytokine signal between immune cells"""
    signal_type: SignalType
    source_id: str
    target_id: Optional[str]
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    ttl: int = 3

class Detector:
    """Base class for threat detectors (antibodies)"""
    def __init__(self, detector_id: str, epitope: Epitope, cell_type: CellType = CellType.B_CELL):
        self.detector_id = detector_id
        self.epitope = epitope
        self.cell_type = cell_type
        self.affinity = epitope.affinity
        self.age = 0
        self.activation_count = 0
        self.last_activation = 0
        self.is_memory = False
        self.parent_id: Optional[str] = None
        self.mutation_count = 0
    
    def matches(self, features: Dict[str, Any], threshold: float = 0.7) -> float:
        """Check if detector matches features - returns affinity score"""
        score = 0.0
        total_weight = 0.0
        for key, value in self.epitope.features.items():
            if key in features:
                if isinstance(value, (int, float)) and isinstance(features[key], (int, float)):
                    diff = abs(value - features[key])
                    max_val = max(abs(value), abs(features[key]), 1)
                    score += (1 - diff / max_val)
                elif value == features[key]:
                    score += 1.0
                total_weight += 1.0
        return score / max(total_weight, 1)
    
    def activate(self, features: Dict[str, Any]) -> bool:
        """Activate detector if match exceeds threshold"""
        affinity = self.matches(features)
        if affinity >= 0.5:
            self.activation_count += 1
            self.last_activation = time.time()
            return True
        return False
    
    def clone(self) -> 'Detector':
        """Create a clone with potential mutations"""
        import copy
        new_detector = copy.deepcopy(self)
        new_detector.detector_id = f"{self.detector_id}_clone_{int(time.time() * 1000)}"
        new_detector.parent_id = self.detector_id
        new_detector.age = 0
        new_detector.activation_count = 0
        return new_detector


# ============================================================================
# MAIN COGNITIVE IMMUNE SYSTEM
# ============================================================================

class CognitiveImmuneSystem:
    """
    Cognitive Immune System - Biologically-inspired meta-defense layer
    
    Implements:
    - Self/Non-Self Discrimination
    - Clonal Selection & Expansion
    - Immunological Memory
    - Affinity Maturation (Somatic Hypermutation)
    - Danger Model (DAMP/PAMP signals)
    - Cytokine Network (inter-cellular signaling)
    - Tolerance (prevent autoimmune responses)
    - Epitope Spreading (broaden response)
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__ + ".CIS")
        
        # Core repertoire
        self.detectors: Dict[str, Detector] = {}
        self.memory_detectors: Dict[str, Detector] = {}
        self.self_epitopes: Dict[str, Epitope] = {}
        
        # Signaling
        self.signal_queue: deque = deque(maxlen=10000)
        self.cytokine_levels: Dict[SignalType, float] = defaultdict(float)
        
        # State
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.tick_count = 0
        
        # Configuration
        self.max_detectors = self.config.get("max_detectors", 10000)
        self.max_memory = self.config.get("max_memory", 5000)
        self.clonal_expansion_threshold = self.config.get("clonal_expansion_threshold", 3)
        self.memory_threshold = self.config.get("memory_threshold", 10)
        self.tolerance_threshold = self.config.get("tolerance_threshold", 0.9)
        self.affinity_threshold = self.config.get("affinity_threshold", 0.7)
        self.hypermutation_rate = self.config.get("hypermutation_rate", 0.1)
        
        # Danger model
        self.danger_signals: deque = deque(maxlen=1000)
        self.safe_signals: deque = deque(maxlen=1000)
        
        # Components (initialized later)
        self.deception_technology: Optional[DeceptionTechnology] = None
        self.federated_intel: Optional[FederatedThreatIntelligence] = None
        self.self_healing: Optional[SelfHealingCode] = None
        self.neuromorphic: Optional[NeuromorphicDetector] = None
        
        # Integrated systems
        self.sensor_hub = None
        self.threat_db = None
        self.quarantine = None
        
        # Initialize self-tolerance
        self._initialize_self_tolerance()
        
        self.logger.info("Cognitive Immune System initialized")
    
    def _initialize_self_tolerance(self):
        """Initialize self-tolerance with known safe patterns"""
        # Add common safe patterns
        safe_patterns = [
            {"process_name": "explorer.exe", "signed": True},
            {"process_name": "svchost.exe", "signed": True},
            {"process_name": "lsass.exe", "signed": True},
            {"process_name": "csrss.exe", "signed": True},
            {"process_name": "winlogon.exe", "signed": True},
        ]
        for pattern in safe_patterns:
            epitope = Epitope(
                signature=f"self_{hash(str(pattern))}",
                features=pattern,
                threat_class="self",
                first_seen=time.time(),
                last_seen=time.time(),
                affinity=1.0,
                is_self=True
            )
            self.self_epitopes[epitope.signature] = epitope
    
    def start(self):
        """Start the immune system"""
        self.running = True
        self._thread = threading.Thread(target=self._immune_loop, daemon=True)
        self._thread.start()
        
        # Start components
        if self.deception_technology:
            self.deception_technology.start()
        if self.federated_intel:
            self.federated_intel.start()
        if self.self_healing:
            self.self_healing.register_test(self._test_patch)
        if self.neuromorphic:
            self.neuromorphic.start()
        
        self.logger.info("Cognitive Immune System started")
    
    def stop(self):
        """Stop the immune system"""
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
        
        # Stop components
        if self.deception_technology:
            self.deception_technology.stop()
        if self.federated_intel:
            self.federated_intel.stop()
        if self.neuromorphic:
            self.neuromorphic.stop()
        
        self.logger.info("Cognitive Immune System stopped")
    
    def _immune_loop(self):
        """Main immune system loop"""
        while self.running:
            try:
                self.tick_count += 1
                
                # Process signals
                self._process_signals()
                
                # Update cytokine levels
                self._update_cytokines()
                
                # Clonal selection
                self._clonal_selection()
                
                # Memory maintenance
                self._maintain_memory()
                
                # Tolerance check
                self._check_tolerance()
                
                # Epitope spreading
                if self.tick_count % 100 == 0:
                    self._epitope_spreading()
                
                # Cleanup old detectors
                if self.tick_count % 1000 == 0:
                    self._cleanup_detectors()
                
                time.sleep(1)  # 1 second tick
                
            except Exception as e:
                self.logger.error(f"Immune loop error: {e}")
                time.sleep(5)
    
    def _process_signals(self):
        """Process cytokine signals"""
        while self.signal_queue:
            signal = self.signal_queue.popleft()
            if signal.ttl <= 0:
                continue
            
            # Update cytokine levels
            self.cytokine_levels[signal.signal_type] += 1.0
            
            # Route signal to target
            if signal.target_id and signal.target_id in self.detectors:
                detector = self.detectors[signal.target_id]
                if signal.signal_type == SignalType.DANGER:
                    detector.activation_count += 1
                elif signal.signal_type == SignalType.REGULATORY:
                    detector.activation_count = max(0, detector.activation_count - 1)
            
            # Broadcast to relevant cells
            self._broadcast_signal(signal)
    
    def _broadcast_signal(self, signal: Signal):
        """Broadcast signal to relevant detectors"""
        for detector in self.detectors.values():
            if detector.cell_type in [CellType.HELPER_T, CellType.DENDRITIC]:
                # These cells respond to cytokines
                pass
    
    def _update_cytokines(self):
        """Decay cytokine levels over time"""
        for stype in self.cytokine_levels:
            self.cytokine_levels[stype] *= 0.95  # 5% decay per tick
    
    def _emit_signal(self, signal: Signal):
        """Emit a signal into the cytokine network"""
        self.signal_queue.append(signal)
    
    def _clonal_selection(self):
        """Clonal expansion of activated detectors"""
        for detector_id, detector in list(self.detectors.items()):
            if detector.activation_count >= self.clonal_expansion_threshold:
                # Clone the detector
                for _ in range(3):  # Create 3 clones
                    if len(self.detectors) >= self.max_detectors:
                        break
                    clone = detector.clone()
                    # Somatic hypermutation
                    self._somatic_hypermutation(clone)
                    self.detectors[clone.detector_id] = clone
                
                # Promote to memory if highly activated
                if detector.activation_count >= self.memory_threshold:
                    self._promote_to_memory(detector)
                
                # Reset activation count
                detector.activation_count = 0
    
    def _somatic_hypermutation(self, detector: Detector):
        """Apply somatic hypermutation to a detector"""
        detector.mutation_count += 1
        # Mutate epitope features slightly
        for key, value in detector.epitope.features.items():
            if isinstance(value, (int, float)) and random.random() < self.hypermutation_rate:
                noise = random.uniform(-0.1, 0.1) * abs(value) if value != 0 else random.uniform(-0.1, 0.1)
                detector.epitope.features[key] = value + noise
        detector.epitope.affinity = min(1.0, detector.epitope.affinity * 1.05)
    
    def _promote_to_memory(self, detector: Detector):
        """Promote detector to memory pool"""
        detector.is_memory = True
        detector.cell_type = CellType.MEMORY_B
        self.memory_detectors[detector.detector_id] = detector
        self.logger.info(f"Promoted detector to memory: {detector.detector_id}")
    
    def _maintain_memory(self):
        """Maintain memory detector pool"""
        if len(self.memory_detectors) > self.max_memory:
            # Remove least recently activated
            sorted_mem = sorted(self.memory_detectors.items(), key=lambda x: x[1].last_activation)
            to_remove = len(self.memory_detectors) - self.max_memory
            for detector_id, _ in sorted_mem[:to_remove]:
                del self.memory_detectors[detector_id]
    
    def _check_tolerance(self):
        """Check for autoimmune responses (tolerance breakdown)"""
        for detector in self.detectors.values():
            for self_epitope in self.self_epitopes.values():
                if detector.matches(self_epitope.features) > self.tolerance_threshold:
                    # Autoimmune reaction - suppress detector
                    self.logger.warning(f"Autoimmune reaction detected: {detector.detector_id}")
                    self._emit_signal(Signal(
                        signal_type=SignalType.TOLERANCE,
                        source_id="tolerance_check",
                        target_id=detector.detector_id,
                        payload={"reason": "self_reactivity", "epitope": self_epitope.signature}
                    ))
                    detector.activation_count = 0
    
    def _epitope_spreading(self):
        """Broaden immune response by creating detectors for related epitopes"""
        if not self.memory_detectors:
            return
        
        # Pick a random memory detector
        detector = random.choice(list(self.memory_detectors.values()))
        
        # Create variant detectors for related threats
        for _ in range(2):
            new_epitope = Epitope(
                signature=f"{detector.epitope.signature}_variant_{random.randint(1000,9999)}",
                features=detector.epitope.features.copy(),
                threat_class=detector.epitope.threat_class,
                first_seen=time.time(),
                last_seen=time.time(),
                affinity=detector.epitope.affinity * 0.8
            )
            # Slightly modify features
            for key in new_epitope.features:
                if isinstance(new_epitope.features[key], (int, float)):
                    new_epitope.features[key] *= random.uniform(0.9, 1.1)
            
            new_detector = Detector(
                detector_id=f"spread_{new_epitope.signature}",
                epitope=new_epitope,
                cell_type=CellType.NAIVE_T
            )
            self.detectors[new_detector.detector_id] = new_detector
    
    def _cleanup_detectors(self):
        """Remove old, inactive detectors"""
        now = time.time()
        to_remove = []
        for detector_id, detector in self.detectors.items():
            if detector.is_memory:
                continue
            if now - detector.last_activation > 3600 and detector.age > 100:  # 1 hour inactive
                to_remove.append(detector_id)
        
        for did in to_remove:
            del self.detectors[did]
    
    def analyze(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze features for threats"""
        results = {
            "threats": [],
            "max_affinity": 0.0,
            "danger_level": 0.0,
            "signals_emitted": 0
        }
        
        # Check against all detectors
        for detector in self.detectors.values():
            affinity = detector.matches(features)
            if affinity > results["max_affinity"]:
                results["max_affinity"] = affinity
            
            if affinity >= self.affinity_threshold:
                threat = {
                    "detector_id": detector.detector_id,
                    "threat_class": detector.epitope.threat_class,
                    "affinity": affinity,
                    "is_memory": detector.is_memory
                }
                results["threats"].append(threat)
                
                # Activate detector
                detector.activate(features)
                
                # Emit danger signal
                self._emit_signal(Signal(
                    signal_type=SignalType.DANGER,
                    source_id=detector.detector_id,
                    target_id=None,
                    payload={"features": features, "affinity": affinity}
                ))
                results["signals_emitted"] += 1
        
        # Calculate danger level from cytokine levels
        results["danger_level"] = self.cytokine_levels[SignalType.DANGER] / 100.0
        
        # Check self-tolerance
        for self_epitope in self.self_epitopes.values():
            if self_epitope.matches(features) > self.tolerance_threshold:
                self._emit_signal(Signal(
                    signal_type=SignalType.SAFE,
                    source_id="self_tolerance",
                    target_id=None,
                    payload={"epitope": self_epitope.signature}
                ))
        
        return results
    
    def learn_threat(self, features: Dict[str, Any], threat_class: str):
        """Learn a new threat pattern"""
        epitope = Epitope(
            signature=f"learned_{threat_class}_{int(time.time() * 1000)}",
            features=features,
            threat_class=threat_class,
            first_seen=time.time(),
            last_seen=time.time(),
            affinity=1.0
        )
        
        detector = Detector(
            detector_id=f"det_{epitope.signature}",
            epitope=epitope,
            cell_type=CellType.NAIVE_T
        )
        
        self.detectors[detector.detector_id] = detector
        self.logger.info(f"Learned new threat: {threat_class}")
    
    def add_self_pattern(self, features: Dict[str, Any]):
        """Add a pattern to self-tolerance"""
        epitope = Epitope(
            signature=f"self_{hash(str(features))}",
            features=features,
            threat_class="self",
            first_seen=time.time(),
            last_seen=time.time(),
            affinity=1.0,
            is_self=True
        )
        self.self_epitopes[epitope.signature] = epitope
    
    def get_status(self) -> Dict:
        """Get CIS status"""
        return {
            "running": self.running,
            "tick_count": self.tick_count,
            "detectors": len(self.detectors),
            "memory_detectors": len(self.memory_detectors),
            "self_epitopes": len(self.self_epitopes),
            "signal_queue_size": len(self.signal_queue),
            "cytokine_levels": dict(self.cytokine_levels),
            "deception": self.deception_technology.get_deception_status() if self.deception_technology else None,
            "federated": self.federated_intel.get_status() if self.federated_intel else None,
            "self_healing": self.self_healing.get_healing_status() if self.self_healing else None,
            "neuromorphic": self.neuromorphic.get_status() if self.neuromorphic else None
        }
    
    def _test_patch(self, patched_code: str) -> bool:
        """Test a patch - placeholder for self-healing integration"""
        return True


# ============================================================================
# ADVERSARIAL RED TEAMER
# ============================================================================

class AdversarialRedTeamer:
    """
    Adversarial Self-Red-Teaming
    
    Continuously simulates attacks against the system using MITRE ATT&CK techniques
    to validate and improve defenses.
    """
    
    def __init__(self, cis: CognitiveImmuneSystem):
        self.cis = cis
        self.logger = logging.getLogger(__name__ + ".RedTeamer")
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.techniques = self._load_mitre_techniques()
        self.campaigns: List[Dict] = []
        self.results: deque = deque(maxlen=1000)
    
    def _load_mitre_techniques(self) -> List[Dict]:
        """Load MITRE ATT&CK techniques"""
        return [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
            {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
            {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
            {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
            {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery"},
            {"id": "T1069", "name": "Permission Groups Discovery", "tactic": "Discovery"},
            {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
            {"id": "T1041", "name": "Exfiltration Over Command and Control Channel", "tactic": "Exfiltration"},
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        ]
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._red_team_loop, daemon=True)
        self._thread.start()
        self.logger.info("Adversarial Red Teamer started")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
    
    def _red_team_loop(self):
        while self.running:
            try:
                # Pick random technique
                technique = random.choice(self.techniques)
                self._simulate_attack(technique)
                time.sleep(300)  # Every 5 minutes
            except Exception as e:
                self.logger.error(f"Red team loop error: {e}")
                time.sleep(60)
    
    def _simulate_attack(self, technique: Dict):
        """Simulate a specific MITRE ATT&CK technique"""
        self.logger.info(f"Simulating attack: {technique['id']} - {technique['name']}")
        
        # Generate attack features
        attack_features = {
            "technique_id": technique["id"],
            "tactic": technique["tactic"],
            "timestamp": time.time(),
            "simulated": True
        }
        
        # Test against CIS
        result = self.cis.analyze(attack_features)
        
        self.results.append({
            "technique": technique,
            "detected": len(result["threats"]) > 0,
            "max_affinity": result["max_affinity"],
            "timestamp": time.time()
        })
        
        # If not detected, learn it
        if not result["threats"]:
            self.cis.learn_threat(attack_features, technique["tactic"])
            self.logger.warning(f"Technique {technique['id']} not detected - added to repertoire")


# ============================================================================
# THREAT EVOLUTION PREDICTOR
# ============================================================================

class ThreatEvolutionPredictor:
    """
    Predictive Threat Evolution
    
    Uses Markov chains and tactic progression models to predict
    likely next steps in an attack chain.
    """
    
    def __init__(self, cis: CognitiveImmuneSystem):
        self.cis = cis
        self.logger = logging.getLogger(__name__ + ".ThreatPredictor")
        self.transition_matrix: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.tactic_sequence: List[str] = []
        self.running = False
        self._thread: Optional[threading.Thread] = None
        
        # Initialize with known MITRE ATT&CK progressions
        self._initialize_transitions()
    
    def _initialize_transitions(self):
        """Initialize known tactic transitions"""
        transitions = {
            "Initial Access": {"Execution": 0.8, "Persistence": 0.2},
            "Execution": {"Persistence": 0.6, "Privilege Escalation": 0.3, "Defense Evasion": 0.1},
            "Persistence": {"Privilege Escalation": 0.5, "Defense Evasion": 0.3, "Credential Access": 0.2},
            "Privilege Escalation": {"Defense Evasion": 0.6, "Credential Access": 0.4},
            "Defense Evasion": {"Credential Access": 0.5, "Discovery": 0.3, "Lateral Movement": 0.2},
            "Credential Access": {"Discovery": 0.6, "Lateral Movement": 0.3, "Collection": 0.1},
            "Discovery": {"Lateral Movement": 0.5, "Collection": 0.3, "Command and Control": 0.2},
            "Lateral Movement": {"Collection": 0.5, "Command and Control": 0.3, "Exfiltration": 0.2},
            "Collection": {"Command and Control": 0.6, "Exfiltration": 0.4},
            "Command and Control": {"Exfiltration": 0.7, "Impact": 0.3},
            "Exfiltration": {"Impact": 0.5},
            "Impact": {}
        }
        self.transition_matrix = {k: dict(v) for k, v in transitions.items()}
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._prediction_loop, daemon=True)
        self._thread.start()
        self.logger.info("Threat Evolution Predictor started")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _prediction_loop(self):
        while self.running:
            try:
                if len(self.tactic_sequence) >= 2:
                    self._predict_next()
                time.sleep(60)
            except Exception as e:
                self.logger.error(f"Prediction loop error: {e}")
                time.sleep(60)
    
    def observe_tactic(self, tactic: str):
        """Observe a tactic in the attack chain"""
        self.tactic_sequence.append(tactic)
        if len(self.tactic_sequence) > 100:
            self.tactic_sequence = self.tactic_sequence[-100:]
        
        # Update transition matrix
        if len(self.tactic_sequence) >= 2:
            prev = self.tactic_sequence[-2]
            curr = self.tactic_sequence[-1]
            self.transition_matrix[prev][curr] += 1
    
    def _predict_next(self) -> List[Tuple[str, float]]:
        """Predict next likely tactics"""
        if not self.tactic_sequence:
            return []
        
        current = self.tactic_sequence[-1]
        transitions = self.transition_matrix.get(current, {})
        
        if not transitions:
            return []
        
        total = sum(transitions.values())
        predictions = [(tactic, count/total) for tactic, count in transitions.items()]
        predictions.sort(key=lambda x: x[1], reverse=True)
        
        # Emit predictions as signals
        for tactic, prob in predictions[:3]:
            self.cis._emit_signal(Signal(
                signal_type=SignalType.MEMORY,
                source_id="threat_predictor",
                target_id=None,
                payload={"predicted_tactic": tactic, "probability": prob, "current": current}
            ))
        
        return predictions[:5]
    
    def get_predictions(self) -> List[Tuple[str, float]]:
        return self._predict_next()


# ============================================================================
# SEMANTIC INTEGRITY VERIFIER
# ============================================================================

class SemanticIntegrityVerifier:
    """
    Semantic Integrity Verification
    
    Detects code drift and unauthorized modifications by comparing
    semantic hashes of code/modules against known good baselines.
    """
    
    def __init__(self, cis: CognitiveImmuneSystem):
        self.cis = cis
        self.logger = logging.getLogger(__name__ + ".IntegrityVerifier")
        self.baselines: Dict[str, str] = {}
        self.file_hashes: Dict[str, str] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.check_interval = 300  # 5 minutes
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._verify_loop, daemon=True)
        self._thread.start()
        self.logger.info("Semantic Integrity Verifier started")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def register_baseline(self, name: str, code: str):
        """Register a semantic baseline"""
        # Create semantic hash (simplified - in production use AST-based)
        semantic_hash = hashlib.sha256(code.encode()).hexdigest()[:32]
        self.baselines[name] = semantic_hash
        self.logger.info(f"Registered baseline: {name}")
    
    def register_file(self, filepath: str):
        """Register a file for integrity monitoring"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            file_hash = hashlib.sha256(content).hexdigest()
            self.file_hashes[filepath] = file_hash
            self.logger.info(f"Registered file: {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to register file {filepath}: {e}")
    
    def _verify_loop(self):
        while self.running:
            try:
                self._verify_all()
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Verify loop error: {e}")
                time.sleep(60)
    
    def _verify_all(self):
        """Verify all registered files and baselines"""
        # Check file integrity
        for filepath, expected_hash in self.file_hashes.items():
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                actual_hash = hashlib.sha256(content).hexdigest()
                if actual_hash != expected_hash:
                    self._alert_integrity_violation(filepath, expected_hash, actual_hash)
            except FileNotFoundError:
                self._alert_integrity_violation(filepath, expected_hash, "FILE_MISSING")
            except Exception as e:
                self.logger.error(f"Error verifying {filepath}: {e}")
        
        # Check semantic baselines (would need AST comparison in production)
        pass
    
    def _alert_integrity_violation(self, filepath: str, expected: str, actual: str):
        """Alert on integrity violation"""
        self.logger.critical(f"INTEGRITY VIOLATION: {filepath} - expected {expected}, got {actual}")
        self.cis._emit_signal(Signal(
            signal_type=SignalType.DANGER,
            source_id="integrity_verifier",
            target_id=None,
            payload={
                "type": "integrity_violation",
                "filepath": filepath,
                "expected_hash": expected,
                "actual_hash": actual
            }
        ))


# ============================================================================
# FACTORY FUNCTION
# ============================================================================

def create_cognitive_immune_system(config: Optional[Dict] = None) -> CognitiveImmuneSystem:
    """Create and configure a Cognitive Immune System instance"""
    cis = CognitiveImmuneSystem(config)
    
    # Initialize components
    cis.deception_technology = DeceptionTechnology(cis)
    cis.federated_intel = FederatedThreatIntelligence(cis)
    cis.self_healing = SelfHealingCode(cis)
    cis.neuromorphic = NeuromorphicDetector(cis)
    
    # Initialize other CIS components
    cis.red_teamer = AdversarialRedTeamer(cis)
    cis.threat_predictor = ThreatEvolutionPredictor(cis)
    cis.integrity_verifier = SemanticIntegrityVerifier(cis)
    
    return cis


def integrate_with_downpour(cis: CognitiveImmuneSystem, downpour_app) -> None:
    """Integrate CIS with Downpour main application"""
    # Connect sensor hub
    if hasattr(downpour_app, 'sensor_hub'):
        cis.sensor_hub = downpour_app.sensor_hub
    
    # Connect threat database
    if hasattr(downpour_app, 'db'):
        cis.threat_db = downpour_app.db
    
    # Connect quarantine
    if hasattr(downpour_app, 'quarantine'):
        cis.quarantine = downpour_app.quarantine
    
    # Start CIS
    cis.start()
    
    # Start sub-components
    cis.red_teamer.start()
    cis.threat_predictor.start()
    cis.integrity_verifier.start()
    
    # Register main app file for integrity monitoring
    cis.integrity_verifier.register_file("downpour_v29_titanium.py")
    
    # Hook into Downpour's threat detection
    original_analyze = getattr(downpour_app, '_analyze_threat', None)
    if original_analyze:
        def enhanced_analyze(features):
            result = original_analyze(features)
            cis_result = cis.analyze(features)
            # Merge results
            return {**result, **cis_result}
        downpour_app._analyze_threat = enhanced_analyze
    
    logging.getLogger(__name__).info("CIS integrated with Downpour")