"""
Cognitive Immune System (CIS) - Meta-Defense Layer for Downpour v29.101+
==========================================================================

A biologically-inspired cognitive immune system that operates as a meta-layer
above all existing security components. It doesn't just detect threats - it
learns, adapts, and evolves its own detection capabilities in real-time.

Architecture Principles (from biological immune systems):
1. SELF/NON-SELF DISCRIMINATION - Distinguish authorized vs unauthorized behavior
2. CLONAL SELECTION - Amplify successful detectors, mutate failures
3. IMMUNOLOGICAL MEMORY - Remember past threats, faster secondary response
4. AFFINITY MATURATION - Detectors improve through somatic hypermutation
5. DANGER MODEL - Respond to damage signals, not just foreign patterns
6. NETWORK THEORY - Detectors communicate via cytokine-like signals
7. TOLERANCE - Learn what's normal to avoid autoimmunity (false positives)
8. EPITOPE SPREADING - Expand recognition to related threat variants

Integration Points:
- Sensor Hub: Real-time telemetry as "antigen presentation"
- AI Security Engine: ML models as "B-cell receptors"
- Threat Feeds: External intelligence as "memory B-cells"
- Quarantine Core: Containment as "phagocytosis"
- PE Analyzer: Static analysis as "MHC presentation"
- Memory Forensics: Runtime inspection as "T-cell scanning"
- Event Push Monitor: Real-time events as "danger signals"
- Sharded Context: Distributed memory as "lymph node network"
"""

from __future__ import annotations

import json
import logging
import threading
import time
import hashlib
import uuid
import math
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from enum import Enum
import sqlite3

# Safe imports for optional dependencies
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)


# ============================================================================
# CORE IMMUNOLOGICAL PRIMITIVES
# ============================================================================

class SignalType(Enum):
    """Cytokine-like signal types for inter-detector communication"""
    DANGER = "danger"           # Damage detected (PAMP/DAMP)
    INFLAMMATORY = "inflammatory"  # Escalate response
    REGULATORY = "regulatory"   # Suppress response (tolerance)
    MEMORY = "memory"           # Store pattern
    CLONAL_EXPANSION = "clonal_expansion"  # Amplify detector
    SOMATIC_MUTATION = "somatic_mutation"  # Mutate detector
    APOPTOSIS = "apoptosis"     # Remove detector
    EPITOPE_SPREAD = "epitope_spread"      # Expand recognition


class CellType(Enum):
    """Immune cell analogs"""
    NAIVE_DETECTOR = "naive_detector"       # Uncommitted detector
    MEMORY_DETECTOR = "memory_detector"     # Experienced detector
    EFFECTOR_DETECTOR = "effector_detector" # Active responder
    REGULATORY_DETECTOR = "regulatory_detector"  # Suppressor
    ANTIGEN_PRESENTING = "antigen_presenting"    # Sensor hub interface


@dataclass
class Epitope:
    """Molecular pattern that detectors recognize"""
    pattern: str                    # The signature/pattern
    pattern_type: str               # hash, ip, domain, behavior, sequence, semantic
    affinity: float = 1.0           # Binding strength 0-1
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash((self.pattern, self.pattern_type))
    
    def __eq__(self, other):
        if not isinstance(other, Epitope):
            return False
        return self.pattern == other.pattern and self.pattern_type == other.pattern_type


@dataclass
class Signal:
    """Cytokine-like signal between detectors"""
    signal_type: SignalType
    source_id: str
    target_id: Optional[str]  # None = broadcast
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    ttl: int = 3  # Signal propagation depth


@dataclass
class Detector:
    """A single detector (B-cell/T-cell analog)"""
    id: str
    cell_type: CellType
    epitopes: Set[Epitope] = field(default_factory=set)  # Receptors
    affinity_threshold: float = 0.7
    activation_count: int = 0
    false_positive_count: int = 0
    true_positive_count: int = 0
    last_activated: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    lineage: str = ""  # Parent detector ID for clonal selection
    mutation_rate: float = 0.1
    is_active: bool = True
    clonal_size: int = 1  # Number of clones
    
    # Metrics
    specificity: float = 0.0  # TP / (TP + FP)
    sensitivity: float = 0.0  # TP / (TP + FN)
    
    def calculate_fitness(self) -> float:
        """Fitness = weighted combination of performance metrics"""
        if self.activation_count == 0:
            return 0.0
        specificity = self.true_positive_count / max(1, self.true_positive_count + self.false_positive_count)
        return specificity * math.log(1 + self.activation_count)
    
    def matches(self, epitope: Epitope) -> float:
        """Check if detector matches epitope, return affinity"""
        for receptor in self.epitopes:
            if receptor.pattern_type == epitope.pattern_type:
                if receptor.pattern == epitope.pattern:
                    return receptor.affinity
                # Semantic similarity for behavior patterns
                if receptor.pattern_type == "behavior":
                    similarity = self._semantic_similarity(receptor.pattern, epitope.pattern)
                    if similarity > self.affinity_threshold:
                        return similarity * receptor.affinity
        return 0.0
    
    def _semantic_similarity(self, a: str, b: str) -> float:
        """Simple semantic similarity for behavior patterns"""
        # Could be enhanced with embeddings
        a_tokens = set(a.lower().split())
        b_tokens = set(b.lower().split())
        if not a_tokens or not b_tokens:
            return 0.0
        return len(a_tokens & b_tokens) / len(a_tokens | b_tokens)


@dataclass
class ImmuneMemory:
    """Long-term immunological memory"""
    epitopes: Dict[Epitope, Dict[str, Any]] = field(default_factory=dict)
    detector_lineages: Dict[str, List[str]] = field(default_factory=dict)  # epitope -> detector IDs
    response_history: deque = field(default_factory=lambda: deque(maxlen=10000))
    
    def remember(self, epitope: Epitope, detector_id: str, outcome: str):
        """Store successful recognition"""
        if epitope not in self.epitopes:
            self.epitopes[epitope] = {
                "first_seen": datetime.now(),
                "detectors": set(),
                "outcomes": defaultdict(int)
            }
        self.epitopes[epitope]["detectors"].add(detector_id)
        self.epitopes[epitope]["outcomes"][outcome] += 1
        self.detector_lineages[detector_id].append(epitope.pattern)
        self.response_history.append({
            "epitope": epitope.pattern,
            "detector": detector_id,
            "outcome": outcome,
            "timestamp": datetime.now()
        })
    
    def get_best_detectors(self, epitope: Epitope, n: int = 3) -> List[str]:
        """Get top detectors for an epitope"""
        if epitope not in self.epitopes:
            return []
        # Sort by success rate
        detectors = list(self.epitopes[epitope]["detectors"])
        return detectors[:n]


# ============================================================================
# COGNITIVE IMMUNE SYSTEM CORE
# ============================================================================

class CognitiveImmuneSystem:
    """
    The Cognitive Immune System - a meta-defense layer that:
    1. Observes all security events as antigen presentation
    2. Maintains a diverse repertoire of detectors
    3. Learns through clonal selection and affinity maturation
    4. Communicates via cytokine-like signals
    5. Maintains immunological memory
    6. Self-regulates to prevent autoimmunity
    7. Evolves detectors against novel threats
    """
    
    def __init__(self, 
                 sensor_hub=None,
                 ai_engine=None,
                 threat_db=None,
                 quarantine=None,
                 config: Optional[Dict] = None):
        
        self.config = config or {}
        self.sensor_hub = sensor_hub
        self.ai_engine = ai_engine
        self.threat_db = threat_db
        self.quarantine = quarantine
        
        # Core immune components
        self.detectors: Dict[str, Detector] = {}
        self.memory = ImmuneMemory()
        self.signal_queue: deque = deque(maxlen=10000)
        self.active_responses: Dict[str, Dict] = {}
        
        # Configuration
        self.naive_pool_size = self.config.get("naive_pool_size", 1000)
        self.max_detectors = self.config.get("max_detectors", 10000)
        self.affinity_threshold = self.config.get("affinity_threshold", 0.7)
        self.clonal_expansion_factor = self.config.get("clonal_expansion_factor", 5)
        self.mutation_rate = self.config.get("mutation_rate", 0.15)
        self.tolerance_threshold = self.config.get("tolerance_threshold", 0.05)  # FP rate
        self.memory_retention_days = self.config.get("memory_retention_days", 90)
        
        # State
        self.running = False
        self._lock = threading.RLock()
        self._worker_thread: Optional[threading.Thread] = None
        self._signal_thread: Optional[threading.Thread] = None
        self._evolution_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = {
            "total_detections": 0,
            "true_positives": 0,
            "false_positives": 0,
            "clonal_expansions": 0,
            "somatic_mutations": 0,
            "detectors_created": 0,
            "detectors_retired": 0,
            "signals_processed": 0,
            "threats_contained": 0,
            "autoimmune_events": 0
        }
        
        # Initialize repertoire
        self._initialize_repertoire()
        
        logger.info(f"CognitiveImmuneSystem initialized with {len(self.detectors)} detectors")
    
    def _initialize_repertoire(self):
        """Create initial naive detector repertoire"""
        with self._lock:
            # Create detectors for known threat patterns from threat feeds
            if self.threat_db:
                stats = self.threat_db.get_statistics()
                logger.info(f"Seeding repertoire from threat DB: {stats.get('total_indicators', 0)} indicators")
            
            # Create base detectors for each pattern type
            pattern_types = ["ip", "domain", "hash", "url", "behavior", "semantic", "sequence"]
            detectors_per_type = self.naive_pool_size // len(pattern_types)
            
            for ptype in pattern_types:
                for i in range(detectors_per_type):
                    self._create_naive_detector(ptype)
            
            # Add specialized detectors
            self._create_specialized_detectors()
    
    def _create_naive_detector(self, pattern_type: str) -> Detector:
        """Create a new naive detector for a pattern type"""
        detector = Detector(
            id=f"naive_{pattern_type}_{uuid.uuid4().hex[:8]}",
            cell_type=CellType.NAIVE_DETECTOR,
            affinity_threshold=self.affinity_threshold,
            mutation_rate=self.mutation_rate
        )
        
        # Initialize with random receptor (will mature on activation)
        if pattern_type == "ip":
            # Random IP pattern
            receptor = Epitope(pattern=f"0.0.0.0/0", pattern_type="ip", affinity=0.3)
        elif pattern_type == "domain":
            receptor = Epitope(pattern="*.example.com", pattern_type="domain", affinity=0.3)
        elif pattern_type == "behavior":
            receptor = Epitope(pattern="suspicious_process_behavior", pattern_type="behavior", affinity=0.3)
        elif pattern_type == "semantic":
            receptor = Epitope(pattern="malicious_intent", pattern_type="semantic", affinity=0.3)
        else:
            receptor = Epitope(pattern=f"generic_{pattern_type}", pattern_type=pattern_type, affinity=0.3)
        
        detector.epitopes.add(receptor)
        
        with self._lock:
            self.detectors[detector.id] = detector
            self.stats["detectors_created"] += 1
        
        return detector
    
    def _create_specialized_detectors(self):
        """Create detectors seeded with known threat intelligence"""
        # These would be seeded from threat feeds, MITRE ATT&CK, etc.
        specialized = [
            ("mitre_t1059", "behavior", "command_line_execution"),
            ("mitre_t1055", "behavior", "process_injection"),
            ("mitre_t1003", "behavior", "credential_dumping"),
            ("mitre_t1486", "behavior", "data_encrypted"),
            ("mitre_t1027", "semantic", "obfuscated_code"),
            ("c2_beaconing", "behavior", "periodic_network_callback"),
            ("living_off_land", "semantic", "lolbin_execution"),
            ("ransomware_encrypt", "sequence", "rapid_file_encryption"),
        ]
        
        for det_id, ptype, pattern in specialized:
            detector = Detector(
                id=f"specialized_{det_id}",
                cell_type=CellType.MEMORY_DETECTOR,
                affinity_threshold=0.6,
                mutation_rate=0.05  # Lower mutation for proven detectors
            )
            detector.epitopes.add(Epitope(pattern=pattern, pattern_type=ptype, affinity=0.9))
            detector.true_positive_count = 10  # Pre-trained
            detector.activation_count = 10
            detector.lineage = "threat_intel_seed"
            
            with self._lock:
                self.detectors[detector.id] = detector
    
    # ========================================================================
    # MAIN IMMUNE RESPONSE LOOP
    # ========================================================================
    
    def start(self):
        """Start the immune system"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker threads
        self._worker_thread = threading.Thread(target=self._immune_loop, daemon=True)
        self._signal_thread = threading.Thread(target=self._signal_processing_loop, daemon=True)
        self._evolution_thread = threading.Thread(target=self._evolution_loop, daemon=True)
        
        self._worker_thread.start()
        self._signal_thread.start()
        self._evolution_thread.start()
        
        # Subscribe to sensor hub if available
        if self.sensor_hub:
            self.sensor_hub.register_consumer("cognitive_immune_system", self._on_sensor_event)
        
        logger.info("Cognitive Immune System started")
    
    def stop(self):
        """Stop the immune system"""
        self.running = False
        
        for thread in [self._worker_thread, self._signal_thread, self._evolution_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=5)
        
        if self.sensor_hub:
            self.sensor_hub.unregister_consumer("cognitive_immune_system")
        
        logger.info("Cognitive Immune System stopped")
    
    def _immune_loop(self):
        """Main immune response loop - runs continuously"""
        while self.running:
            try:
                # Process pending signals
                self._process_signals()
                
                # Check active responses
                self._update_active_responses()
                
                # Maintain tolerance (prevent autoimmunity)
                self._maintain_tolerance()
                
                # Sleep - immune system runs at ~1Hz
                time.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Immune loop error: {e}")
                time.sleep(5.0)
    
    def _signal_processing_loop(self):
        """Process cytokine-like signals between detectors"""
        while self.running:
            try:
                if self.signal_queue:
                    signal = self.signal_queue.popleft()
                    self._process_signal(signal)
                    self.stats["signals_processed"] += 1
                else:
                    time.sleep(0.1)
            except Exception as e:
                logger.error(f"Signal processing error: {e}")
                time.sleep(1.0)
    
    def _evolution_loop(self):
        """Evolutionary loop - clonal selection, mutation, retirement"""
        while self.running:
            try:
                # Run every 60 seconds
                time.sleep(60)
                
                if not self.running:
                    break
                
                self._clonal_selection()
                self._somatic_hypermutation()
                self._retire_failed_detectors()
                self._maintain_repertoire_diversity()
                self._consolidate_memory()
                
            except Exception as e:
                logger.error(f"Evolution loop error: {e}")
    
    # ========================================================================
    # ANTIGEN PRESENTATION & DETECTION
    # ========================================================================
    
    def _on_sensor_event(self, event_type: str, data: Dict[str, Any]):
        """Receive antigen presentation from sensor hub"""
        try:
            # Convert sensor event to epitopes
            epitopes = self._event_to_epitopes(event_type, data)
            
            for epitope in epitopes:
                self._present_antigen(epitope, context={"source": "sensor_hub", "event": event_type, "data": data})
                
        except Exception as e:
            logger.error(f"Sensor event processing error: {e}")
    
    def _event_to_epitopes(self, event_type: str, data: Dict) -> List[Epitope]:
        """Convert sensor event to epitopes (antigens)"""
        epitopes = []
        
        if event_type == "process":
            # Process creation/injection epitopes
            if "pid" in data:
                epitopes.append(Epitope(
                    pattern=str(data["pid"]),
                    pattern_type="process_id",
                    metadata=data
                ))
            if "command_line" in data:
                epitopes.append(Epitope(
                    pattern=data["command_line"][:200],
                    pattern_type="behavior",
                    metadata={"source": "command_line"}
                ))
            if "injection_detected" in data and data["injection_detected"]:
                epitopes.append(Epitope(
                    pattern="process_injection",
                    pattern_type="behavior",
                    affinity=0.9,
                    metadata={"technique": "T1055"}
                ))
        
        elif event_type == "network":
            # Network connection epitopes
            if "remote_ip" in data:
                epitopes.append(Epitope(
                    pattern=data["remote_ip"],
                    pattern_type="ip",
                    metadata={"port": data.get("remote_port"), "direction": data.get("direction")}
                ))
            if "suspicious" in data and data["suspicious"]:
                epitopes.append(Epitope(
                    pattern="suspicious_connection",
                    pattern_type="behavior",
                    affinity=0.8
                ))
        
        elif event_type == "file":
            # File system epitopes
            if "hash" in data:
                epitopes.append(Epitope(
                    pattern=data["hash"],
                    pattern_type="hash",
                    metadata={"path": data.get("path")}
                ))
            if "entropy" in data and data["entropy"] > 7.5:
                epitopes.append(Epitope(
                    pattern="high_entropy_file",
                    pattern_type="behavior",
                    affinity=0.7
                ))
        
        elif event_type == "memory":
            # Memory forensics epitopes
            if "injection_detected" in data:
                epitopes.append(Epitope(
                    pattern="memory_injection",
                    pattern_type="behavior",
                    affinity=0.95,
                    metadata={"technique": "T1055", "details": data}
                ))
            if "hollowing_detected" in data:
                epitopes.append(Epitope(
                    pattern="process_hollowing",
                    pattern_type="behavior",
                    affinity=0.95,
                    metadata={"technique": "T1055.012"}
                ))
        
        elif event_type == "registry":
            # Registry epitopes
            if "persistence" in data:
                epitopes.append(Epitope(
                    pattern="registry_persistence",
                    pattern_type="behavior",
                    affinity=0.8,
                    metadata={"technique": "T1547"}
                ))
        
        return epitopes
    
    def _present_antigen(self, epitope: Epitope, context: Dict):
        """Present antigen to detector repertoire"""
        with self._lock:
            self.stats["total_detections"] += 1
            
            # Find matching detectors
            matches = []
            for detector in self.detectors.values():
                if not detector.is_active:
                    continue
                affinity = detector.matches(epitope)
                if affinity >= detector.affinity_threshold:
                    matches.append((detector, affinity))
            
            # Sort by affinity
            matches.sort(key=lambda x: x[1], reverse=True)
            
            # Activate top matches
            for detector, affinity in matches[:5]:  # Top 5 responders
                self._activate_detector(detector, epitope, affinity, context)
            
            # If no matches, create new naive detector (epitope spreading)
            if not matches:
                self._epitope_spreading(epitope, context)
    
    def _activate_detector(self, detector: Detector, epitope: Epitope, affinity: float, context: Dict):
        """Activate a detector (clonal expansion)"""
        detector.activation_count += 1
        detector.last_activated = datetime.now()
        
        # Clonal expansion - create copies with slight mutations
        if detector.cell_type == CellType.NAIVE_DETECTOR:
            detector.cell_type = CellType.EFFECTOR_DETECTOR
            self._clonal_expand(detector, epitope)
        
        # Emit activation signal
        self._emit_signal(Signal(
            signal_type=SignalType.CLONAL_EXPANSION,
            source_id=detector.id,
            target_id=None,  # Broadcast
            payload={
                "epitope": epitope.pattern,
                "affinity": affinity,
                "context": context
            }
        ))
        
        # Initiate effector response
        self._effector_response(detector, epitope, context)
    
    def _clonal_expand(self, detector: Detector, epitope: Epitope):
        """Clonal expansion - create mutated copies of successful detector"""
        num_clones = self.clonal_expansion_factor
        
        for i in range(num_clones):
            clone = Detector(
                id=f"clone_{detector.id}_{uuid.uuid4().hex[:6]}",
                cell_type=CellType.EFFECTOR_DETECTOR,
                epitopes=set(detector.epitopes),  # Copy receptors
                affinity_threshold=detector.affinity_threshold,
                mutation_rate=detector.mutation_rate * 0.5,  # Lower for clones
                lineage=detector.id
            )
            
            # Somatic hypermutation - mutate receptors
            for receptor in clone.epitopes:
                if random.random() < detector.mutation_rate:
                    self._mutate_receptor(receptor)
            
            # Increase affinity for triggering epitope
            for receptor in clone.epitopes:
                if receptor.pattern_type == epitope.pattern_type:
                    receptor.affinity = min(1.0, receptor.affinity * 1.2)
            
            clone.clonal_size = 1
            
            with self._lock:
                self.detectors[clone.id] = clone
                self.stats["clonal_expansions"] += 1
            
            detector.clonal_size += 1
    
    def _mutate_receptor(self, receptor: Epitope):
        """Somatic hypermutation of a receptor"""
        if receptor.pattern_type == "ip":
            # Mutate IP pattern (adjust CIDR)
            pass
        elif receptor.pattern_type == "domain":
            # Mutate domain pattern
            pass
        elif receptor.pattern_type == "behavior":
            # Mutate behavior pattern - add/remove tokens
            tokens = receptor.pattern.split()
            if tokens and random.random() < 0.5:
                tokens.pop(random.randrange(len(tokens)))
            if random.random() < 0.3:
                tokens.append(f"mutated_{random.randint(1,100)}")
            receptor.pattern = " ".join(tokens) if tokens else "mutated_behavior"
        
        receptor.affinity = max(0.1, receptor.affinity * random.uniform(0.8, 1.2))
        self.stats["somatic_mutations"] += 1
    
    def _effector_response(self, detector: Detector, epitope: Epitope, context: Dict):
        """Execute effector response based on detector type and epitope"""
        response_id = f"resp_{detector.id}_{uuid.uuid4().hex[:8]}"
        
        # Determine response based on epitope type and threat level
        threat_level = self._calculate_threat_level(epitope, detector, context)
        
        response = {
            "id": response_id,
            "detector_id": detector.id,
            "epitope": epitope.pattern,
            "epitope_type": epitope.pattern_type,
            "threat_level": threat_level,
            "affinity": detector.matches(epitope),
            "context": context,
            "timestamp": datetime.now(),
            "status": "active",
            "actions": []
        }
        
        # Execute response based on threat level
        if threat_level >= 0.8:  # Critical
            response["actions"] = self._critical_response(epitope, context)
        elif threat_level >= 0.6:  # High
            response["actions"] = self._high_response(epitope, context)
        elif threat_level >= 0.4:  # Medium
            response["actions"] = self._medium_response(epitope, context)
        else:  # Low
            response["actions"] = self._low_response(epitope, context)
        
        with self._lock:
            self.active_responses[response_id] = response
        
        # Store in memory
        self.memory.remember(epitope, detector.id, "activated")
    
    def _calculate_threat_level(self, epitope: Epitope, detector: Detector, context: Dict) -> float:
        """Calculate threat level from multiple signals"""
        base_threat = detector.matches(epitope)
        
        # Boost from context
        context_boost = 0.0
        if context.get("source") == "memory_forensics":
            context_boost += 0.2
        if context.get("event") == "injection_detected":
            context_boost += 0.3
        if context.get("technique") in ["T1055", "T1059", "T1486"]:
            context_boost += 0.25
        
        # External threat intel correlation
        intel_boost = 0.0
        if self.threat_db:
            check = self.threat_db.check_indicator(epitope.pattern, epitope.pattern_type)
            if check:
                intel_boost = min(0.3, check.get("severity", 0) / 100)
        
        return min(1.0, base_threat + context_boost + intel_boost)
    
    def _critical_response(self, epitope: Epitope, context: Dict) -> List[str]:
        """Critical threat - immediate containment"""
        actions = []
        
        if epitope.pattern_type == "process_id" and self.quarantine:
            pid = int(epitope.pattern)
            actions.append(f"quarantine_process:{pid}")
            # Would call quarantine.quarantine_process(pid)
        
        if epitope.pattern_type == "ip" and hasattr(self, '_block_ip'):
            actions.append(f"block_ip:{epitope.pattern}")
        
        if epitope.pattern_type == "hash" and self.quarantine:
            actions.append(f"quarantine_file_hash:{epitope.pattern}")
        
        actions.append("alert:critical")
        actions.append("forensic_capture")
        
        self.stats["threats_contained"] += 1
        return actions
    
    def _high_response(self, epitope: Epitope, context: Dict) -> List[str]:
        """High threat - aggressive monitoring + containment prep"""
        return ["enhanced_monitoring", "alert:high", "prepare_containment"]
    
    def _medium_response(self, epitope: Epitope, context: Dict) -> List[str]:
        """Medium threat - increased surveillance"""
        return ["increased_surveillance", "alert:medium"]
    
    def _low_response(self, epitope: Epitope, context: Dict) -> List[str]:
        """Low threat - logging"""
        return ["log", "baseline_monitoring"]
    
    # ========================================================================
    # SIGNAL PROCESSING (CYTOKINE NETWORK)
    # ========================================================================
    
    def _emit_signal(self, signal: Signal):
        """Emit a cytokine-like signal"""
        self.signal_queue.append(signal)
    
    def _process_signal(self, signal: Signal):
        """Process incoming signal"""
        if signal.target_id:
            # Targeted signal
            if signal.target_id in self.detectors:
                self._deliver_signal(self.detectors[signal.target_id], signal)
        else:
            # Broadcast signal
            for detector in self.detectors.values():
                self._deliver_signal(detector, signal)
    
    def _deliver_signal(self, detector: Detector, signal: Signal):
        """Deliver signal to detector"""
        if signal.signal_type == SignalType.DANGER:
            # Lower activation threshold temporarily
            detector.affinity_threshold *= 0.8
        elif signal.signal_type == SignalType.REGULATORY:
            # Raise threshold (tolerance)
            detector.affinity_threshold = min(0.95, detector.affinity_threshold * 1.1)
        elif signal.signal_type == SignalType.MEMORY:
            # Promote to memory
            if detector.cell_type == CellType.EFFECTOR_DETECTOR:
                detector.cell_type = CellType.MEMORY_DETECTOR
        elif signal.signal_type == SignalType.APOPTOSIS:
            # Mark for retirement
            detector.is_active = False
    
    # ========================================================================
    # TOLERANCE & AUTOIMMUNITY PREVENTION
    # ========================================================================
    
    def _maintain_tolerance(self):
        """Prevent autoimmunity (excessive false positives)"""
        with self._lock:
            for detector in list(self.detectors.values()):
                if detector.activation_count > 10:
                    fp_rate = detector.false_positive_count / detector.activation_count
                    if fp_rate > self.tolerance_threshold:
                        # Emit regulatory signal
                        self._emit_signal(Signal(
                            signal_type=SignalType.REGULATORY,
                            source_id="cis_tolerance",
                            target_id=detector.id,
                            payload={"reason": "high_false_positive_rate", "rate": fp_rate}
                        ))
                        self.stats["autoimmune_events"] += 1
                        
                        # If persistent, retire
                        if fp_rate > self.tolerance_threshold * 2:
                            detector.is_active = False
                            self.stats["detectors_retired"] += 1
    
    # ========================================================================
    # EVOLUTIONARY OPERATIONS
    # ========================================================================
    
    def _clonal_selection(self):
        """Select best detectors for expansion"""
        with self._lock:
            # Score all detectors
            scored = [(d, d.calculate_fitness()) for d in self.detectors.values() if d.is_active]
            scored.sort(key=lambda x: x[1], reverse=True)
            
            # Top 10% get clonal expansion signal
            top_count = max(1, len(scored) // 10)
            for detector, fitness in scored[:top_count]:
                if fitness > 0.5:
                    self._emit_signal(Signal(
                        signal_type=SignalType.CLONAL_EXPANSION,
                        source_id="cis_evolution",
                        target_id=detector.id,
                        payload={"fitness": fitness}
                    ))
    
    def _somatic_hypermutation(self):
        """Mutate detectors to explore pattern space"""
        with self._lock:
            for detector in self.detectors.values():
                if not detector.is_active:
                    continue
                if detector.cell_type in [CellType.EFFECTOR_DETECTOR, CellType.MEMORY_DETECTOR]:
                    # Mutate with probability based on activation
                    if random.random() < (detector.mutation_rate * 0.1):
                        for receptor in detector.epitopes:
                            self._mutate_receptor(receptor)
    
    def _retire_failed_detectors(self):
        """Remove detectors that consistently fail"""
        with self._lock:
            to_retire = []
            for detector in self.detectors.values():
                if not detector.is_active:
                    continue
                
                age_days = (datetime.now() - detector.created_at).days
                
                # Retire criteria
                if detector.activation_count == 0 and age_days > 7:
                    to_retire.append(detector.id)
                elif detector.false_positive_count > 10 and detector.true_positive_count == 0:
                    to_retire.append(detector.id)
                elif detector.specificity < 0.1 and detector.activation_count > 20:
                    to_retire.append(detector.id)
            
            for det_id in to_retire:
                if det_id in self.detectors:
                    del self.detectors[det_id]
                    self.stats["detectors_retired"] += 1
    
    def _maintain_repertoire_diversity(self):
        """Ensure diverse detector repertoire"""
        with self._lock:
            # Count by pattern type
            type_counts = defaultdict(int)
            for d in self.detectors.values():
                for e in d.epitopes:
                    type_counts[e.pattern_type] += 1
            
            # Add naive detectors for underrepresented types
            target_per_type = self.naive_pool_size // 7  # 7 pattern types
            for ptype, count in type_counts.items():
                if count < target_per_type * 0.5:
                    needed = target_per_type - count
                    for _ in range(min(needed, 5)):
                        self._create_naive_detector(ptype)
    
    def _consolidate_memory(self):
        """Consolidate immunological memory"""
        # Promote successful effectors to memory
        with self._lock:
            for detector in self.detectors.values():
                if (detector.cell_type == CellType.EFFECTOR_DETECTOR and 
                    detector.true_positive_count >= 5 and
                    detector.specificity > 0.8):
                    detector.cell_type = CellType.MEMORY_DETECTOR
                    detector.mutation_rate *= 0.5  # Reduce mutation for memory
                    
                    # Emit memory signal
                    self._emit_signal(Signal(
                        signal_type=SignalType.MEMORY,
                        source_id="cis_consolidation",
                        target_id=detector.id,
                        payload={"true_positives": detector.true_positive_count}
                    ))
    
    # ========================================================================
    # RESPONSE MANAGEMENT
    # ========================================================================
    
    def _update_active_responses(self):
        """Update status of active responses"""
        with self._lock:
            completed = []
            for resp_id, response in self.active_responses.items():
                if response["status"] == "active":
                    # Check if response actions completed
                    # In real implementation, would check actual completion
                    response["status"] = "completed"
                    completed.append(resp_id)
            
            for resp_id in completed:
                del self.active_responses[resp_id]
    
    # ========================================================================
    # EPITOPE SPREADING (NOVELTY DETECTION)
    # ========================================================================
    
    def _epitope_spreading(self, epitope: Epitope, context: Dict):
        """When no detector matches, spread recognition to related patterns"""
        # Create new naive detector for this epitope
        new_detector = Detector(
            id=f"naive_spread_{epitope.pattern_type}_{uuid.uuid4().hex[:8]}",
            cell_type=CellType.NAIVE_DETECTOR,
            affinity_threshold=self.affinity_threshold,
            mutation_rate=self.mutation_rate * 1.5  # Higher mutation for novel patterns
        )
        new_detector.epitopes.add(epitope)
        new_detector.lineage = "epitope_spreading"
        
        with self._lock:
            self.detectors[new_detector.id] = new_detector
            self.stats["detectors_created"] += 1
        
        # Emit epitope spread signal
        self._emit_signal(Signal(
            signal_type=SignalType.EPITOPE_SPREAD,
            source_id="cis_novelty",
            target_id=None,
            payload={"epitope": epitope.pattern, "type": epitope.pattern_type}
        ))
        
        logger.info(f"Epitope spreading: created detector for novel pattern {epitope.pattern_type}:{epitope.pattern[:50]}")
    
    # ========================================================================
    # EXTERNAL INTEGRATION
    # ========================================================================
    
    def inject_threat_intel(self, indicators: List[Dict]):
        """Inject external threat intelligence as memory"""
        for ind in indicators:
            epitope = Epitope(
                pattern=ind.get("value", ""),
                pattern_type=ind.get("type", "unknown"),
                affinity=0.9,
                metadata=ind
            )
            # Create or reinforce memory detector
            self._reinforce_memory(epitope)
    
    def _reinforce_memory(self, epitope: Epitope):
        """Reinforce memory for known threat"""
        with self._lock:
            # Find existing memory detectors
            for detector in self.detectors.values():
                if detector.cell_type == CellType.MEMORY_DETECTOR:
                    if detector.matches(epitope) > 0.8:
                        # Reinforce
                        detector.true_positive_count += 1
                        self.memory.remember(epitope, detector.id, "reinforced")
                        return
            
            # Create new memory detector
            detector = Detector(
                id=f"memory_ext_{uuid.uuid4().hex[:8]}",
                cell_type=CellType.MEMORY_DETECTOR,
                affinity_threshold=0.6,
                mutation_rate=0.02
            )
            detector.epitopes.add(epitope)
            detector.true_positive_count = 100  # High confidence from external intel
            detector.activation_count = 100
            detector.lineage = "external_intel"
            
            self.detectors[detector.id] = detector
            self.memory.remember(epitope, detector.id, "external_intel")
    
    def get_immune_status(self) -> Dict:
        """Get comprehensive immune system status"""
        with self._lock:
            type_counts = defaultdict(int)
            cell_type_counts = defaultdict(int)
            
            for d in self.detectors.values():
                if d.is_active:
                    cell_type_counts[d.cell_type.value] += 1
                    for e in d.epitopes:
                        type_counts[e.pattern_type] += 1
            
            return {
                "running": self.running,
                "total_detectors": len([d for d in self.detectors.values() if d.is_active]),
                "detectors_by_type": dict(type_counts),
                "detectors_by_cell_type": dict(cell_type_counts),
                "memory_epitopes": len(self.memory.epitopes),
                "active_responses": len(self.active_responses),
                "signal_queue_size": len(self.signal_queue),
                "stats": self.stats.copy(),
                "repertoire_diversity": len(type_counts)
            }
    
    def get_detector_lineage(self, detector_id: str) -> Optional[Dict]:
        """Get lineage tree for a detector"""
        if detector_id not in self.detectors:
            return None
        
        detector = self.detectors[detector_id]
        lineage = {
            "id": detector.id,
            "cell_type": detector.cell_type.value,
            "parent": detector.lineage,
            "children": [],
            "epitopes": [{"pattern": e.pattern, "type": e.pattern_type, "affinity": e.affinity} 
                        for e in detector.epitopes],
            "stats": {
                "activations": detector.activation_count,
                "true_positives": detector.true_positive_count,
                "false_positives": detector.false_positive_count,
                "fitness": detector.calculate_fitness(),
                "specificity": detector.specificity
            }
        }
        
        # Find children
        for d in self.detectors.values():
            if d.lineage == detector_id:
                lineage["children"].append(d.id)
        
        return lineage
    
    def export_immune_state(self) -> Dict:
        """Export complete immune state for persistence"""
        with self._lock:
            return {
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "detectors": {
                    det_id: {
                        "id": d.id,
                        "cell_type": d.cell_type.value,
                        "epitopes": [{"pattern": e.pattern, "type": e.pattern_type, "affinity": e.affinity} for e in d.epitopes],
                        "affinity_threshold": d.affinity_threshold,
                        "activation_count": d.activation_count,
                        "true_positive_count": d.true_positive_count,
                        "false_positive_count": d.false_positive_count,
                        "lineage": d.lineage,
                        "mutation_rate": d.mutation_rate,
                        "is_active": d.is_active,
                        "created_at": d.created_at.isoformat()
                    }
                    for det_id, d in self.detectors.items() if d.is_active
                },
                "memory": {
                    "epitopes": [
                        {"pattern": e.pattern, "type": e.pattern_type, "data": data}
                        for e, data in self.memory.epitopes.items()
                    ]
                },
                "stats": self.stats
            }
    
    def import_immune_state(self, state: Dict):
        """Import immune state from persistence"""
        with self._lock:
            # Restore detectors
            self.detectors.clear()
            for det_id, data in state.get("detectors", {}).items():
                detector = Detector(
                    id=data["id"],
                    cell_type=CellType(data["cell_type"]),
                    affinity_threshold=data["affinity_threshold"],
                    activation_count=data["activation_count"],
                    true_positive_count=data["true_positive_count"],
                    false_positive_count=data["false_positive_count"],
                    lineage=data["lineage"],
                    mutation_rate=data["mutation_rate"],
                    is_active=data["is_active"]
                )
                detector.created_at = datetime.fromisoformat(data["created_at"])
                for e_data in data["epitopes"]:
                    detector.epitopes.add(Epitope(
                        pattern=e_data["pattern"],
                        pattern_type=e_data["type"],
                        affinity=e_data["affinity"]
                    ))
                self.detectors[det_id] = detector
            
            # Restore memory
            self.memory = ImmuneMemory()
            for ep_data in state.get("memory", {}).get("epitopes", []):
                epitope = Epitope(pattern=ep_data["pattern"], pattern_type=ep_data["type"])
                self.memory.epitopes[epitope] = ep_data.get("data", {})
            
            self.stats = state.get("stats", self.stats)
            
            logger.info(f"Imported immune state: {len(self.detectors)} detectors, {len(self.memory.epitopes)} memory epitopes")


# ============================================================================
# ADVERSARIAL SELF-RED-TEAMING
# ============================================================================

class AdversarialRedTeamer:
    """
    Continuous self-red-teaming: the immune system attacks itself
    to find blind spots before adversaries do.
    """
    
    def __init__(self, cis: CognitiveImmuneSystem):
        self.cis = cis
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.attack_patterns = self._load_attack_patterns()
        self.results_history = deque(maxlen=1000)
    
    def _load_attack_patterns(self) -> List[Dict]:
        """Load known attack patterns for testing"""
        return [
            {"name": "process_injection", "technique": "T1055", "epitopes": ["process_injection"]},
            {"name": "command_execution", "technique": "T1059", "epitopes": ["command_line_execution"]},
            {"name": "credential_dumping", "technique": "T1003", "epitopes": ["credential_dumping"]},
            {"name": "data_encryption", "technique": "T1486", "epitopes": ["rapid_file_encryption"]},
            {"name": "obfuscation", "technique": "T1027", "epitopes": ["obfuscated_code"]},
            {"name": "c2_beaconing", "technique": "T1071", "epitopes": ["periodic_network_callback"]},
            {"name": "lolbin", "technique": "T1218", "epitopes": ["lolbin_execution"]},
            {"name": "registry_persistence", "technique": "T1547", "epitopes": ["registry_persistence"]},
        ]
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._red_team_loop, daemon=True)
        self._thread.start()
        logger.info("Adversarial Red Teamer started")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _red_team_loop(self):
        """Continuous self-attack loop"""
        while self.running:
            try:
                # Run attack simulation every 5 minutes
                time.sleep(300)
                
                if not self.running:
                    break
                
                self._run_attack_simulation()
                
            except Exception as e:
                logger.error(f"Red team loop error: {e}")
    
    def _run_attack_simulation(self):
        """Simulate attacks against own detectors"""
        for pattern in self.attack_patterns:
            # Create test epitopes
            test_epitopes = [
                Epitope(pattern=e, pattern_type="behavior", affinity=0.9)
                for e in pattern["epitopes"]
            ]
            
            for epitope in test_epitopes:
                # Present to immune system
                self.cis._present_antigen(epitope, {
                    "source": "red_team",
                    "technique": pattern["technique"],
                    "simulation": True
                })
        
        # Check detection rate
        status = self.cis.get_immune_status()
        detection_rate = status["stats"]["true_positives"] / max(1, status["stats"]["total_detections"])
        
        self.results_history.append({
            "timestamp": datetime.now(),
            "detection_rate": detection_rate,
            "total_detectors": status["total_detectors"],
            "false_positive_rate": status["stats"]["false_positives"] / max(1, status["stats"]["total_detections"])
        })
        
        logger.info(f"Red team simulation complete: detection_rate={detection_rate:.2%}, "
                   f"detectors={status['total_detectors']}")


# ============================================================================
# PREDICTIVE THREAT EVOLUTION
# ============================================================================

class ThreatEvolutionPredictor:
    """
    Predict how threats will evolve based on:
    1. Historical mutation patterns
    2. MITRE ATT&CK technique chaining
    3. Adversary TTP evolution
    4. Vulnerability exploitation trends
    """
    
    def __init__(self, cis: CognitiveImmuneSystem):
        self.cis = cis
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.evolution_models = {}
        self.predictions = deque(maxlen=1000)
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._prediction_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _prediction_loop(self):
        while self.running:
            time.sleep(3600)  # Hourly predictions
            if not self.running:
                break
            self._generate_predictions()
    
    def _generate_predictions(self):
        """Generate threat evolution predictions"""
        # Analyze recent threat patterns
        recent_threats = list(self.cis.memory.response_history)[-1000:]
        
        # Group by technique
        technique_counts = defaultdict(int)
        for event in recent_threats:
            tech = event.get("metadata", {}).get("technique")
            if tech:
                technique_counts[tech] += 1
        
        # Predict next techniques based on ATT&CK chaining
        # (simplified - would use Markov chains or graph analysis)
        predictions = []
        for tech, count in sorted(technique_counts.items(), key=lambda x: -x[1])[:5]:
            predictions.append({
                "technique": tech,
                "probability": min(0.9, count / 100),
                "reasoning": f"Observed {count} times recently",
                "predicted_at": datetime.now().isoformat()
            })
        
        for pred in predictions:
            self.predictions.append(pred)
            
            # Pre-emptively create detectors for predicted threats
            self._create_predictive_detectors(pred)
        
        logger.info(f"Generated {len(predictions)} threat evolution predictions")
    
    def _create_predictive_detectors(self, prediction: Dict):
        """Create detectors for predicted threats"""
        tech = prediction["technique"]
        # Map MITRE technique to behavior patterns
        tech_patterns = {
            "T1055": ["process_injection", "thread_hijacking", "apc_injection"],
            "T1059": ["powershell_execution", "cmd_execution", "wscript_execution"],
            "T1003": ["lsass_dump", "sam_dump", "ntds_dump"],
            "T1486": ["rapid_encryption", "file_renaming", "ransom_note"],
            "T1027": ["base64_encoding", "xor_encoding", "packed_executable"],
            "T1071": ["dns_beaconing", "http_beaconing", "https_beaconing"],
        }
        
        patterns = tech_patterns.get(tech, [tech.lower()])
        
        for pattern in patterns:
            epitope = Epitope(
                pattern=pattern,
                pattern_type="behavior",
                affinity=0.8,
                metadata={"predicted": True, "source_technique": tech, "confidence": prediction["probability"]}
            )
            
            # Create predictive detector
            detector = Detector(
                id=f"predictive_{tech}_{uuid.uuid4().hex[:8]}",
                cell_type=CellType.NAIVE_DETECTOR,
                affinity_threshold=0.6,
                mutation_rate=0.2
            )
            detector.epitopes.add(epitope)
            detector.lineage = f"predictive_{tech}"
            
            with self.cis._lock:
                self.cis.detectors[detector.id] = detector


# ============================================================================
# SEMANTIC INTEGRITY VERIFICATION
# ============================================================================

class SemanticIntegrityVerifier:
    """
    Verify semantic integrity of code and behavior - detect
    adversarial manipulation of the security system itself.
    """
    
    def __init__(self, cis: CognitiveImmuneSystem):
        self.cis = cis
        self.baselines: Dict[str, str] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        self.running = True
        self._capture_baselines()
        self._thread = threading.Thread(target=self._verification_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _capture_baselines(self):
        """Capture semantic baselines of critical components"""
        import inspect
        
        # Baseline critical functions
        critical_modules = [
            "cognitive_immune_system",
            "ai_security_engine",
            "threat_feed_aggregator",
            "quarantine_core",
            "sensor_hub"
        ]
        
        for mod_name in critical_modules:
            try:
                mod = __import__(mod_name)
                for name, obj in inspect.getmembers(mod):
                    if inspect.isfunction(obj) and not name.startswith("_"):
                        try:
                            source = inspect.getsource(obj)
                            self.baselines[f"{mod_name}.{name}"] = hashlib.sha256(source.encode()).hexdigest()
                        except:
                            pass
            except:
                pass
    
    def _verification_loop(self):
        while self.running:
            time.sleep(600)  # Every 10 minutes
            if not self.running:
                break
            self._verify_integrity()
    
    def _verify_integrity(self):
        """Verify semantic integrity of critical code"""
        import inspect
        
        for key, baseline_hash in self.baselines.items():
            try:
                mod_name, func_name = key.rsplit(".", 1)
                mod = __import__(mod_name)
                obj = getattr(mod, func_name)
                source = inspect.getsource(obj)
                current_hash = hashlib.sha256(source.encode()).hexdigest()
                
                if current_hash != baseline_hash:
                    # SEMANTIC DRIFT DETECTED
                    self.cis._emit_signal(Signal(
                        signal_type=SignalType.DANGER,
                        source_id="semantic_integrity",
                        target_id=None,
                        payload={
                            "alert": "semantic_drift_detected",
                            "component": key,
                            "baseline": baseline_hash[:16],
                            "current": current_hash[:16]
                        }
                    ))
                    
                    logger.critical(f"SEMANTIC DRIFT: {key} has been modified!")
                    
            except Exception as e:
                logger.error(f"Integrity verification failed for {key}: {e}")


# ============================================================================
# FACTORY & INTEGRATION
# ============================================================================

def create_cognitive_immune_system(config: Optional[Dict] = None) -> CognitiveImmuneSystem:
    """Factory function to create CIS with all sub-components"""
    cis = CognitiveImmuneSystem(config=config)
    
    # Create sub-components
    red_teamer = AdversarialRedTeamer(cis)
    predictor = ThreatEvolutionPredictor(cis)
    verifier = SemanticIntegrityVerifier(cis)
    
    # Attach to CIS for access
    cis.red_teamer = red_teamer
    cis.predictor = predictor
    cis.verifier = verifier
    
    return cis


def integrate_with_downpour(cis: CognitiveImmuneSystem, downpour_app):
    """Integrate CIS with main Downpour application"""
    # Wire sensor hub
    if hasattr(downpour_app, 'sensor_hub') and downpour_app.sensor_hub:
        cis.sensor_hub = downpour_app.sensor_hub
    
    # Wire AI engine
    if hasattr(downpour_app, 'ai_engine') and downpour_app.ai_engine:
        cis.ai_engine = downpour_app.ai_engine
    
    # Wire threat database
    if hasattr(downpour_app, 'threat_db') and downpour_app.threat_db:
        cis.threat_db = downpour_app.threat_db
    elif hasattr(downpour_app, 'ultimate_threat_intel_db'):
        cis.threat_db = downpour_app.ultimate_threat_intel_db
    
    # Wire quarantine
    if hasattr(downpour_app, 'quarantine_core') and downpour_app.quarantine_core:
        cis.quarantine = downpour_app.quarantine_core
    
    # Start CIS
    cis.start()
    
    # Start sub-components
    cis.red_teamer.start()
    cis.predictor.start()
    cis.verifier.start()
    
    # Add CIS status to Downpour UI
    if hasattr(downpour_app, '_add_status_panel'):
        downpour_app._add_status_panel("Cognitive Immune System", cis.get_immune_status)
    
    logger.info("Cognitive Immune System integrated with Downpour")
    
    return cis


# ============================================================================
# DEMO / TEST
# ============================================================================

if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.INFO)
    
    cis = create_cognitive_immune_system({
        "naive_pool_size": 100,
        "max_detectors": 1000,
        "affinity_threshold": 0.7,
        "clonal_expansion_factor": 3,
        "mutation_rate": 0.1
    })
    
    print("=== Cognitive Immune System Test ===")
    print(f"Initial detectors: {len(cis.detectors)}")
    
    # Test antigen presentation
    test_epitope = Epitope(pattern="malicious_process_injection", pattern_type="behavior", affinity=0.9)
    cis._present_antigen(test_epitope, {"source": "test", "technique": "T1055"})
    
    print(f"After presentation: {len(cis.detectors)} detectors")
    
    status = cis.get_immune_status()
    print(f"Status: {json.dumps(status, indent=2, default=str)}")
    
    # Test evolution
    cis._clonal_selection()
    cis._somatic_hypermutation()
    print(f"After evolution: {len(cis.detectors)} detectors")
    
    print("=== Test Complete ===")