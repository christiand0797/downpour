"""
Machine Learning Optimization Engine for Downpour v28 Titanium
Learns from device characteristics and optimizes performance
"""

import logging
import os
import json
import time
import hashlib
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
import pickle
import io

_ml_logger = logging.getLogger(__name__)

# FIX-v28p41: Restricted unpickler — prevents arbitrary code execution from
# tampered .pkl files.  Only allows builtins and dataclass types used by this
# module.
_SAFE_MODULES = {'builtins', 'collections', 'datetime', 'dataclasses',
                 'copy', __name__}

class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that refuses to instantiate objects from unexpected modules."""
    def find_class(self, module: str, name: str):
        if module.split('.')[0] in _SAFE_MODULES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Blocked unpickling of {module}.{name} — not in allowlist")

@dataclass
class DeviceProfile:
    """Device profile data structure"""
    device_id: str
    device_type: str
    cpu_cores: int
    memory_gb: int
    gpu_memory_mb: int
    storage_type: str
    performance_score: float
    battery_present: bool
    timestamp: float

@dataclass
class OptimizationResult:
    """Optimization result data structure"""
    device_id: str
    strategy: str
    settings: Dict[str, Any]
    performance_metrics: Dict[str, float]
    user_satisfaction: float
    timestamp: float

class MLOptimizationEngine:
    """Machine Learning-based optimization engine"""
    
    def __init__(self):
        self.device_profiles = []
        self.optimization_history = []
        self.performance_models = {}
        self.optimization_strategies = {}
        self.learning_data = {}
        
        # Load existing data if available
        self._load_learning_data()
        
    def generate_device_fingerprint(self, device_profile: Dict[str, Any]) -> str:
        """Generate unique device fingerprint"""
        try:
            # Create fingerprint from key hardware characteristics
            fingerprint_data = {
                'cpu_name': device_profile.get('hardware_profile', {}).get('cpu', {}).get('name', ''),
                'memory_gb': device_profile.get('hardware_profile', {}).get('memory', {}).get('total_gb', 0),
                'gpu_name': device_profile.get('hardware_profile', {}).get('graphics', {}).get('primary_gpu', ''),
                'storage_type': device_profile.get('hardware_profile', {}).get('storage', {}).get('primary_drive_type', ''),
                'screen_resolution': 'unknown'
            }
            
            # Add monitor info if available
            monitors = device_profile.get('hardware_profile', {}).get('peripherals', {}).get('monitors', [])
            if monitors:
                fingerprint_data['screen_resolution'] = monitors[0].get('resolution', 'unknown')
            
            # Create hash
            fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
            device_id = hashlib.md5(fingerprint_str.encode()).hexdigest()[:12]
            
            return device_id
            
        except Exception as exc:
            _ml_logger.debug("Device fingerprint generation failed: %s", exc)
            return hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
    
    def analyze_device_characteristics(self, device_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze device characteristics for ML optimization"""
        characteristics = {
            'device_class': self._classify_device(device_profile),
            'performance_class': self._classify_performance(device_profile),
            'usage_pattern': self._predict_usage_pattern(device_profile),
            'optimization_targets': self._determine_optimization_targets(device_profile),
            'risk_factors': self._identify_risk_factors(device_profile)
        }
        
        return characteristics
    
    def _classify_device(self, device_profile: Dict[str, Any]) -> str:
        """Classify device type based on characteristics"""
        hardware = device_profile.get('hardware_profile', {})
        
        cpu_cores = hardware.get('cpu', {}).get('cores', 1)
        memory_gb = hardware.get('memory', {}).get('total_gb', 0)
        gpu_memory = hardware.get('graphics', {}).get('gpu_memory_mb', 0)
        battery = hardware.get('sensors', {}).get('battery') is not None
        
        # Classification logic
        if battery and memory_gb <= 16 and cpu_cores <= 8:
            return 'ultrabook'
        elif battery and memory_gb >= 16 and cpu_cores >= 6:
            return 'gaming_laptop'
        elif battery:
            return 'standard_laptop'
        elif not battery and memory_gb >= 32 and cpu_cores >= 8:
            return 'workstation'
        elif not battery and memory_gb >= 16 and cpu_cores >= 6:
            return 'performance_desktop'
        elif not battery:
            return 'standard_desktop'
        else:
            return 'unknown'
    
    def _classify_performance(self, device_profile: Dict[str, Any]) -> str:
        """Classify device performance level"""
        performance = device_profile.get('performance_profile', {})
        hardware = device_profile.get('hardware_profile', {})
        
        score = performance.get('overall_score', 0)
        memory_gb = hardware.get('memory', {}).get('total_gb', 0)
        gpu_memory = hardware.get('graphics', {}).get('gpu_memory_mb', 0)
        
        # Enhanced classification with multiple factors
        if score >= 80 and memory_gb >= 32 and gpu_memory >= 8192:
            return 'enthusiast'
        elif score >= 70 and memory_gb >= 16 and gpu_memory >= 4096:
            return 'high_end'
        elif score >= 50 and memory_gb >= 8 and gpu_memory >= 2048:
            return 'performance'
        elif score >= 30 and memory_gb >= 4:
            return 'mainstream'
        else:
            return 'budget'
    
    def _predict_usage_pattern(self, device_profile: Dict[str, Any]) -> str:
        """Predict likely usage pattern based on device characteristics"""
        device_class = self._classify_device(device_profile)
        performance_class = self._classify_performance(device_profile)
        
        # Usage pattern prediction
        patterns = {
            'ultrabook': 'productivity_mobility',
            'gaming_laptop': 'gaming_entertainment',
            'standard_laptop': 'general_productivity',
            'workstation': 'professional_work',
            'performance_desktop': 'content_creation',
            'standard_desktop': 'general_use'
        }
        
        base_pattern = patterns.get(device_class, 'general_use')
        
        # Adjust based on performance
        if performance_class in ['enthusiast', 'high_end']:
            if device_class in ['gaming_laptop', 'performance_desktop']:
                base_pattern = 'intensive_gaming'
            elif device_class == 'workstation':
                base_pattern = 'professional_intensive'
        
        return base_pattern
    
    def _determine_optimization_targets(self, device_profile: Dict[str, Any]) -> List[str]:
        """Determine optimization targets based on device characteristics"""
        targets = []
        
        device_class = self._classify_device(device_profile)
        performance_class = self._classify_performance(device_profile)
        usage_pattern = self._predict_usage_pattern(device_profile)
        
        # Base targets
        targets.append('stability')
        targets.append('responsiveness')
        
        # Device-specific targets
        if 'laptop' in device_class:
            targets.append('battery_efficiency')
            targets.append('thermal_management')
        
        if performance_class in ['enthusiast', 'high_end']:
            targets.append('maximum_performance')
            targets.append('resource_utilization')
        
        # Usage pattern targets
        if 'gaming' in usage_pattern:
            targets.append('fps_optimization')
            targets.append('graphics_performance')
        elif 'productivity' in usage_pattern:
            targets.append('multitasking')
            targets.append('application_responsiveness')
        elif 'professional' in usage_pattern:
            targets.append('compute_performance')
            targets.append('data_processing')
        
        # Battery-specific targets
        if device_profile.get('hardware_profile', {}).get('sensors', {}).get('battery'):
            targets.append('power_optimization')
        
        return list(set(targets))  # Remove duplicates
    
    def _identify_risk_factors(self, device_profile: Dict[str, Any]) -> List[str]:
        """Identify potential performance risk factors"""
        risks = []
        
        hardware = device_profile.get('hardware_profile', {})
        
        # Memory risks
        memory_gb = hardware.get('memory', {}).get('total_gb', 0)
        if memory_gb < 8:
            risks.append('low_memory')
        elif memory_gb < 16:
            risks.append('moderate_memory')
        
        # Storage risks
        storage_type = hardware.get('storage', {}).get('primary_drive_type', '')
        if storage_type == 'hdd':
            risks.append('slow_storage')
        
        # GPU risks
        gpu_memory = hardware.get('graphics', {}).get('gpu_memory_mb', 0)
        if gpu_memory < 2048:
            risks.append('integrated_graphics')
        elif gpu_memory < 4096:
            risks.append('limited_graphics')
        
        # CPU risks
        cpu_cores = hardware.get('cpu', {}).get('cores', 1)
        if cpu_cores < 4:
            risks.append('low_cpu_cores')
        
        # Thermal risks (laptops)
        device_type = device_profile.get('device_type', '')
        if device_type == 'laptop':
            risks.append('thermal_throttling')
        
        # Battery risks
        if hardware.get('sensors', {}).get('battery'):
            battery_percent = hardware.get('sensors', {}).get('battery', {}).get('percent', 100)
            if battery_percent < 20:
                risks.append('low_battery')
        
        return risks
    
    def generate_optimization_strategy(self, device_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ML-based optimization strategy"""
        device_id = self.generate_device_fingerprint(device_profile)
        characteristics = self.analyze_device_characteristics(device_profile)
        
        # Check for similar devices in history
        similar_devices = self._find_similar_devices(device_profile)
        
        if similar_devices:
            # Use learned optimization from similar devices
            strategy = self._learn_from_similar_devices(similar_devices, characteristics)
        else:
            # Generate new strategy based on characteristics
            strategy = self._generate_baseline_strategy(characteristics)
        
        # Add adaptive elements
        strategy['adaptive_elements'] = self._generate_adaptive_elements(characteristics)
        strategy['learning_components'] = self._generate_learning_components(characteristics)
        
        # Store for learning
        self._store_device_profile(device_id, device_profile)
        
        return strategy
    
    def _find_similar_devices(self, device_profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find similar devices in history"""
        similar_devices = []
        
        current_device_class = self._classify_device(device_profile)
        current_performance_class = self._classify_performance(device_profile)
        
        for profile in self.device_profiles:
            # Check device class similarity
            profile_class = self._classify_device(profile)
            profile_performance = self._classify_performance(profile)
            
            if profile_class == current_device_class:
                similarity_score = 0
                
                # Performance class similarity
                _perf_classes = ['budget', 'mainstream', 'performance', 'high_end', 'enthusiast']
                if profile_performance == current_performance_class:
                    similarity_score += 50
                elif (profile_performance in _perf_classes and current_performance_class in _perf_classes
                      and abs(_perf_classes.index(profile_performance) - _perf_classes.index(current_performance_class)) <= 1):
                    similarity_score += 25
                
                # Hardware similarity
                current_memory = device_profile.get('hardware_profile', {}).get('memory', {}).get('total_gb', 0)
                profile_memory = profile.get('hardware_profile', {}).get('memory', {}).get('total_gb', 0)
                
                memory_diff = abs(current_memory - profile_memory)
                if memory_diff <= 4:
                    similarity_score += 30
                elif memory_diff <= 8:
                    similarity_score += 15
                
                if similarity_score >= 50:  # Similarity threshold
                    similar_devices.append({
                        'profile': profile,
                        'similarity_score': similarity_score,
                        'optimization_results': self._get_optimization_results_for_device(profile.get('device_id', ''))
                    })
        
        # Sort by similarity score
        similar_devices.sort(key=lambda x: x['similarity_score'], reverse=True)
        
        return similar_devices[:5]  # Return top 5 similar devices
    
    def _learn_from_similar_devices(self, similar_devices: List[Dict[str, Any]], characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """Learn optimization strategies from similar devices"""
        if not similar_devices:
            return self._generate_baseline_strategy(characteristics)
        
        # Aggregate successful strategies from similar devices
        successful_strategies = {}
        strategy_performance = {}
        
        for device_data in similar_devices:
            optimization_results = device_data.get('optimization_results', [])
            
            for result in optimization_results:
                strategy = result.get('strategy', 'unknown')
                satisfaction = result.get('user_satisfaction', 0)
                performance = result.get('performance_metrics', {})
                
                if strategy not in successful_strategies:
                    successful_strategies[strategy] = []
                    strategy_performance[strategy] = []
                
                successful_strategies[strategy].append(result)
                strategy_performance[strategy].append(satisfaction)
        
        # Find best performing strategy
        best_strategy = 'baseline'
        best_performance = 0
        
        for strategy, performances in strategy_performance.items():
            avg_performance = sum(performances) / len(performances)
            if avg_performance > best_performance:
                best_performance = avg_performance
                best_strategy = strategy
        
        # Generate strategy based on best performer
        if best_strategy != 'baseline' and successful_strategies.get(best_strategy):
            best_result = successful_strategies[best_strategy][0]
            return {
                'strategy_type': 'learned',
                'base_strategy': best_strategy,
                'settings': best_result.get('settings', {}),
                'expected_performance': best_performance,
                'confidence': min(len(successful_strategies[best_strategy]) / 3, 1.0),
                'adaptations': self._adapt_strategy_for_current_device(best_result.get('settings', {}), characteristics)
            }
        else:
            return self._generate_baseline_strategy(characteristics)
    
    def _generate_baseline_strategy(self, characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate baseline optimization strategy"""
        device_class = characteristics['device_class']
        performance_class = characteristics['performance_class']
        usage_pattern = characteristics['usage_pattern']
        targets = characteristics['optimization_targets']
        risks = characteristics['risk_factors']
        
        strategy = {
            'strategy_type': 'baseline',
            'device_class': device_class,
            'performance_class': performance_class,
            'usage_pattern': usage_pattern,
            'settings': {},
            'target_optimizations': targets,
            'risk_mitigations': risks
        }
        
        # Generate settings based on characteristics
        settings = self._generate_settings_for_characteristics(characteristics)
        strategy['settings'] = settings
        
        return strategy
    
    def _generate_settings_for_characteristics(self, characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate optimization settings based on device characteristics"""
        settings = {
            'performance_mode': 'balanced',
            'resource_allocation': 'adaptive',
            'feature_set': 'core',
            'ui_optimization': 'standard',
            'monitoring_intensity': 'moderate',
            'security_level': 'standard'
        }
        
        device_class = characteristics['device_class']
        performance_class = characteristics['performance_class']
        usage_pattern = characteristics['usage_pattern']
        targets = characteristics['optimization_targets']
        risks = characteristics['risk_factors']
        
        # Performance mode based on performance class
        performance_modes = {
            'enthusiast': 'maximum',
            'high_end': 'high',
            'performance': 'enhanced',
            'mainstream': 'balanced',
            'budget': 'efficient'
        }
        settings['performance_mode'] = performance_modes.get(performance_class, 'balanced')
        
        # Resource allocation based on device class
        if device_class in ['workstation', 'performance_desktop']:
            settings['resource_allocation'] = 'generous'
        elif device_class in ['gaming_laptop', 'ultrabook']:
            settings['resource_allocation'] = 'adaptive'
        else:
            settings['resource_allocation'] = 'conservative'
        
        # Feature set based on usage pattern
        if 'gaming' in usage_pattern:
            settings['feature_set'] = 'gaming_optimized'
        elif 'professional' in usage_pattern:
            settings['feature_set'] = 'professional'
        elif 'productivity' in usage_pattern:
            settings['feature_set'] = 'productivity'
        else:
            settings['feature_set'] = 'general'
        
        # UI optimization based on graphics capabilities
        if 'integrated_graphics' in risks:
            settings['ui_optimization'] = 'lightweight'
        elif 'limited_graphics' in risks:
            settings['ui_optimization'] = 'standard'
        else:
            settings['ui_optimization'] = 'enhanced'
        
        # Monitoring intensity based on targets
        if 'maximum_performance' in targets:
            settings['monitoring_intensity'] = 'high'
        elif 'battery_efficiency' in targets:
            settings['monitoring_intensity'] = 'low'
        else:
            settings['monitoring_intensity'] = 'moderate'
        
        # Security level based on device type
        if device_class == 'workstation':
            settings['security_level'] = 'high'
        elif device_class in ['ultrabook', 'standard_laptop']:
            settings['security_level'] = 'balanced'
        else:
            settings['security_level'] = 'standard'
        
        return settings
    
    def _adapt_strategy_for_current_device(self, base_settings: Dict[str, Any], characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt learned strategy for current device characteristics"""
        adapted_settings = base_settings.copy()
        
        risks = characteristics['risk_factors']
        targets = characteristics['optimization_targets']
        
        # Adapt for memory risks
        if 'low_memory' in risks:
            adapted_settings['resource_allocation'] = 'minimal'
            adapted_settings['feature_set'] = 'essential'
        elif 'moderate_memory' in risks:
            adapted_settings['resource_allocation'] = 'conservative'
        
        # Adapt for storage risks
        if 'slow_storage' in risks:
            adapted_settings['monitoring_intensity'] = 'low'
            adapted_settings['cache_usage'] = 'minimal'
        
        # Adapt for thermal risks
        if 'thermal_throttling' in risks:
            adapted_settings['performance_mode'] = 'thermal_aware'
            adapted_settings['thermal_management'] = 'aggressive'
        
        # Adapt for battery risks
        if 'low_battery' in risks:
            adapted_settings['performance_mode'] = 'power_saving'
            adapted_settings['feature_set'] = 'battery_optimized'
        
        return adapted_settings
    
    def _generate_adaptive_elements(self, characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate adaptive optimization elements"""
        adaptive_elements = {
            'dynamic_performance_scaling': True,
            'resource_monitoring': True,
            'thermal_aware_optimization': 'laptop' in characteristics['device_class'],
            'battery_aware_optimization': 'battery_efficiency' in characteristics['optimization_targets'],
            'usage_pattern_learning': True,
            'performance_feedback_loop': True
        }
        
        return adaptive_elements
    
    def _generate_learning_components(self, characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate machine learning components"""
        learning_components = {
            'performance_prediction': True,
            'user_behavior_learning': True,
            'device_profiling': True,
            'optimization_history': True,
            'adaptive_algorithm_selection': True,
            'continuous_improvement': True
        }
        
        return learning_components
    
    def record_optimization_result(self, device_id: str, strategy: str, settings: Dict[str, Any], 
                                 performance_metrics: Dict[str, float], user_satisfaction: float):
        """Record optimization result for learning"""
        result = OptimizationResult(
            device_id=device_id,
            strategy=strategy,
            settings=settings,
            performance_metrics=performance_metrics,
            user_satisfaction=user_satisfaction,
            timestamp=time.time()
        )
        
        self.optimization_history.append(result)
        self._save_learning_data()
    
    def _store_device_profile(self, device_id: str, device_profile: Dict[str, Any]):
        """Store device profile for learning"""
        # Extract key information for storage
        hardware = device_profile.get('hardware_profile', {})
        performance = device_profile.get('performance_profile', {})
        
        profile = DeviceProfile(
            device_id=device_id,
            device_type=device_profile.get('device_type', 'unknown'),
            cpu_cores=hardware.get('cpu', {}).get('cores', 1),
            memory_gb=hardware.get('memory', {}).get('total_gb', 0),
            gpu_memory_mb=hardware.get('graphics', {}).get('gpu_memory_mb', 0),
            storage_type=hardware.get('storage', {}).get('primary_drive_type', 'unknown'),
            performance_score=performance.get('overall_score', 0),
            battery_present=hardware.get('sensors', {}).get('battery') is not None,
            timestamp=time.time()
        )
        
        self.device_profiles.append(profile)
        self._save_learning_data()
    
    def _get_optimization_results_for_device(self, device_id: str) -> List[Dict[str, Any]]:
        """Get optimization results for a specific device"""
        results = []
        for result in self.optimization_history:
            if result.device_id == device_id:
                results.append(asdict(result))
        return results
    
    def _load_learning_data(self):
        """Load learning data from files."""
        _base = os.path.dirname(os.path.abspath(__file__))
        try:
            profiles_file = os.path.join(_base, 'device_profiles.pkl')
            if os.path.exists(profiles_file):
                with open(profiles_file, 'rb') as f:
                    self.device_profiles = _RestrictedUnpickler(f).load()
            history_file = os.path.join(_base, 'optimization_history.pkl')
            if os.path.exists(history_file):
                with open(history_file, 'rb') as f:
                    self.optimization_history = _RestrictedUnpickler(f).load()
        except Exception as exc:
            _ml_logger.debug("Could not load learning data: %s", exc)
            self.device_profiles = []
            self.optimization_history = []

    def _save_learning_data(self):
        """Save learning data to files."""
        _base = os.path.dirname(os.path.abspath(__file__))
        try:
            with open(os.path.join(_base, 'device_profiles.pkl'), 'wb') as f:
                pickle.dump(self.device_profiles, f)
            with open(os.path.join(_base, 'optimization_history.pkl'), 'wb') as f:
                pickle.dump(self.optimization_history, f)
        except Exception as exc:
            _ml_logger.debug("Could not save learning data: %s", exc)
    
    def get_optimization_summary(self) -> Dict[str, Any]:
        """Get summary of optimization learning"""
        summary = {
            'total_devices_learned': len(self.device_profiles),
            'total_optimizations': len(self.optimization_history),
            'device_types': {},
            'performance_classes': {},
            'successful_strategies': {},
            'average_satisfaction': 0
        }
        
        if self.optimization_history:
            satisfaction_scores = [result.user_satisfaction for result in self.optimization_history]
            summary['average_satisfaction'] = sum(satisfaction_scores) / len(satisfaction_scores)
        
        # Count device types
        for profile in self.device_profiles:
            device_type = profile.device_type
            summary['device_types'][device_type] = summary['device_types'].get(device_type, 0) + 1
        
        return summary

# Usage example
if __name__ == "__main__":
    engine = MLOptimizationEngine()
    
    # Example device profile (would come from device_adaptation_engine)
    example_profile = {
        'device_type': 'laptop',
        'hardware_profile': {
            'cpu': {'name': 'Intel Core i7-1165G7', 'cores': 4},
            'memory': {'total_gb': 16},
            'graphics': {'gpu_memory_mb': 2048, 'primary_gpu': 'integrated'},
            'storage': {'primary_drive_type': 'ssd'},
            'sensors': {'battery': {'percent': 85}}
        },
        'performance_profile': {
            'overall_score': 65,
            'performance_tier': 'performance'
        }
    }
    
    strategy = engine.generate_optimization_strategy(example_profile)
    
    print("🧠 ML OPTIMIZATION STRATEGY GENERATED")
    print("=" * 50)
    print(f"Strategy Type: {strategy['strategy_type']}")
    print(f"Performance Mode: {strategy['settings'].get('performance_mode', 'unknown')}")
    print(f"Resource Allocation: {strategy['settings'].get('resource_allocation', 'unknown')}")
    print(f"Feature Set: {strategy['settings'].get('feature_set', 'unknown')}")
    
    summary = engine.get_optimization_summary()
    print(f"\n📊 LEARNING SUMMARY:")
    print(f"Devices Learned: {summary['total_devices_learned']}")
    print(f"Optimizations: {summary['total_optimizations']}")
    print(f"Average Satisfaction: {summary['average_satisfaction']:.2f}")
