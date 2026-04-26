#!/usr/bin/env python3
"""
__version__ = "29.0.0"
Enhanced Hardware Integration for Downpour v29 Titanium
Advanced hardware monitoring with responsive gauges and real-time performance data
"""

import os
import sys
import time
import threading
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging

# Add current directory to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

try:
    from advanced_hardware_monitor import AdvancedHardwareMonitor, HardwareMetrics, GaugeConfiguration
    from advanced_gauge_system import AdvancedGaugeSystem, GaugeType, GaugeStyle, AnimationType
    ADVANCED_HARDWARE_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).warning("Advanced hardware monitoring not available: %s", e)
    ADVANCED_HARDWARE_AVAILABLE = False
    # Provide a fallback HardwareMetrics dataclass when advanced module isn't available
    @dataclass
    class HardwareMetrics:
        timestamp: float = 0.0
        cpu_percent: float = 0.0
        cpu_frequency: float = 0.0
        cpu_temperature: float = 0.0
        cpu_cores_active: int = 0
        memory_percent: float = 0.0
        memory_used_gb: float = 0.0
        memory_total_gb: float = 0.0
        memory_available_gb: float = 0.0
        disk_percent: float = 0.0
        disk_used_gb: float = 0.0
        disk_total_gb: float = 0.0
        disk_read_mb_s: float = 0.0
        disk_write_mb_s: float = 0.0
        network_sent_mb_s: float = 0.0
        network_recv_mb_s: float = 0.0
        gpu_percent: float = 0.0
        gpu_memory_percent: float = 0.0
        gpu_temperature: float = 0.0
        gpu_frequency: float = 0.0
        battery_percent: float = 0.0
        battery_plugged: bool = True
        process_count: int = 0
        thread_count: int = 0
        boot_time: float = 0.0
        uptime_hours: float = 0.0
        system_load_avg: list = field(default_factory=lambda: [0.0, 0.0, 0.0])
        performance_level: Optional[str] = None
        health_score: float = 0.0
    GaugeConfiguration = None

try:
    import tkinter as tk
    from tkinter import ttk, Canvas
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

@dataclass
class EnhancedHardwareConfig:
    """Enhanced hardware configuration"""
    enable_advanced_monitoring: bool = True
    enable_responsive_gauges: bool = True
    update_interval: float = 0.5
    history_size: int = 100
    smoothing_factor: float = 0.3
    enable_predictions: bool = True
    enable_alerts: bool = True
    enable_gpu_monitoring: bool = True
    enable_network_monitoring: bool = True
    enable_battery_monitoring: bool = True
    enable_temperature_monitoring: bool = True
    gauge_animation_type: str = "smooth"
    gauge_animation_speed: float = 0.15
    enable_glow_effects: bool = True
    enable_gradient_colors: bool = True
    performance_thresholds: Dict[str, float] = field(default_factory=lambda: {
        'cpu': 80.0,
        'memory': 85.0,
        'disk': 90.0,
        'gpu': 85.0,
        'temperature': 75.0,
        'network': 50.0,
        'battery': 20.0
    })

class EnhancedHardwareIntegration:
    """Enhanced hardware integration with advanced monitoring"""
    
    def __init__(self, config: Optional[EnhancedHardwareConfig] = None):
        self.config = config or EnhancedHardwareConfig()
        self.script_dir = Path(__file__).parent
        
        # Initialize components
        self.hardware_monitor = None
        self.gauge_system = None
        self.integration_callbacks = []
        
        # Performance data
        self.current_metrics = None
        self.performance_history = []
        self.alerts = []
        
        # State
        self.is_initialized = False
        self.is_monitoring = False
        
        # Setup logging
        self.logger = self.setup_logging()
        
        # Initialize if advanced hardware monitoring is available
        if ADVANCED_HARDWARE_AVAILABLE:
            self.initialize_advanced_monitoring()
        else:
            self.logger.warning("Advanced hardware monitoring not available, using fallback")
            self.initialize_fallback_monitoring()
    
    def setup_logging(self):
        """Setup logging system"""
        logger = logging.getLogger("EnhancedHardwareIntegration")
        logger.setLevel(logging.INFO)
        return logger
    
    def initialize_advanced_monitoring(self):
        """Initialize advanced hardware monitoring"""
        try:
            # Create gauge configuration
            gauge_config = GaugeConfiguration(
                update_interval=self.config.update_interval,
                history_size=self.config.history_size,
                smoothing_factor=self.config.smoothing_factor,
                alert_threshold_cpu=self.config.performance_thresholds['cpu'],
                alert_threshold_memory=self.config.performance_thresholds['memory'],
                alert_threshold_disk=self.config.performance_thresholds['disk'],
                alert_threshold_temp=self.config.performance_thresholds['temperature'],
                enable_gpu_monitoring=self.config.enable_gpu_monitoring,
                enable_network_monitoring=self.config.enable_network_monitoring,
                enable_battery_monitoring=self.config.enable_battery_monitoring,
                enable_advanced_metrics=True,
                enable_predictive_alerts=self.config.enable_predictions
            )
            
            # Create hardware monitor
            self.hardware_monitor = AdvancedHardwareMonitor(gauge_config)
            
            # Register callback for metrics updates
            self.hardware_monitor.add_callback(self.on_metrics_update)
            
            self.is_initialized = True
            self.logger.info("Advanced hardware monitoring initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize advanced monitoring: {e}")
            self.initialize_fallback_monitoring()
    
    def initialize_fallback_monitoring(self):
        """Initialize fallback monitoring system"""
        try:
            import psutil
            
            self.fallback_monitor = {
                'psutil': psutil,
                'last_network_io': None,
                'last_disk_io': None,
                'last_update_time': time.time(),
                'is_monitoring': False
            }
            
            self.is_initialized = True
            self.logger.info("Fallback monitoring initialized")
            
        except ImportError:
            self.logger.error("psutil not available, hardware monitoring disabled")
    
    def start_monitoring(self):
        """Start hardware monitoring"""
        if not self.is_initialized:
            self.logger.error("Hardware monitoring not initialized")
            return False
        
        if self.is_monitoring:
            self.logger.warning("Hardware monitoring already running")
            return True
        
        try:
            if self.hardware_monitor:
                self.hardware_monitor.start_monitoring()
            else:
                self.start_fallback_monitoring()
            
            self.is_monitoring = True
            self.logger.info("Hardware monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop hardware monitoring"""
        if not self.is_monitoring:
            return
        
        try:
            if self.hardware_monitor:
                self.hardware_monitor.stop_monitoring()
            else:
                self.stop_fallback_monitoring()
            
            self.is_monitoring = False
            self.logger.info("Hardware monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
    
    def start_fallback_monitoring(self):
        """Start fallback monitoring"""
        if not hasattr(self, 'fallback_monitor'):
            return
        
        self.fallback_monitor['is_monitoring'] = True
        
        def fallback_loop():
            while self.fallback_monitor['is_monitoring']:
                try:
                    self.collect_fallback_metrics()
                    time.sleep(self.config.update_interval)
                except Exception as e:
                    self.logger.error(f"Fallback monitoring error: {e}")
                    time.sleep(1.0)
        
        threading.Thread(target=fallback_loop, daemon=True).start()
    
    def stop_fallback_monitoring(self):
        """Stop fallback monitoring"""
        if hasattr(self, 'fallback_monitor'):
            self.fallback_monitor['is_monitoring'] = False
    
    def collect_fallback_metrics(self):
        """Collect metrics using fallback system"""
        try:
            psutil = self.fallback_monitor['psutil']
            current_time = time.time()
            
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_freq = psutil.cpu_freq()
            cpu_freq_current = cpu_freq.current if cpu_freq else 0.0
            
            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used_gb = memory.used / (1024**3)
            memory_total_gb = memory.total / (1024**3)
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_used_gb = disk.used / (1024**3)
            disk_total_gb = disk.total / (1024**3)
            
            # Network metrics
            network_io = psutil.net_io_counters()
            if self.fallback_monitor['last_network_io']:
                time_delta = current_time - self.fallback_monitor['last_update_time']
                network_sent_mb_s = (network_io.bytes_sent - self.fallback_monitor['last_network_io'].bytes_sent) / (1024**2) / time_delta
                network_recv_mb_s = (network_io.bytes_recv - self.fallback_monitor['last_network_io'].bytes_recv) / (1024**2) / time_delta
            else:
                network_sent_mb_s = 0.0
                network_recv_mb_s = 0.0
            self.fallback_monitor['last_network_io'] = network_io
            
            # Create metrics object
            metrics = HardwareMetrics(
                timestamp=current_time,
                cpu_percent=cpu_percent,
                cpu_frequency=cpu_freq_current,
                cpu_temperature=0.0,
                cpu_cores_active=len(psutil.pids()),
                memory_percent=memory_percent,
                memory_used_gb=memory_used_gb,
                memory_total_gb=memory_total_gb,
                memory_available_gb=memory.available / (1024**3),
                disk_percent=disk_percent,
                disk_used_gb=disk_used_gb,
                disk_total_gb=disk_total_gb,
                disk_read_mb_s=0.0,
                disk_write_mb_s=0.0,
                network_sent_mb_s=network_sent_mb_s,
                network_recv_mb_s=network_recv_mb_s,
                gpu_percent=0.0,
                gpu_memory_percent=0.0,
                gpu_temperature=0.0,
                gpu_frequency=0.0,
                battery_percent=0.0,
                battery_plugged=True,
                process_count=len(psutil.pids()),
                thread_count=threading.active_count(),
                boot_time=psutil.boot_time(),
                uptime_hours=(current_time - psutil.boot_time()) / 3600,
                system_load_avg=[0.0, 0.0, 0.0],
                performance_level=None,
                health_score=0.0
            )
            
            self.fallback_monitor['last_update_time'] = current_time
            self.on_metrics_update(metrics)
            
        except Exception as e:
            self.logger.error(f"Fallback metrics collection error: {e}")
    
    def on_metrics_update(self, metrics: HardwareMetrics):
        """Handle metrics update"""
        self.current_metrics = metrics
        
        # Add to history
        self.performance_history.append(metrics)
        if len(self.performance_history) > self.config.history_size:
            self.performance_history.pop(0)
        
        # Check alerts
        if self.config.enable_alerts:
            self.check_alerts(metrics)
        
        # Notify callbacks
        for callback in self.integration_callbacks:
            try:
                callback(metrics)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")
    
    def check_alerts(self, metrics: HardwareMetrics):
        """Check for performance alerts"""
        new_alerts = []
        
        # CPU alert
        if metrics.cpu_percent > self.config.performance_thresholds['cpu']:
            new_alerts.append({
                'type': 'cpu_high',
                'message': f"CPU usage high: {metrics.cpu_percent:.1f}%",
                'timestamp': metrics.timestamp,
                'severity': 'warning' if metrics.cpu_percent < 90 else 'critical'
            })
        
        # Memory alert
        if metrics.memory_percent > self.config.performance_thresholds['memory']:
            new_alerts.append({
                'type': 'memory_high',
                'message': f"Memory usage high: {metrics.memory_percent:.1f}%",
                'timestamp': metrics.timestamp,
                'severity': 'warning' if metrics.memory_percent < 95 else 'critical'
            })
        
        # Disk alert
        if metrics.disk_percent > self.config.performance_thresholds['disk']:
            new_alerts.append({
                'type': 'disk_high',
                'message': f"Disk usage high: {metrics.disk_percent:.1f}%",
                'timestamp': metrics.timestamp,
                'severity': 'warning' if metrics.disk_percent < 95 else 'critical'
            })
        
        # Add new alerts
        self.alerts.extend(new_alerts)
        
        # Keep only recent alerts
        if len(self.alerts) > 50:
            self.alerts = self.alerts[-50:]
    
    def get_current_metrics(self) -> Optional[HardwareMetrics]:
        """Get current hardware metrics"""
        return self.current_metrics
    
    def get_responsive_gauge_data(self, metric_type: str) -> Dict[str, Any]:
        """Get responsive gauge data for specific metric"""
        if not self.current_metrics:
            return {}
        
        if self.hardware_monitor:
            return self.hardware_monitor.get_responsive_gauge_data(metric_type)
        else:
            # Fallback gauge data
            return self.get_fallback_gauge_data(metric_type)
    
    def get_fallback_gauge_data(self, metric_type: str) -> Dict[str, Any]:
        """Get fallback gauge data"""
        if not self.current_metrics:
            return {}
        
        # Get current value
        if metric_type == "cpu":
            value = self.current_metrics.cpu_percent
            threshold = self.config.performance_thresholds['cpu']
        elif metric_type == "memory":
            value = self.current_metrics.memory_percent
            threshold = self.config.performance_thresholds['memory']
        elif metric_type == "disk":
            value = self.current_metrics.disk_percent
            threshold = self.config.performance_thresholds['disk']
        elif metric_type == "gpu":
            value = self.current_metrics.gpu_percent
            threshold = self.config.performance_thresholds['gpu']
        elif metric_type == "temperature":
            value = self.current_metrics.cpu_temperature
            threshold = self.config.performance_thresholds['temperature']
        elif metric_type == "network":
            value = (self.current_metrics.network_sent_mb_s + self.current_metrics.network_recv_mb_s) * 10
            threshold = self.config.performance_thresholds['network']
        elif metric_type == "battery":
            value = self.current_metrics.battery_percent
            threshold = self.config.performance_thresholds['battery']
        else:
            return {}
        
        # Calculate color
        color = self.get_gauge_color(value, threshold, metric_type)
        
        return {
            'value': value,
            'color': color,
            'trend': 'stable',
            'velocity': 0.0,
            'threshold': threshold,
            'unit': self.get_metric_unit(metric_type),
            'status': self.get_metric_status(value, threshold),
            'history': [],
            'predicted': value
        }
    
    def get_gauge_color(self, value: float, threshold: float, metric_type: str) -> str:
        """Get gauge color based on value and threshold"""
        if metric_type == "health":
            # Health score: higher is better
            if value >= 80:
                return "#00ff00"  # Green
            elif value >= 60:
                return "#ffff00"  # Yellow
            elif value >= 40:
                return "#ff8800"  # Orange
            else:
                return "#ff0000"  # Red
        elif metric_type == "battery":
            # Battery: higher is better
            if value >= 60:
                return "#00ff00"  # Green
            elif value >= 30:
                return "#ffff00"  # Yellow
            else:
                return "#ff0000"  # Red
        else:
            # Usage metrics: lower is better
            if value < threshold * 0.5:
                return "#00ff00"  # Green
            elif value < threshold * 0.75:
                return "#ffff00"  # Yellow
            elif value < threshold:
                return "#ff8800"  # Orange
            else:
                return "#ff0000"  # Red
    
    def get_metric_unit(self, metric_type: str) -> str:
        """Get unit for metric type"""
        units = {
            "cpu": "%",
            "memory": "%",
            "disk": "%",
            "gpu": "%",
            "temperature": "°C",
            "network": "MB/s",
            "battery": "%"
        }
        return units.get(metric_type, "")
    
    def get_metric_status(self, value: float, threshold: float) -> str:
        """Get status based on value and threshold"""
        if value < threshold * 0.5:
            return "excellent"
        elif value < threshold * 0.75:
            return "good"
        elif value < threshold:
            return "warning"
        else:
            return "critical"
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        if not self.current_metrics:
            return {}
        
        if self.hardware_monitor:
            return self.hardware_monitor.get_performance_summary()
        else:
            # Fallback summary
            return {
                'current': self.current_metrics,
                'statistics': self.get_fallback_statistics(),
                'alerts': self.alerts[-10:],
                'hardware_info': self.get_fallback_hardware_info()
            }
    
    def get_fallback_statistics(self) -> Dict[str, Any]:
        """Get fallback statistics"""
        if not self.performance_history:
            return {}
        
        # Calculate basic statistics
        cpu_values = [m.cpu_percent for m in self.performance_history]
        memory_values = [m.memory_percent for m in self.performance_history]
        disk_values = [m.disk_percent for m in self.performance_history]
        
        return {
            'cpu': {
                'current': self.current_metrics.cpu_percent,
                'average': sum(cpu_values) / len(cpu_values),
                'min': min(cpu_values),
                'max': max(cpu_values),
                'trend': 'stable'
            },
            'memory': {
                'current': self.current_metrics.memory_percent,
                'average': sum(memory_values) / len(memory_values),
                'min': min(memory_values),
                'max': max(memory_values),
                'trend': 'stable'
            },
            'disk': {
                'current': self.current_metrics.disk_percent,
                'average': sum(disk_values) / len(disk_values),
                'min': min(disk_values),
                'max': max(disk_values),
                'trend': 'stable'
            }
        }
    
    def get_fallback_hardware_info(self) -> Dict[str, Any]:
        """Get fallback hardware information"""
        try:
            import psutil
            import platform
            
            return {
                'platform': platform.platform(),
                'system': platform.system(),
                'processor': platform.processor(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_info': [],
                'gpu_info': [],
                'network_interfaces': list(psutil.net_if_addrs().keys()),
                'battery_available': False
            }
        except Exception as e:
            self.logger.error(f"Error getting hardware info: {e}")
            return {}
    
    def add_callback(self, callback: Callable[[HardwareMetrics], None]):
        """Add callback for metrics updates"""
        self.integration_callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[HardwareMetrics], None]):
        """Remove callback"""
        if callback in self.integration_callbacks:
            self.integration_callbacks.remove(callback)
    
    def create_gauge_system(self, root: tk.Tk) -> Optional['AdvancedGaugeSystem']:
        """Create gauge system if GUI is available"""
        if not GUI_AVAILABLE or not self.hardware_monitor:
            return None
        
        try:
            return AdvancedGaugeSystem(root, self.hardware_monitor)
        except Exception as e:
            self.logger.error(f"Failed to create gauge system: {e}")
            return None
    
    def export_metrics(self, filename: str):
        """Export metrics to file anchored to this module's directory."""
        try:
            out = Path(__file__).parent / filename
            data = {
                'timestamp': datetime.now().isoformat(),
                'current_metrics': self.current_metrics.__dict__ if self.current_metrics else None,
                'performance_summary': self.get_performance_summary(),
                'alerts': self.alerts,
                'configuration': self.config.__dict__
            }
            with open(out, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            self.logger.info("Metrics exported to %s", out)
        except Exception as exc:
            self.logger.error("Failed to export metrics: %s", exc)
    
    def cleanup(self):
        """Cleanup resources"""
        self.stop_monitoring()
        self.integration_callbacks.clear()
        self.performance_history.clear()
        self.alerts.clear()

# Global instance
enhanced_hardware_integration = None

def initialize_enhanced_hardware(config: Optional[EnhancedHardwareConfig] = None) -> EnhancedHardwareIntegration:
    """Initialize enhanced hardware integration"""
    global enhanced_hardware_integration
    
    if enhanced_hardware_integration is None:
        enhanced_hardware_integration = EnhancedHardwareIntegration(config)
    
    return enhanced_hardware_integration

def get_enhanced_hardware() -> Optional[EnhancedHardwareIntegration]:
    """Get enhanced hardware integration instance"""
    return enhanced_hardware_integration

def main():
    """Main function for testing"""
    print("Enhanced Hardware Integration Test")
    print("=" * 50)
    print("Advanced hardware monitoring with responsive gauges")
    print("Real-time performance data visualization")
    print("Sophisticated metrics and alerting")
    print("Integration-ready for main application")
    print("=" * 50)
    
    # Initialize enhanced hardware
    config = EnhancedHardwareConfig(
        enable_advanced_monitoring=True,
        enable_responsive_gauges=True,
        update_interval=0.5,
        enable_predictions=True,
        enable_alerts=True,
        gauge_animation_type="smooth",
        enable_glow_effects=True
    )
    
    hardware = initialize_enhanced_hardware(config)
    
    try:
        print("\nStarting enhanced hardware monitoring...")
        hardware.start_monitoring()
        
        # Monitor for 10 seconds
        time.sleep(10)
        
        # Show current metrics
        current = hardware.get_current_metrics()
        if current:
            print(f"\nCurrent Metrics:")
            print(f"   CPU: {current.cpu_percent:.1f}% @ {current.cpu_frequency:.0f}MHz")
            print(f"   Memory: {current.memory_percent:.1f}% ({current.memory_used_gb:.1f}GB)")
            print(f"   Disk: {current.disk_percent:.1f}% ({current.disk_used_gb:.1f}GB)")
            print(f"   Network: {current.network_sent_mb_s:.1f}MB/s sent, {current.network_recv_mb_s:.1f}MB/s recv")
            print(f"   Processes: {current.process_count}, Threads: {current.thread_count}")
            print(f"   Uptime: {current.uptime_hours:.1f} hours")
        
        # Show gauge data
        print(f"\n[GAUGE] Responsive Gauge Data:")
        for metric in ["cpu", "memory", "disk", "network"]:
            gauge_data = hardware.get_responsive_gauge_data(metric)
            if gauge_data:
                print(f"   {metric.title()}: {gauge_data['value']:.1f}{gauge_data['unit']} ({gauge_data['status']}) - {gauge_data['color']}")
        
        # Show performance summary
        summary = hardware.get_performance_summary()
        if summary and 'statistics' in summary:
            stats = summary['statistics']
            print(f"\n📈 Performance Summary:")
            for metric in ['cpu', 'memory', 'disk']:
                if metric in stats:
                    metric_stats = stats[metric]
                    print(f"   {metric.title()}: {metric_stats['current']:.1f}% (avg: {metric_stats['average']:.1f}%)")
        
        # Export metrics
        hardware.export_metrics("enhanced_hardware_metrics.json")
        
        # Test gauge system if GUI available
        if GUI_AVAILABLE:
            print("\n[UI] Testing gauge system...")
            root = tk.Tk()
            gauge_system = hardware.create_gauge_system(root)
            if gauge_system:
                print("[OK] Gauge system created successfully")
                # Don't actually run the GUI in test mode
                root.destroy()
            else:
                print("[ERROR] Gauge system creation failed")
        
    except KeyboardInterrupt:
        print("\n[WARNING] Monitoring stopped by user")
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        hardware.cleanup()
        print("\n[DONE] Enhanced hardware integration test completed")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
