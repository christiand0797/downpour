#!/usr/bin/env python3
"""
Advanced Hardware Performance Monitoring System
Real-time responsive gauges with sophisticated performance readings
"""

import os
import sys
import time
import threading
import queue
import json
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import math
import statistics
import gc

class PerformanceLevel(Enum):
    """Performance level classification"""
    EXCELLENT = "excellent"
    GOOD = "good"
    AVERAGE = "average"
    POOR = "poor"
    CRITICAL = "critical"

@dataclass
class HardwareMetrics:
    """Comprehensive hardware metrics"""
    timestamp: float
    cpu_percent: float
    cpu_frequency: float
    cpu_temperature: float
    cpu_cores_active: int
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    memory_available_gb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    disk_read_mb_s: float
    disk_write_mb_s: float
    network_sent_mb_s: float
    network_recv_mb_s: float
    gpu_percent: float
    gpu_memory_percent: float
    gpu_temperature: float
    gpu_frequency: float
    battery_percent: float
    battery_plugged: bool
    process_count: int
    thread_count: int
    boot_time: float
    uptime_hours: float
    system_load_avg: List[float]
    performance_level: PerformanceLevel
    health_score: float

@dataclass
class GaugeConfiguration:
    """Gauge configuration settings"""
    update_interval: float = 0.5
    history_size: int = 100
    smoothing_factor: float = 0.3
    alert_threshold_cpu: float = 80.0
    alert_threshold_memory: float = 85.0
    alert_threshold_disk: float = 90.0
    alert_threshold_temp: float = 75.0
    enable_gpu_monitoring: bool = True
    enable_network_monitoring: bool = True
    enable_battery_monitoring: bool = True
    enable_advanced_metrics: bool = True
    enable_predictive_alerts: bool = True

class AdvancedHardwareMonitor:
    """Advanced hardware monitoring system with responsive gauges"""
    
    def __init__(self, config: Optional[GaugeConfiguration] = None):
        self.config = config or GaugeConfiguration()
        self.script_dir = Path(__file__).parent
        
        # Data storage
        self.metrics_history = queue.Queue(maxsize=self.config.history_size)
        self.current_metrics = None
        self.previous_metrics = None
        
        # Performance tracking
        self.performance_trends = {}
        self.alerts = []
        self.performance_scores = []
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.update_callbacks = []
        
        # Hardware detection
        self.hardware_info = self.detect_hardware()
        
        # Initialize metrics
        self.last_network_io = None
        self.last_disk_io = None
        self.last_update_time = time.time()
        
        # Performance optimization
        self.performance_cache = {}
        self.cache_timeout = 1.0
        
        self.logger = self.setup_logging()
    
    def setup_logging(self):
        """Setup logging system"""
        import logging
        logger = logging.getLogger("AdvancedHardwareMonitor")
        logger.setLevel(logging.INFO)
        return logger
    
    def detect_hardware(self) -> Dict[str, Any]:
        """Detect and catalog hardware capabilities"""
        hardware = {
            "platform": platform.platform(),
            "system": platform.system(),
            "processor": platform.processor(),
            "architecture": platform.architecture(),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "disk_info": [],
            "gpu_info": [],
            "network_interfaces": list(psutil.net_if_addrs().keys()),
            "battery_available": False,
            "thermal_sensors": False
        }
        
        # Disk information
        disk_partitions = psutil.disk_partitions()
        for partition in disk_partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                hardware["disk_info"].append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "total": usage.total,
                    "fstype": partition.fstype
                })
            except (PermissionError, OSError):
                continue
        
        # GPU information
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
            for gpu in gpus:
                hardware["gpu_info"].append({
                    "id": gpu.id,
                    "name": gpu.name,
                    "memory_total": gpu.memoryTotal,
                    "driver": gpu.driver,
                    "temperature": gpu.temperature
                })
        except ImportError:
            pass
        
        # Battery information
        try:
            battery = psutil.sensors_battery()
            if battery:
                hardware["battery_available"] = True
        except (AttributeError, OSError):
            pass
        
        # Thermal sensors
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                hardware["thermal_sensors"] = True
        except (AttributeError, OSError):
            pass
        
        return hardware
    
    def start_monitoring(self):
        """Start hardware monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("[MONITOR] Advanced hardware monitoring started")
    
    def stop_monitoring(self):
        """Stop hardware monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        self.logger.info("[STOP] Hardware monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop with optimized performance"""
        while self.is_monitoring:
            try:
                start_time = time.time()
                
                # Collect metrics
                metrics = self.collect_comprehensive_metrics()
                
                # Process and store metrics
                processed_metrics = self.process_metrics(metrics)
                
                # Update current metrics
                self.previous_metrics = self.current_metrics
                self.current_metrics = processed_metrics
                
                # Store in history
                try:
                    self.metrics_history.put_nowait(processed_metrics)
                except queue.Full:
                    # Remove oldest and add new
                    try:
                        self.metrics_history.get_nowait()
                        self.metrics_history.put_nowait(processed_metrics)
                    except queue.Empty:
                        pass
                
                # Update performance trends
                self.update_performance_trends(processed_metrics)
                
                # Check alerts
                self.check_performance_alerts(processed_metrics)
                
                # Notify callbacks
                self.notify_callbacks(processed_metrics)
                
                # Calculate sleep time to maintain target interval
                elapsed = time.time() - start_time
                sleep_time = max(0.01, self.config.update_interval - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1.0)
    
    def collect_comprehensive_metrics(self) -> HardwareMetrics:
        """Collect comprehensive hardware metrics"""
        timestamp = time.time()
        
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_freq = psutil.cpu_freq()
        cpu_freq_current = cpu_freq.current if cpu_freq else 0.0
        
        # CPU temperature (if available)
        cpu_temp = self.get_cpu_temperature()
        
        # CPU cores active
        cpu_cores_active = len(psutil.pids())
        
        # Memory metrics
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_gb = memory.used / (1024**3)
        memory_total_gb = memory.total / (1024**3)
        memory_available_gb = memory.available / (1024**3)
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_used_gb = disk.used / (1024**3)
        disk_total_gb = disk.total / (1024**3)
        
        # Disk I/O metrics
        disk_io = psutil.disk_io_counters()
        current_time = time.time()
        if self.last_disk_io and self.last_update_time:
            time_delta = current_time - self.last_update_time
            disk_read_mb_s = (disk_io.read_bytes - self.last_disk_io.read_bytes) / (1024**2) / time_delta
            disk_write_mb_s = (disk_io.write_bytes - self.last_disk_io.write_bytes) / (1024**2) / time_delta
        else:
            disk_read_mb_s = 0.0
            disk_write_mb_s = 0.0
        self.last_disk_io = disk_io
        
        # Network metrics
        network_io = psutil.net_io_counters()
        if self.last_network_io and self.last_update_time:
            network_sent_mb_s = (network_io.bytes_sent - self.last_network_io.bytes_sent) / (1024**2) / time_delta
            network_recv_mb_s = (network_io.bytes_recv - self.last_network_io.bytes_recv) / (1024**2) / time_delta
        else:
            network_sent_mb_s = 0.0
            network_recv_mb_s = 0.0
        self.last_network_io = network_io
        
        # GPU metrics
        gpu_percent = 0.0
        gpu_memory_percent = 0.0
        gpu_temperature = 0.0
        gpu_frequency = 0.0
        
        if self.config.enable_gpu_monitoring and self.hardware_info["gpu_info"]:
            try:
                import GPUtil
                gpus = GPUtil.getGPUs()
                if gpus:
                    gpu = gpus[0]  # Use first GPU
                    gpu_percent = gpu.load * 100
                    gpu_memory_percent = (gpu.memoryUsed / gpu.memoryTotal) * 100
                    gpu_temperature = gpu.temperature
                    gpu_frequency = getattr(gpu, 'frequency', 0.0)
            except ImportError:
                pass
        
        # Battery metrics
        battery_percent = 0.0
        battery_plugged = True
        if self.config.enable_battery_monitoring and self.hardware_info["battery_available"]:
            try:
                battery = psutil.sensors_battery()
                if battery:
                    battery_percent = battery.percent
                    battery_plugged = battery.power_plugged
            except (AttributeError, OSError):
                pass
        
        # System metrics
        process_count = len(psutil.pids())
        thread_count = threading.active_count()
        boot_time = psutil.boot_time()
        uptime_hours = (timestamp - boot_time) / 3600
        
        # System load average
        try:
            load_avg = list(psutil.getloadavg())
        except (AttributeError, OSError):
            load_avg = [0.0, 0.0, 0.0]
        
        # Calculate performance level and health score
        performance_level = self.calculate_performance_level(cpu_percent, memory_percent, disk_percent)
        health_score = self.calculate_health_score(cpu_percent, memory_percent, disk_percent, gpu_percent)
        
        self.last_update_time = current_time
        
        return HardwareMetrics(
            timestamp=timestamp,
            cpu_percent=cpu_percent,
            cpu_frequency=cpu_freq_current,
            cpu_temperature=cpu_temp,
            cpu_cores_active=cpu_cores_active,
            memory_percent=memory_percent,
            memory_used_gb=memory_used_gb,
            memory_total_gb=memory_total_gb,
            memory_available_gb=memory_available_gb,
            disk_percent=disk_percent,
            disk_used_gb=disk_used_gb,
            disk_total_gb=disk_total_gb,
            disk_read_mb_s=disk_read_mb_s,
            disk_write_mb_s=disk_write_mb_s,
            network_sent_mb_s=network_sent_mb_s,
            network_recv_mb_s=network_recv_mb_s,
            gpu_percent=gpu_percent,
            gpu_memory_percent=gpu_memory_percent,
            gpu_temperature=gpu_temperature,
            gpu_frequency=gpu_frequency,
            battery_percent=battery_percent,
            battery_plugged=battery_plugged,
            process_count=process_count,
            thread_count=thread_count,
            boot_time=boot_time,
            uptime_hours=uptime_hours,
            system_load_avg=load_avg,
            performance_level=performance_level,
            health_score=health_score
        )
    
    def get_cpu_temperature(self) -> float:
        """Get CPU temperature"""
        try:
            temps = psutil.sensors_temperatures()
            if 'coretemp' in temps:
                core_temps = temps['coretemp']
                if core_temps:
                    # Get the highest temperature from all cores
                    max_temp = 0.0
                    for entry in core_temps:
                        if hasattr(entry, 'current') and entry.current > max_temp:
                            max_temp = entry.current
                    return max_temp
            elif 'acpitz' in temps:
                # Alternative temperature sensor
                acpi_temps = temps['acpitz']
                if acpi_temps:
                    return acpi_temps[0].current
        except (AttributeError, OSError):
            pass
        return 0.0
    
    def process_metrics(self, metrics: HardwareMetrics) -> HardwareMetrics:
        """Process metrics with smoothing and optimization"""
        if not self.previous_metrics:
            return metrics
        
        # Apply smoothing to reduce noise
        smoothing = self.config.smoothing_factor
        smoothed_metrics = HardwareMetrics(
            timestamp=metrics.timestamp,
            cpu_percent=self._smooth_value(self.previous_metrics.cpu_percent, metrics.cpu_percent, smoothing),
            cpu_frequency=self._smooth_value(self.previous_metrics.cpu_frequency, metrics.cpu_frequency, smoothing),
            cpu_temperature=self._smooth_value(self.previous_metrics.cpu_temperature, metrics.cpu_temperature, smoothing),
            cpu_cores_active=metrics.cpu_cores_active,
            memory_percent=self._smooth_value(self.previous_metrics.memory_percent, metrics.memory_percent, smoothing),
            memory_used_gb=metrics.memory_used_gb,
            memory_total_gb=metrics.memory_total_gb,
            memory_available_gb=metrics.memory_available_gb,
            disk_percent=self._smooth_value(self.previous_metrics.disk_percent, metrics.disk_percent, smoothing),
            disk_used_gb=metrics.disk_used_gb,
            disk_total_gb=metrics.disk_total_gb,
            disk_read_mb_s=self._smooth_value(self.previous_metrics.disk_read_mb_s, metrics.disk_read_mb_s, smoothing),
            disk_write_mb_s=self._smooth_value(self.previous_metrics.disk_write_mb_s, metrics.disk_write_mb_s, smoothing),
            network_sent_mb_s=self._smooth_value(self.previous_metrics.network_sent_mb_s, metrics.network_sent_mb_s, smoothing),
            network_recv_mb_s=self._smooth_value(self.previous_metrics.network_recv_mb_s, metrics.network_recv_mb_s, smoothing),
            gpu_percent=self._smooth_value(self.previous_metrics.gpu_percent, metrics.gpu_percent, smoothing),
            gpu_memory_percent=self._smooth_value(self.previous_metrics.gpu_memory_percent, metrics.gpu_memory_percent, smoothing),
            gpu_temperature=self._smooth_value(self.previous_metrics.gpu_temperature, metrics.gpu_temperature, smoothing),
            gpu_frequency=self._smooth_value(self.previous_metrics.gpu_frequency, metrics.gpu_frequency, smoothing),
            battery_percent=metrics.battery_percent,
            battery_plugged=metrics.battery_plugged,
            process_count=metrics.process_count,
            thread_count=metrics.thread_count,
            boot_time=metrics.boot_time,
            uptime_hours=metrics.uptime_hours,
            system_load_avg=metrics.system_load_avg,
            performance_level=metrics.performance_level,
            health_score=metrics.health_score
        )
        
        return smoothed_metrics
    
    def _smooth_value(self, old_value: float, new_value: float, smoothing: float) -> float:
        """Apply exponential smoothing to reduce noise"""
        return old_value * smoothing + new_value * (1 - smoothing)
    
    def calculate_performance_level(self, cpu_percent: float, memory_percent: float, disk_percent: float) -> PerformanceLevel:
        """Calculate overall performance level"""
        avg_usage = (cpu_percent + memory_percent + disk_percent) / 3
        
        if avg_usage < 50:
            return PerformanceLevel.EXCELLENT
        elif avg_usage < 70:
            return PerformanceLevel.GOOD
        elif avg_usage < 85:
            return PerformanceLevel.AVERAGE
        elif avg_usage < 95:
            return PerformanceLevel.POOR
        else:
            return PerformanceLevel.CRITICAL
    
    def calculate_health_score(self, cpu_percent: float, memory_percent: float, disk_percent: float, gpu_percent: float) -> float:
        """Calculate system health score (0-100)"""
        # Weight different components
        cpu_weight = 0.3
        memory_weight = 0.25
        disk_weight = 0.2
        gpu_weight = 0.25
        
        # Calculate individual scores (lower usage = higher score)
        cpu_score = max(0, 100 - cpu_percent)
        memory_score = max(0, 100 - memory_percent)
        disk_score = max(0, 100 - disk_percent)
        gpu_score = max(0, 100 - gpu_percent)
        
        # Calculate weighted average
        health_score = (cpu_score * cpu_weight + 
                        memory_score * memory_weight + 
                        disk_score * disk_weight + 
                        gpu_score * gpu_weight)
        
        return round(health_score, 2)
    
    def update_performance_trends(self, metrics: HardwareMetrics):
        """Update performance trends for predictive analysis"""
        if not self.performance_trends:
            self.performance_trends = {
                'cpu_trend': [],
                'memory_trend': [],
                'disk_trend': [],
                'gpu_trend': [],
                'health_trend': []
            }
        
        # Add current values to trends
        self.performance_trends['cpu_trend'].append(metrics.cpu_percent)
        self.performance_trends['memory_trend'].append(metrics.memory_percent)
        self.performance_trends['disk_trend'].append(metrics.disk_percent)
        self.performance_trends['gpu_trend'].append(metrics.gpu_percent)
        self.performance_trends['health_trend'].append(metrics.health_score)
        
        # Keep only recent history
        max_trend_size = 50
        for key in self.performance_trends:
            if len(self.performance_trends[key]) > max_trend_size:
                self.performance_trends[key] = self.performance_trends[key][-max_trend_size:]
    
    def check_performance_alerts(self, metrics: HardwareMetrics):
        """Check for performance alerts and warnings"""
        new_alerts = []
        
        # CPU alerts
        if metrics.cpu_percent > self.config.alert_threshold_cpu:
            new_alerts.append({
                'type': 'cpu_high',
                'message': f"CPU usage high: {metrics.cpu_percent:.1f}%",
                'timestamp': metrics.timestamp,
                'severity': 'warning' if metrics.cpu_percent < 90 else 'critical'
            })
        
        # Memory alerts
        if metrics.memory_percent > self.config.alert_threshold_memory:
            new_alerts.append({
                'type': 'memory_high',
                'message': f"Memory usage high: {metrics.memory_percent:.1f}%",
                'timestamp': metrics.timestamp,
                'severity': 'warning' if metrics.memory_percent < 95 else 'critical'
            })
        
        # Disk alerts
        if metrics.disk_percent > self.config.alert_threshold_disk:
            new_alerts.append({
                'type': 'disk_high',
                'message': f"Disk usage high: {metrics.disk_percent:.1f}%",
                'timestamp': metrics.timestamp,
                'severity': 'warning' if metrics.disk_percent < 95 else 'critical'
            })
        
        # Temperature alerts
        if metrics.cpu_temperature > self.config.alert_threshold_temp:
            new_alerts.append({
                'type': 'temperature_high',
                'message': f"CPU temperature high: {metrics.cpu_temperature:.1f}°C",
                'timestamp': metrics.timestamp,
                'severity': 'warning' if metrics.cpu_temperature < 85 else 'critical'
            })
        
        # GPU alerts
        if metrics.gpu_percent > 85:
            new_alerts.append({
                'type': 'gpu_high',
                'message': f"GPU usage high: {metrics.gpu_percent:.1f}%",
                'timestamp': metrics.timestamp,
                'severity': 'warning' if metrics.gpu_percent < 95 else 'critical'
            })
        
        # Health score alerts
        if metrics.health_score < 30:
            new_alerts.append({
                'type': 'health_low',
                'message': f"System health low: {metrics.health_score:.1f}%",
                'timestamp': metrics.timestamp,
                'severity': 'critical'
            })
        
        # Add new alerts to list
        self.alerts.extend(new_alerts)
        
        # Keep only recent alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
    
    def notify_callbacks(self, metrics: HardwareMetrics):
        """Notify all registered callbacks"""
        for callback in self.update_callbacks:
            try:
                callback(metrics)
            except Exception as e:
                self.logger.error(f"Error in callback: {e}")
    
    def add_callback(self, callback: Callable[[HardwareMetrics], None]):
        """Add callback for metric updates"""
        self.update_callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[HardwareMetrics], None]):
        """Remove callback"""
        if callback in self.update_callbacks:
            self.update_callbacks.remove(callback)
    
    def get_current_metrics(self) -> Optional[HardwareMetrics]:
        """Get current hardware metrics"""
        return self.current_metrics
    
    def get_metrics_history(self, count: int = 100) -> List[HardwareMetrics]:
        """Get recent metrics history"""
        history = []
        temp_queue = queue.Queue()
        
        # Copy metrics from history queue
        while not self.metrics_history.empty() and len(history) < count:
            try:
                metrics = self.metrics_history.get_nowait()
                temp_queue.put(metrics)
                history.append(metrics)
            except queue.Empty:
                break
        
        # Restore metrics to queue
        while not temp_queue.empty():
            try:
                self.metrics_history.put_nowait(temp_queue.get_nowait())
            except queue.Full:
                break
        
        return history
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary with statistics"""
        if not self.current_metrics:
            return {}
        
        history = self.get_metrics_history(50)
        if not history:
            return {}
        
        # Calculate statistics
        cpu_values = [m.cpu_percent for m in history]
        memory_values = [m.memory_percent for m in history]
        disk_values = [m.disk_percent for m in history]
        health_values = [m.health_score for m in history]
        
        return {
            'current': self.current_metrics,
            'statistics': {
                'cpu': {
                    'current': self.current_metrics.cpu_percent,
                    'average': statistics.mean(cpu_values),
                    'min': min(cpu_values),
                    'max': max(cpu_values),
                    'trend': self.calculate_trend(cpu_values)
                },
                'memory': {
                    'current': self.current_metrics.memory_percent,
                    'average': statistics.mean(memory_values),
                    'min': min(memory_values),
                    'max': max(memory_values),
                    'trend': self.calculate_trend(memory_values)
                },
                'disk': {
                    'current': self.current_metrics.disk_percent,
                    'average': statistics.mean(disk_values),
                    'min': min(disk_values),
                    'max': max(disk_values),
                    'trend': self.calculate_trend(disk_values)
                },
                'health': {
                    'current': self.current_metrics.health_score,
                    'average': statistics.mean(health_values),
                    'min': min(health_values),
                    'max': max(health_values),
                    'trend': self.calculate_trend(health_values)
                }
            },
            'alerts': self.alerts[-10:],  # Recent alerts
            'hardware_info': self.hardware_info
        }
    
    def calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction"""
        if len(values) < 2:
            return "stable"
        
        # Simple linear regression for trend
        n = len(values)
        x = list(range(n))
        
        # Calculate slope
        x_mean = sum(x) / n
        y_mean = sum(values) / n
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return "stable"
        
        slope = numerator / denominator
        
        if slope > 0.5:
            return "increasing"
        elif slope < -0.5:
            return "decreasing"
        else:
            return "stable"
    
    def get_responsive_gauge_data(self, metric_type: str) -> Dict[str, Any]:
        """Get responsive gauge data for specific metric"""
        if not self.current_metrics:
            return {}
        
        history = self.get_metrics_history(20)
        if not history:
            return {}
        
        # Get recent values for smooth animation
        if metric_type == "cpu":
            values = [m.cpu_percent for m in history]
            current = self.current_metrics.cpu_percent
            threshold = self.config.alert_threshold_cpu
        elif metric_type == "memory":
            values = [m.memory_percent for m in history]
            current = self.current_metrics.memory_percent
            threshold = self.config.alert_threshold_memory
        elif metric_type == "disk":
            values = [m.disk_percent for m in history]
            current = self.current_metrics.disk_percent
            threshold = self.config.alert_threshold_disk
        elif metric_type == "gpu":
            values = [m.gpu_percent for m in history]
            current = self.current_metrics.gpu_percent
            threshold = 85.0
        elif metric_type == "temperature":
            values = [m.cpu_temperature for m in history]
            current = self.current_metrics.cpu_temperature
            threshold = self.config.alert_threshold_temp
        elif metric_type == "health":
            values = [m.health_score for m in history]
            current = self.current_metrics.health_score
            threshold = 30.0  # Low health threshold
        else:
            return {}
        
        # Calculate gauge properties
        gauge_value = min(100, max(0, current))
        gauge_color = self.get_gauge_color(gauge_value, threshold, metric_type)
        gauge_trend = self.calculate_trend(values)
        gauge_velocity = self.calculate_velocity(values) if len(values) > 1 else 0.0
        
        return {
            'value': gauge_value,
            'color': gauge_color,
            'trend': gauge_trend,
            'velocity': gauge_velocity,
            'threshold': threshold,
            'unit': self.get_metric_unit(metric_type),
            'status': self.get_metric_status(gauge_value, threshold),
            'history': values[-10:],  # Last 10 values for animation
            'predicted': self.predict_next_value(values) if len(values) > 5 else gauge_value
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
            "health": "%"
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
    
    def calculate_velocity(self, values: List[float]) -> float:
        """Calculate rate of change (velocity)"""
        if len(values) < 2:
            return 0.0
        
        # Simple velocity calculation
        return values[-1] - values[-2]
    
    def predict_next_value(self, values: List[float]) -> float:
        """Simple linear prediction for next value"""
        if len(values) < 3:
            return values[-1] if values else 0.0
        
        # Simple linear prediction
        n = len(values)
        x = list(range(n))
        
        # Calculate slope
        x_mean = sum(x) / n
        y_mean = sum(values) / n
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return values[-1]
        
        slope = numerator / denominator
        predicted = values[-1] + slope
        
        # Clamp to valid range
        return max(0, min(100, predicted))
    
    def export_metrics(self, filename: str, format: str = "json"):
        """Export metrics to file"""
        if format.lower() == "json":
            data = {
                'timestamp': datetime.now().isoformat(),
                'current_metrics': self.current_metrics.__dict__ if self.current_metrics else None,
                'hardware_info': self.hardware_info,
                'configuration': self.config.__dict__,
                'alerts': self.alerts,
                'performance_summary': self.get_performance_summary()
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        
        self.logger.info(f"Metrics exported to {filename}")

def main():
    """Main function for testing"""
    print("[MONITOR] Advanced Hardware Performance Monitor")
    print("=" * 50)
    print("Real-time responsive gauges with sophisticated performance readings")
    print("🔥 Advanced monitoring with predictive analysis")
    print("[STATS] Responsive gauges with smooth animations")
    print("[TARGET] Intelligent alerts and trend analysis")
    print("=" * 50)
    
    monitor = AdvancedHardwareMonitor()
    
    # Add example callback
    def metrics_callback(metrics):
        print(f"[STATS] CPU: {metrics.cpu_percent:.1f}% | Memory: {metrics.memory_percent:.1f}% | Health: {metrics.health_score:.1f}")
    
    monitor.add_callback(metrics_callback)
    
    try:
        print("\n[MONITOR] Starting hardware monitoring...")
        monitor.start_monitoring()
        
        # Monitor for 10 seconds
        time.sleep(10)
        
        # Show current metrics
        current = monitor.get_current_metrics()
        if current:
            print(f"\n[STATS] Current Metrics:")
            print(f"   CPU: {current.cpu_percent:.1f}% @ {current.cpu_frequency:.0f}MHz")
            print(f"   Memory: {current.memory_percent:.1f}% ({current.memory_used_gb:.1f}GB / {current.memory_total_gb:.1f}GB)")
            print(f"   Disk: {current.disk_percent:.1f}% ({current.disk_used_gb:.1f}GB / {current.disk_total_gb:.1f}GB)")
            print(f"   GPU: {current.gpu_percent:.1f}% ({current.gpu_memory_percent:.1f}% memory)")
            print(f"   Temperature: {current.cpu_temperature:.1f}°C")
            print(f"   Battery: {current.battery_percent:.1f}% ({'Plugged' if current.battery_plugged else 'On Battery'})")
            print(f"   Health Score: {current.health_score:.1f}/100")
            print(f"   Performance Level: {current.performance_level.value}")
            print(f"   Uptime: {current.uptime_hours:.1f} hours")
        
        # Show gauge data
        print(f"\n[TARGET] Responsive Gauge Data:")
        for metric in ["cpu", "memory", "disk", "gpu", "temperature", "health"]:
            gauge_data = monitor.get_responsive_gauge_data(metric)
            if gauge_data:
                print(f"   {metric.title()}: {gauge_data['value']:.1f}{gauge_data['unit']} ({gauge_data['status']}) - {gauge_data['color']} - Trend: {gauge_data['trend']}")
        
        # Show performance summary
        summary = monitor.get_performance_summary()
        if summary and 'statistics' in summary:
            stats = summary['statistics']
            print(f"\n[CHART] Performance Summary:")
            for metric in ['cpu', 'memory', 'disk', 'health']:
                if metric in stats:
                    metric_stats = stats[metric]
                    print(f"   {metric.title()}: {metric_stats['current']:.1f}% (avg: {metric_stats['average']:.1f}%, trend: {metric_stats['trend']})")
        
        # Export metrics
        monitor.export_metrics("hardware_metrics.json")
        
    except KeyboardInterrupt:
        print("\n[STOP] Monitoring stopped by user")
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        monitor.stop_monitoring()
        print("\n[FLAG] Hardware monitoring stopped")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
