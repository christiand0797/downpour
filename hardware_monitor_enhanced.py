"""
Enhanced Hardware Monitor v2.0
Advanced system monitoring with improved GPU detection, temperature monitoring, and performance tracking
"""

__version__ = "29.0.0"

try:
    from vulnerability_scanner import VulnerabilityScanner
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False
import sys
import time
import threading
import logging
import json
from datetime import datetime, timedelta
from pathlib import Path

# Safe imports with fallbacks
try:
    import psutil
    PSUTIL_VERSION = psutil.__version__
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    PSUTIL_VERSION = "0.0.0"

try:
    import GPUtil
    GPUTIL_AVAILABLE = True
except ImportError:
    GPUTIL_AVAILABLE = False

try:
    from pynvml import *
    nvmlInit()
    PYNVML_AVAILABLE = True
    PYNVML_VERSION = nvmlSystemGetDriverVersion()
except Exception as e:
    PYNVML_AVAILABLE = False
    PYNVML_VERSION = "0.0.0"

try:
    import wmi
    try:
        import pythoncom
        pythoncom.CoInitialize()
    except Exception:
        pass
    WMI_AVAILABLE = True
    wmi_client = wmi.WMI()
except ImportError:
    WMI_AVAILABLE = False

try:
    import platform
    PLATFORM_AVAILABLE = True
except ImportError:
    PLATFORM_AVAILABLE = False


class EnhancedHardwareMonitor:
    """Advanced hardware monitoring with comprehensive system information"""
    
    def __init__(self):
        self.logger = self._setup_logger()
        self.gpu_info = {}
        self.cpu_info = {}
        self.system_info = {}
        self.network_stats = {}
        self.disk_stats = {}
        self.temperature_data = {}
        self.gpu_handles = []
        self.performance_history = []
        self.max_history_entries = 100
        
        # Initialize monitoring
        self._detect_hardware()
        self._initialize_monitoring()
        
    def _setup_logger(self):
        """Setup logging for hardware monitor"""
        logger = logging.getLogger('HardwareMonitor')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _detect_hardware(self):
        """Detect all available hardware components"""
        self.logger.info("Detecting hardware components...")
        
        # Detect GPUs
        self._detect_gpus()
        
        # Detect CPU information
        self._detect_cpu()
        
        # Detect system information
        self._detect_system_info()
        
        # Initialize temperature monitoring
        self._initialize_temperature_monitoring()
        
    def _detect_gpus(self):
        """Enhanced GPU detection with multiple methods"""
        self.gpu_handles = []
        gpu_count = 0
        
        # Method 1: NVIDIA GPU via pynvml
        if PYNVML_AVAILABLE:
            try:
                gpu_count = nvmlDeviceGetCount()
                self.logger.info(f"Detected {gpu_count} NVIDIA GPUs via pynvml")
                
                for i in range(gpu_count):
                    handle = nvmlDeviceGetHandleByIndex(i)
                    self.gpu_handles.append(handle)
                    
            except Exception as e:
                self.logger.warning(f"NVIDIA GPU detection failed: {e}")
        
        # Method 2: GPUtil for broader GPU support
        if GPUTIL_AVAILABLE:
            try:
                gpus = GPUtil.getGPUs()
                if gpus:
                    self.logger.info(f"Detected {len(gpus)} GPUs via GPUtil")
            except Exception as e:
                self.logger.warning(f"GPUtil detection failed: {e}")
        
        # Method 3: WMI for Windows GPU detection
        if WMI_AVAILABLE and sys.platform == "win32":
            try:
                gpu_devices = wmi_client.Win32_VideoController()
                self.logger.info(f"Detected {len(gpu_devices)} GPUs via WMI")
            except Exception as e:
                self.logger.warning(f"WMI GPU detection failed: {e}")
    
    def _detect_cpu(self):
        """Enhanced CPU detection with detailed information"""
        if not PSUTIL_AVAILABLE:
            self.logger.error("psutil not available for CPU monitoring")
            return
        
        try:
            # Basic CPU info
            self.cpu_info = {
                'name': platform.processor() if PLATFORM_AVAILABLE else "Unknown CPU",
                'usage': 0,
                'usage_per_core': [],
                'temperature': 0,
                'core_count': psutil.cpu_count(logical=False),
                'thread_count': psutil.cpu_count(logical=True),
                'frequency': 0,
                'max_frequency': 0,
                'cache_l1': 0,
                'cache_l2': 0,
                'cache_l3': 0,
                'architecture': platform.architecture()[0] if PLATFORM_AVAILABLE else "Unknown",
                'available': True
            }
            
            # Get CPU frequency if available
            try:
                freq = psutil.cpu_freq()
                if freq:
                    self.cpu_info['frequency'] = freq.current
                    self.cpu_info['max_frequency'] = freq.max
            except Exception:
                pass
            
            # Enhanced CPU info via WMI on Windows
            if WMI_AVAILABLE and sys.platform == "win32":
                try:
                    cpu_info = wmi_client.Win32_Processor()[0]
                    self.cpu_info.update({
                        'name': cpu_info.Name,
                        'manufacturer': cpu_info.Manufacturer,
                        'max_clock_speed': cpu_info.MaxClockSpeed,
                        'l2_cache_size': cpu_info.L2CacheSize,
                        'l3_cache_size': cpu_info.L3CacheSize
                    })
                except Exception as e:
                    self.logger.warning(f"WMI CPU info failed: {e}")
            
            self.logger.info(f"CPU detected: {self.cpu_info.get('name', 'Unknown')}")
            
        except Exception as e:
            self.logger.error(f"CPU detection failed: {e}")
            self.cpu_info = {'available': False}
    
    def _detect_system_info(self):
        """Detect comprehensive system information"""
        try:
            self.system_info = {
                'platform': platform.system() if PLATFORM_AVAILABLE else "Unknown",
                'platform_version': platform.version() if PLATFORM_AVAILABLE else "Unknown",
                'platform_release': platform.release() if PLATFORM_AVAILABLE else "Unknown",
                'architecture': platform.architecture()[0] if PLATFORM_AVAILABLE else "Unknown",
                'hostname': platform.node() if PLATFORM_AVAILABLE else "Unknown",
                'processor': platform.processor() if PLATFORM_AVAILABLE else "Unknown",
                'python_version': platform.python_version() if PLATFORM_AVAILABLE else "Unknown",
                'boot_time': psutil.boot_time() if PSUTIL_AVAILABLE else 0,
                'total_memory': psutil.virtual_memory().total if PSUTIL_AVAILABLE else 0,
                'disk_total': 0
            }
            
            # Get total disk space
            if PSUTIL_AVAILABLE:
                try:
                    disk_usage = psutil.disk_usage('/')
                    self.system_info['disk_total'] = disk_usage.total
                except Exception:
                    pass
            
            self.logger.info(f"System: {self.system_info.get('platform', 'Unknown')} {self.system_info.get('platform_version', 'Unknown')}")
            
        except Exception as e:
            self.logger.error(f"System info detection failed: {e}")
    
    def _initialize_temperature_monitoring(self):
        """Initialize temperature monitoring for various components"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            # Try to get temperature sensors
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        if entries:
                            self.temperature_data[name] = [temp.current for temp in entries]
                            
            # GPU temperature via pynvml
            if PYNVML_AVAILABLE and self.gpu_handles:
                for i, handle in enumerate(self.gpu_handles):
                    try:
                        temp = nvmlDeviceGetTemperature(handle, NVML_TEMPERATURE_GPU)
                        self.temperature_data[f'gpu_{i}'] = temp
                    except Exception:
                        pass
                        
        except Exception as e:
            self.logger.warning(f"Temperature monitoring initialization failed: {e}")
    
    def _initialize_monitoring(self):
        """Initialize continuous monitoring thread"""
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.monitoring_active:
            try:
                # Update all metrics
                self.update_all_metrics()
                time.sleep(1)  # Update every second
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(5)  # Wait longer on error
    
    def update_all_metrics(self):
        """Update all hardware metrics"""
        timestamp = datetime.now()
        
        # Update CPU metrics
        cpu_data = self.get_cpu_info()
        
        # Update GPU metrics
        gpu_data = self.get_gpu_info()
        
        # Update memory metrics
        memory_data = self.get_memory_info()
        
        # Update network metrics
        network_data = self.get_network_info()
        
        # Update disk metrics
        disk_data = self.get_disk_info()
        
        # Store in performance history
        performance_entry = {
            'timestamp': timestamp.isoformat(),
            'cpu': cpu_data,
            'gpu': gpu_data,
            'memory': memory_data,
            'network': network_data,
            'disk': disk_data
        }
        
        self.performance_history.append(performance_entry)
        
        # Limit history size
        if len(self.performance_history) > self.max_history_entries:
            self.performance_history.pop(0)
    
    def get_gpu_info(self):
        """Get comprehensive GPU information"""
        if not PSUTIL_AVAILABLE:
            return self._get_default_gpu_info()
        
        info = {
            'name': 'No GPU detected',
            'usage': 0,
            'memory_used': 0,
            'memory_total': 0,
            'memory_percent': 0,
            'temperature': 0,
            'fan_speed': 0,
            'power_draw': 0,
            'clock_speed': 0,
            'memory_clock': 0,
            'driver_version': 'Unknown',
            'available': False,
            'gpu_count': 0,
            'multi_gpu': False
        }
        
        # Method 1: NVIDIA via pynvml (most detailed)
        if PYNVML_AVAILABLE and self.gpu_handles:
            try:
                handle = self.gpu_handles[0]  # Primary GPU
                info['gpu_count'] = len(self.gpu_handles)
                info['multi_gpu'] = len(self.gpu_handles) > 1
                
                # GPU name
                name = nvmlDeviceGetName(handle).decode('utf-8') if isinstance(nvmlDeviceGetName(handle), bytes) else nvmlDeviceGetName(handle)
                info['name'] = name
                info['available'] = True
                
                # GPU utilization
                try:
                    util = nvmlDeviceGetUtilizationRates(handle)
                    info['usage'] = util.gpu
                except Exception:
                    pass
                
                # Memory information
                try:
                    mem = nvmlDeviceGetMemoryInfo(handle)
                    info['memory_used'] = mem.used // (1024**2)  # MB
                    info['memory_total'] = mem.total // (1024**2)  # MB
                    info['memory_percent'] = (mem.used / mem.total) * 100
                except Exception:
                    pass
                
                # Temperature
                try:
                    info['temperature'] = nvmlDeviceGetTemperature(handle, NVML_TEMPERATURE_GPU)
                except Exception:
                    pass
                
                # Fan speed
                try:
                    info['fan_speed'] = nvmlDeviceGetFanSpeed(handle)
                except Exception:
                    pass
                
                # Power consumption
                try:
                    info['power_draw'] = nvmlDeviceGetPowerUsage(handle) / 1000  # Watts
                except Exception:
                    pass
                
                # Clock speeds
                try:
                    info['clock_speed'] = nvmlDeviceGetClockInfo(handle, NVML_CLOCK_GRAPHICS)
                    info['memory_clock'] = nvmlDeviceGetClockInfo(handle, NVML_CLOCK_MEM)
                except Exception:
                    pass
                
                # Driver version
                try:
                    info['driver_version'] = nvmlSystemGetDriverVersion().decode('utf-8') if isinstance(nvmlSystemGetDriverVersion(), bytes) else nvmlSystemGetDriverVersion()
                except Exception:
                    pass
                
            except Exception as e:
                self.logger.warning(f"NVIDIA GPU monitoring error: {e}")
        
        # Method 2: GPUtil as fallback
        elif GPUTIL_AVAILABLE:
            try:
                gpus = GPUtil.getGPUs()
                if gpus:
                    gpu = gpus[0]
                    info.update({
                        'name': gpu.name,
                        'usage': gpu.load * 100,
                        'memory_used': gpu.memoryUsed,
                        'memory_total': gpu.memoryTotal,
                        'memory_percent': (gpu.memoryUsed / gpu.memoryTotal) * 100 if gpu.memoryTotal > 0 else 0,
                        'temperature': gpu.temperature,
                        'available': True,
                        'gpu_count': len(gpus),
                        'multi_gpu': len(gpus) > 1
                    })
            except Exception as e:
                self.logger.warning(f"GPUtil monitoring error: {e}")
        
        # Method 3: Basic WMI GPU info
        elif WMI_AVAILABLE and sys.platform == "win32":
            try:
                gpu_devices = wmi_client.Win32_VideoController()
                if gpu_devices:
                    gpu = gpu_devices[0]
                    info.update({
                        'name': gpu.Name or gpu.Description,
                        'available': True,
                        'driver_version': gpu.DriverVersion or 'Unknown'
                    })
            except Exception as e:
                self.logger.warning(f"WMI GPU monitoring error: {e}")
        
        self.gpu_info = info
        return info
    
    def get_cpu_info(self):
        """Get comprehensive CPU information"""
        if not PSUTIL_AVAILABLE:
            return {'available': False}
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            
            # Update CPU info
            self.cpu_info.update({
                'usage': cpu_percent,
                'usage_per_core': cpu_per_core,
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            })
            
            # Temperature
            if 'cpu' in self.temperature_data:
                temps = self.temperature_data['cpu']
                if temps:
                    self.cpu_info['temperature'] = temps[0]
            
            # Frequency
            try:
                freq = psutil.cpu_freq()
                if freq:
                    self.cpu_info.update({
                        'frequency': freq.current,
                        'min_frequency': freq.min,
                        'max_frequency': freq.max
                    })
            except Exception:
                pass
            
            return self.cpu_info
            
        except Exception as e:
            self.logger.error(f"CPU monitoring error: {e}")
            return self.cpu_info
    
    def get_memory_info(self):
        """Get comprehensive memory information"""
        if not PSUTIL_AVAILABLE:
            return {'available': False}
        
        try:
            # Virtual memory
            virtual = psutil.virtual_memory()
            
            # Swap memory
            swap = psutil.swap_memory()
            
            return {
                'virtual': {
                    'total': virtual.total,
                    'available': virtual.available,
                    'used': virtual.used,
                    'free': virtual.free,
                    'percent': virtual.percent
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent
                },
                'available': True
            }
            
        except Exception as e:
            self.logger.error(f"Memory monitoring error: {e}")
            return {'available': False}
    
    def get_network_info(self):
        """Get network activity information"""
        if not PSUTIL_AVAILABLE:
            return {'available': False}
        
        try:
            net_io = psutil.net_io_counters()
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            # Calculate speed (if previous data exists)
            current_time = time.time()
            speed_data = {'upload': 0, 'download': 0}
            
            if hasattr(self, '_last_network_check'):
                time_diff = current_time - self._last_network_check['time']
                if time_diff > 0:
                    bytes_sent_diff = net_io.bytes_sent - self._last_network_check['bytes_sent']
                    bytes_recv_diff = net_io.bytes_recv - self._last_network_check['bytes_recv']
                    
                    speed_data['upload'] = bytes_sent_diff / time_diff  # bytes per second
                    speed_data['download'] = bytes_recv_diff / time_diff  # bytes per second
            
            # Store current data for next calculation
            self._last_network_check = {
                'time': current_time,
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv
            }
            
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'errin': net_io.errin,
                'errout': net_io.errout,
                'dropin': net_io.dropin,
                'dropout': net_io.dropout,
                'speed_upload': speed_data['upload'],
                'speed_download': speed_data['download'],
                'interfaces': list(net_if_addrs.keys()),
                'interface_stats': {name: {
                    'isup': stats.isup,
                    'duplex': stats.duplex,
                    'speed': stats.speed,
                    'mtu': stats.mtu
                } for name, stats in net_if_stats.items()},
                'available': True
            }
            
        except Exception as e:
            self.logger.error(f"Network monitoring error: {e}")
            return {'available': False}
    
    def get_disk_info(self):
        """Get disk usage and performance information"""
        if not PSUTIL_AVAILABLE:
            return {'available': False}
        
        try:
            disk_io = psutil.disk_io_counters()
            disk_partitions = psutil.disk_partitions()
            
            disk_usage = {}
            for partition in disk_partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': (usage.used / usage.total) * 100,
                        'fstype': partition.fstype,
                        'device': partition.device
                    }
                except Exception:
                    continue
            
            # Calculate speed (if previous data exists)
            current_time = time.time()
            speed_data = {'read': 0, 'write': 0}
            
            if hasattr(self, '_last_disk_check') and disk_io:
                time_diff = current_time - self._last_disk_check['time']
                if time_diff > 0:
                    read_bytes_diff = disk_io.read_bytes - self._last_disk_check['read_bytes']
                    write_bytes_diff = disk_io.write_bytes - self._last_disk_check['write_bytes']
                    
                    speed_data['read'] = read_bytes_diff / time_diff  # bytes per second
                    speed_data['write'] = write_bytes_diff / time_diff  # bytes per second
            
            # Store current data for next calculation
            if disk_io:
                self._last_disk_check = {
                    'time': current_time,
                    'read_bytes': disk_io.read_bytes,
                    'write_bytes': disk_io.write_bytes
                }
            
            return {
                'usage': disk_usage,
                'io_counters': {
                    'read_count': disk_io.read_count if disk_io else 0,
                    'write_count': disk_io.write_count if disk_io else 0,
                    'read_bytes': disk_io.read_bytes if disk_io else 0,
                    'write_bytes': disk_io.write_bytes if disk_io else 0,
                    'read_time': disk_io.read_time if disk_io else 0,
                    'write_time': disk_io.write_time if disk_io else 0
                },
                'speed_read': speed_data['read'],
                'speed_write': speed_data['write'],
                'available': True
            }
            
        except Exception as e:
            self.logger.error(f"Disk monitoring error: {e}")
            return {'available': False}
    
    def get_temperature_info(self):
        """Get temperature information for all components"""
        return {
            'sensors': self.temperature_data.copy(),
            'cpu_temp': self.cpu_info.get('temperature', 0),
            'gpu_temp': self.gpu_info.get('temperature', 0),
            'available': len(self.temperature_data) > 0
        }
    
    def get_performance_history(self, minutes=5):
        """Get performance history for the last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        filtered_history = []
        for entry in self.performance_history:
            entry_time = datetime.fromisoformat(entry['timestamp'])
            if entry_time >= cutoff_time:
                filtered_history.append(entry)
        
        return filtered_history
    
    def get_system_summary(self):
        """Get a comprehensive system summary"""
        return {
            'system': self.system_info,
            'cpu': self.get_cpu_info(),
            'gpu': self.get_gpu_info(),
            'memory': self.get_memory_info(),
            'network': self.get_network_info(),
            'disk': self.get_disk_info(),
            'temperature': self.get_temperature_info(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_default_gpu_info(self):
        """Default GPU info when psutil is not available"""
        return {
            'name': 'Hardware monitoring unavailable',
            'usage': 0,
            'memory_used': 0,
            'memory_total': 0,
            'memory_percent': 0,
            'temperature': 0,
            'fan_speed': 0,
            'power_draw': 0,
            'clock_speed': 0,
            'memory_clock': 0,
            'driver_version': 'Unknown',
            'available': False
        }
    
    def cleanup(self):
        """Cleanup monitoring resources"""
        self.monitoring_active = False
        if hasattr(self, 'monitoring_thread'):
            self.monitoring_thread.join(timeout=5)


# Test the enhanced hardware monitor
if __name__ == "__main__":
    monitor = EnhancedHardwareMonitor()
    
    print("=== Enhanced Hardware Monitor Test ===")
    print(f"System: {monitor.system_info.get('platform', 'Unknown')}")
    print(f"CPU: {monitor.cpu_info.get('name', 'Unknown')}")
    print(f"GPU: {monitor.gpu_info.get('name', 'Unknown')}")
    print(f"GPU Available: {monitor.gpu_info.get('available', False)}")
    
    # Test data collection
    summary = monitor.get_system_summary()
    print(f"\n=== System Summary ===")
    print(json.dumps(summary, indent=2, default=str))
    
    # Keep monitoring for a few seconds
    time.sleep(3)
    
    # Get performance history
    history = monitor.get_performance_history(minutes=1)
    print(f"\nCollected {len(history)} data points in the last minute")
    
    monitor.cleanup()
    print("\nHardware monitor test completed.")