"""
Device Adaptation Engine for Downpour v29 Titanium
Automatically detects and adapts to any hardware, device, and environment

v29: Added KEV vulnerability context for security-aware adaptation.
"""

__version__ = "29.0.0"

import logging
import os
import sys
import platform
import subprocess
import json
import time
from typing import Dict, List, Tuple, Any

_dae_logger = logging.getLogger(__name__)

class DeviceAdaptationEngine:
    """Ultra-smart device detection and adaptation system"""
    
    def __init__(self):
        self.device_profile = {}
        self.hardware_capabilities = {}
        self.environment_factors = {}
        self.optimization_settings = {}
        self.adaptation_strategies = {}
        
    def comprehensive_device_analysis(self) -> Dict[str, Any]:
        """Perform comprehensive device and environment analysis."""
        _dae_logger.info("Starting comprehensive device analysis")
        
        analysis_result = {
            'timestamp': time.time(),
            'device_type': self._detect_device_type(),
            'hardware_profile': self._analyze_hardware(),
            'environment_profile': self._analyze_environment(),
            'network_profile': self._analyze_network(),
            'security_profile': self._analyze_security_context(),
            'performance_profile': self._analyze_performance_capabilities(),
            'user_context': self._analyze_user_context(),
            'adaptation_recommendations': {}
        }
        
        # Generate adaptation strategies
        analysis_result['adaptation_recommendations'] = self._generate_adaptation_strategies(analysis_result)
        
        # Save device profile
        self.device_profile = analysis_result
        self._save_device_profile()
        
        return analysis_result
    
    def _detect_device_type(self) -> str:
        """Detect the type of device being used"""
        try:
            # Check manufacturer and model
            computer_system = {}
            try:
                result = subprocess.run(['wmic', 'computersystem', 'get', 'manufacturer,model', '/format:json'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout)
                    if data and len(data) > 0:
                        computer_system = data[0]
            except Exception:
                pass
            
            manufacturer = computer_system.get('Manufacturer', '').lower()
            model = computer_system.get('Model', '').lower()
            
            # Detect device type based on characteristics
            if any(keyword in manufacturer for keyword in ['microsoft', 'vmware', 'virtualbox', 'qemu']):
                return 'virtual_machine'
            elif any(keyword in model for keyword in ['laptop', 'notebook', 'ultrabook', 'macbook']):
                return 'laptop'
            elif any(keyword in model for keyword in ['desktop', 'tower', 'workstation']):
                return 'desktop'
            elif any(keyword in manufacturer for keyword in ['dell', 'hp', 'lenovo', 'asus', 'acer']):
                if any(keyword in model for keyword in ['laptop', 'notebook']):
                    return 'laptop'
                else:
                    return 'desktop'
            else:
                # Fall back to hardware-based detection
                return self._detect_device_by_hardware()
                
        except Exception as e:
            _dae_logger.debug("Device type detection failed: %s", e)
            return 'unknown'
    
    def _detect_device_by_hardware(self) -> str:
        """Detect device type based on hardware characteristics"""
        try:
            import psutil
            
            # Check battery presence (laptops have batteries)
            battery = psutil.sensors_battery()
            if battery is not None:
                return 'laptop'
            
            # Check number of cores and memory
            cpu_count = psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total // (1024**3)
            
            # High-end desktops typically have more cores and memory
            if cpu_count >= 8 and memory_gb >= 16:
                return 'desktop'
            elif cpu_count >= 4 and memory_gb >= 8:
                return 'desktop'  # Could be high-end laptop or desktop
            else:
                return 'laptop'  # Assume lower-spec is laptop/mobile
                
        except ImportError:
            # If psutil not available, use basic detection
            return 'unknown'
        except Exception:
            return 'unknown'
    
    def _analyze_hardware(self) -> Dict[str, Any]:
        """Comprehensive hardware analysis"""
        hardware_info = {
            'cpu': self._analyze_cpu(),
            'memory': self._analyze_memory(),
            'storage': self._analyze_storage(),
            'graphics': self._analyze_graphics(),
            'network': self._analyze_network_hardware(),
            'peripherals': self._analyze_peripherals(),
            'sensors': self._analyze_sensors()
        }
        
        return hardware_info
    
    def _analyze_cpu(self) -> Dict[str, Any]:
        """Analyze CPU capabilities"""
        cpu_info = {
            'name': 'Unknown',
            'architecture': platform.machine(),
            'cores': 1,
            'logical_cores': 1,
            'max_frequency': 0.0,
            'capabilities': []
        }
        
        try:
            import psutil
            
            # Get CPU info
            cpu_info['logical_cores'] = psutil.cpu_count(logical=True)
            cpu_info['cores'] = psutil.cpu_count(logical=False)
            
            # Get CPU frequency
            freq = psutil.cpu_freq()
            if freq:
                cpu_info['max_frequency'] = freq.max
            
            # Get CPU name (Windows specific)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'cpu', 'get', 'name', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data and len(data) > 0:
                            cpu_info['name'] = data[0].get('Name', 'Unknown')
                except Exception:
                    pass
            
            # Determine capabilities based on CPU info
            cpu_name = cpu_info['name'].lower()
            if any(brand in cpu_name for brand in ['intel', 'amd']):
                cpu_info['capabilities'].append('x64')
            if any(feature in cpu_name for feature in ['core i9', 'core i7', 'ryzen 9', 'ryzen 7']):
                cpu_info['capabilities'].append('high_performance')
            if any(feature in cpu_name for feature in ['ultra', 'low power']):
                cpu_info['capabilities'].append('power_efficient')
                
        except ImportError:
            pass
        except Exception as e:
            _dae_logger.debug("CPU analysis failed: %s", e)
        
        return cpu_info
    
    def _analyze_memory(self) -> Dict[str, Any]:
        """Analyze memory configuration"""
        memory_info = {
            'total_gb': 0,
            'available_gb': 0,
            'speed_mhz': 0,
            'type': 'Unknown',
            'performance_tier': 'unknown'
        }
        
        try:
            import psutil
            
            # Get memory info
            virtual_memory = psutil.virtual_memory()
            memory_info['total_gb'] = virtual_memory.total // (1024**3)
            memory_info['available_gb'] = virtual_memory.available // (1024**3)
            
            # Determine performance tier
            total_gb = memory_info['total_gb']
            if total_gb >= 32:
                memory_info['performance_tier'] = 'high_end'
            elif total_gb >= 16:
                memory_info['performance_tier'] = 'performance'
            elif total_gb >= 8:
                memory_info['performance_tier'] = 'standard'
            elif total_gb >= 4:
                memory_info['performance_tier'] = 'basic'
            else:
                memory_info['performance_tier'] = 'minimal'
                
            # Try to get memory speed (Windows specific)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'memorychip', 'get', 'speed', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data and len(data) > 0:
                            speeds = [int(item.get('Speed', 0)) for item in data if item.get('Speed')]
                            if speeds:
                                memory_info['speed_mhz'] = max(speeds)
                except Exception:
                    pass
                    
        except ImportError:
            pass
        except Exception as e:
            _dae_logger.debug("Memory analysis failed: %s", e)
        
        return memory_info
    
    def _analyze_storage(self) -> Dict[str, Any]:
        """Analyze storage configuration"""
        storage_info = {
            'drives': [],
            'total_capacity_gb': 0,
            'ssd_present': False,
            'hdd_present': False,
            'primary_drive_type': 'unknown',
            'performance_tier': 'unknown'
        }
        
        try:
            import psutil
            
            # Analyze disk partitions
            disk_partitions = psutil.disk_partitions()
            total_capacity = 0
            
            for partition in disk_partitions:
                try:
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    drive_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total_gb': disk_usage.total // (1024**3),
                        'free_gb': disk_usage.free // (1024**3),
                        'used_gb': disk_usage.used // (1024**3),
                        'drive_type': 'unknown'
                    }
                    
                    total_capacity += drive_info['total_gb']
                    
                    # Try to determine drive type (Windows specific)
                    if platform.system() == 'Windows':
                        try:
                            result = subprocess.run(['wmic', 'diskdrive', 'get', 'model,mediatype', '/format:json'], 
                                                  capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                import json
                                data = json.loads(result.stdout)
                                if data and len(data) > 0:
                                    for drive in data:
                                        model = drive.get('Model', '').lower()
                                        media_type = drive.get('MediaType', '').lower()
                                        if 'ssd' in model or 'solid state' in model:
                                            drive_info['drive_type'] = 'ssd'
                                            storage_info['ssd_present'] = True
                                        elif 'hdd' in model or 'hard disk' in model:
                                            drive_info['drive_type'] = 'hdd'
                                            storage_info['hdd_present'] = True
                        except Exception:
                            pass
                    
                    storage_info['drives'].append(drive_info)
                    
                except Exception as e:
                    _dae_logger.debug("Could not analyze partition %s: %s", partition.device, e)
            
            storage_info['total_capacity_gb'] = total_capacity
            
            # Determine primary drive type and performance tier
            if storage_info['ssd_present']:
                storage_info['primary_drive_type'] = 'ssd'
                storage_info['performance_tier'] = 'high_performance'
            elif storage_info['hdd_present']:
                storage_info['primary_drive_type'] = 'hdd'
                storage_info['performance_tier'] = 'standard'
            else:
                storage_info['primary_drive_type'] = 'unknown'
                storage_info['performance_tier'] = 'unknown'
                
        except ImportError:
            pass
        except Exception as e:
            _dae_logger.debug("Storage analysis failed: %s", e)
        
        return storage_info
    
    def _analyze_graphics(self) -> Dict[str, Any]:
        """Analyze graphics capabilities"""
        graphics_info = {
            'gpus': [],
            'primary_gpu': 'unknown',
            'gpu_memory_mb': 0,
            'directx_support': False,
            'opengl_support': False,
            'cuda_support': False,
            'gaming_capability': 'unknown'
        }
        
        try:
            # Try to get GPU information (Windows specific)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'path', 'win32_VideoController', 'get', 'name,adapterram', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data and len(data) > 0:
                            for gpu in data:
                                gpu_info = {
                                    'name': gpu.get('Name', 'Unknown'),
                                    'memory_mb': 0,
                                    'type': 'unknown'
                                }
                                
                                # Parse GPU memory
                                adapter_ram = gpu.get('AdapterRAM')
                                if adapter_ram and adapter_ram.isdigit():
                                    gpu_info['memory_mb'] = int(adapter_ram) // (1024**2)
                                
                                # Determine GPU type
                                name = gpu_info['name'].lower()
                                if any(brand in name for brand in ['nvidia', 'geforce', 'quadro', 'tesla']):
                                    gpu_info['type'] = 'nvidia'
                                    graphics_info['cuda_support'] = True
                                elif any(brand in name for brand in ['amd', 'radeon', 'radeon pro']):
                                    gpu_info['type'] = 'amd'
                                elif any(brand in name for brand in ['intel', 'iris', 'uhd', 'hd graphics']):
                                    gpu_info['type'] = 'integrated'
                                else:
                                    gpu_info['type'] = 'discrete'
                                
                                graphics_info['gpus'].append(gpu_info)
                                
                                # Set primary GPU
                                if graphics_info['primary_gpu'] == 'unknown':
                                    graphics_info['primary_gpu'] = gpu_info['type']
                                    graphics_info['gpu_memory_mb'] = gpu_info['memory_mb']
                except Exception:
                    pass
            
            # Determine gaming capability
            if graphics_info['gpu_memory_mb'] >= 4096:
                graphics_info['gaming_capability'] = 'high_end'
            elif graphics_info['gpu_memory_mb'] >= 2048:
                graphics_info['gaming_capability'] = 'gaming'
            elif graphics_info['gpu_memory_mb'] >= 1024:
                graphics_info['gaming_capability'] = 'light_gaming'
            else:
                graphics_info['gaming_capability'] = 'integrated'
                
        except Exception as e:
            _dae_logger.debug("Graphics analysis failed: %s", e)
        
        return graphics_info
    
    def _analyze_network_hardware(self) -> Dict[str, Any]:
        """Analyze network hardware and connectivity"""
        network_info = {
            'interfaces': [],
            'connection_type': 'unknown',
            'speed_mbps': 0,
            'wifi_available': False,
            'ethernet_available': False,
            'internet_connected': False
        }
        
        try:
            import psutil
            
            # Get network interfaces
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, addresses in net_if_addrs.items():
                interface_info = {
                    'name': interface_name,
                    'addresses': [],
                    'is_up': False,
                    'speed': 0,
                    'type': 'unknown'
                }
                
                # Get interface stats
                if interface_name in net_if_stats:
                    stats = net_if_stats[interface_name]
                    interface_info['is_up'] = stats.isup
                    interface_info['speed'] = stats.speed
                
                # Process addresses
                for addr in addresses:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_info['addresses'].append(addr_info)
                
                # Determine interface type
                name_lower = interface_name.lower()
                if any(keyword in name_lower for keyword in ['wi-fi', 'wifi', 'wlan', 'wireless']):
                    interface_info['type'] = 'wifi'
                    network_info['wifi_available'] = True
                elif any(keyword in name_lower for keyword in ['ethernet', 'lan', 'local', 'wired']):
                    interface_info['type'] = 'ethernet'
                    network_info['ethernet_available'] = True
                
                network_info['interfaces'].append(interface_info)
            
            # Check internet connectivity
            try:
                import socket
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                network_info['internet_connected'] = True
            except Exception:
                network_info['internet_connected'] = False
                
        except ImportError:
            pass
        except Exception as e:
            _dae_logger.debug("Network hardware analysis failed: %s", e)
        
        return network_info
    
    def _analyze_peripherals(self) -> Dict[str, Any]:
        """Analyze connected peripherals"""
        peripherals_info = {
            'monitors': [],
            'keyboard': False,
            'mouse': False,
            'webcam': False,
            'microphone': False,
            'speakers': False,
            'printers': [],
            'usb_devices': []
        }
        
        try:
            # Check for monitors (Windows specific)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'desktopmonitor', 'get', 'screenheight,screenwidth', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data and len(data) > 0:
                            for monitor in data:
                                monitor_info = {
                                    'width': monitor.get('ScreenWidth', 0),
                                    'height': monitor.get('ScreenHeight', 0),
                                    'resolution': f"{monitor.get('ScreenWidth', 0)}x{monitor.get('ScreenHeight', 0)}"
                                }
                                peripherals_info['monitors'].append(monitor_info)
                except Exception:
                    pass
            
            # Check for common peripherals
            try:
                result = subprocess.run(['wmic', 'path', 'win32_keyboard', 'get', 'name', '/format:json'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    peripherals_info['keyboard'] = True
            except Exception:
                pass
            
            try:
                result = subprocess.run(['wmic', 'path', 'win32_pointingdevice', 'get', 'name', '/format:json'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    peripherals_info['mouse'] = True
            except Exception:
                pass
                
        except Exception as e:
            _dae_logger.debug("Peripheral analysis failed: %s", e)
        
        return peripherals_info
    
    def _analyze_sensors(self) -> Dict[str, Any]:
        """Analyze available sensors"""
        sensors_info = {
            'temperature_sensors': [],
            'battery': None,
            'fan_sensors': [],
            'power_sensors': []
        }
        
        try:
            import psutil
            
            # Check for battery
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    sensors_info['battery'] = {
                        'percent': battery.percent,
                        'plugged_in': battery.power_plugged,
                        'seconds_left': battery.secsleft if not battery.power_plugged else None
                    }
            
            # Check for temperature sensors (if available)
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                for name, entries in temps.items():
                    for entry in entries:
                        sensor_info = {
                            'name': name,
                            'label': entry.label or 'Unknown',
                            'current_temp': entry.current,
                            'high_temp': entry.high,
                            'critical_temp': entry.critical
                        }
                        sensors_info['temperature_sensors'].append(sensor_info)
                        
        except ImportError:
            pass
        except Exception as e:
            _dae_logger.debug("Sensor analysis failed: %s", e)
        
        return sensors_info
    
    def _analyze_environment(self) -> Dict[str, Any]:
        """Analyze software and runtime environment"""
        env_info = {
            'operating_system': self._analyze_os(),
            'python_environment': self._analyze_python_env(),
            'installed_software': self._detect_installed_software(),
            'system_services': self._analyze_system_services(),
            'security_software': self._detect_security_software()
        }
        
        return env_info
    
    def _analyze_os(self) -> Dict[str, Any]:
        """Analyze operating system"""
        os_info = {
            'name': platform.system(),
            'version': platform.version(),
            'release': platform.release(),
            'architecture': platform.architecture()[0],
            'machine': platform.machine(),
            'processor': platform.processor(),
            'edition': 'Unknown',
            'build_number': 'Unknown'
        }
        
        try:
            # Get detailed Windows info
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'os', 'get', 'edition,version,buildnumber', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data and len(data) > 0:
                            os_info['edition'] = data[0].get('Edition', 'Unknown')
                            os_info['build_number'] = data[0].get('BuildNumber', 'Unknown')
                except Exception:
                    pass
                    
        except Exception as e:
            _dae_logger.debug("OS analysis failed: %s", e)
        
        return os_info
    
    def _analyze_python_env(self) -> Dict[str, Any]:
        """Analyze Python environment"""
        python_info = {
            'version': sys.version,
            'version_info': list(sys.version_info),
            'executable': sys.executable,
            'platform': sys.platform,
            'implementation': platform.python_implementation(),
            'compiler': platform.python_compiler(),
            'packages': {},
            'virtual_env': False
        }
        
        # Check if in virtual environment
        python_info['virtual_env'] = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        
        # Check key packages
        key_packages = ['psutil', 'numpy', 'pandas', 'requests', 'tkinter', 'matplotlib', 'scipy']
        for package in key_packages:
            try:
                __import__(package)
                python_info['packages'][package] = True
            except ImportError:
                python_info['packages'][package] = False
        
        return python_info
    
    def _detect_installed_software(self) -> List[str]:
        """Detect commonly installed software"""
        software_list = []
        
        try:
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'product', 'get', 'name', '/format:json'], 
                                          capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data:
                            for item in data:
                                name = item.get('Name', '')
                                if name and name != 'Name':
                                    software_list.append(name)
                except Exception:
                    pass
                    
        except Exception as e:
            _dae_logger.debug("Software detection failed: %s", e)
        
        return software_list[:50]  # Limit to first 50 items
    
    def _analyze_system_services(self) -> Dict[str, Any]:
        """Analyze running system services"""
        services_info = {
            'critical_services': {},
            'security_services': {},
            'performance_services': {}
        }
        
        try:
            if platform.system() == 'Windows':
                # Check critical services
                critical_services = ['Themes', 'AudioSrv', 'BITS', 'Winmgmt']
                security_services = ['WinDefend', 'wscsvc', 'BFE', 'MpsSvc']
                
                all_services = critical_services + security_services
                
                for service in all_services:
                    try:
                        result = subprocess.run(['sc', 'query', service], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            status = 'running' if 'RUNNING' in result.stdout.upper() else 'stopped'
                            
                            if service in critical_services:
                                services_info['critical_services'][service] = status
                            elif service in security_services:
                                services_info['security_services'][service] = status
                    except Exception:
                        services_info['critical_services'][service] = 'unknown'
                        
        except Exception as e:
            _dae_logger.debug("Services analysis failed: %s", e)
        
        return services_info
    
    def _detect_security_software(self) -> Dict[str, Any]:
        """Detect security software"""
        security_info = {
            'antivirus': [],
            'firewall': [],
            'antimalware': []
        }
        
        try:
            if platform.system() == 'Windows':
                # Check Windows Defender
                try:
                    result = subprocess.run(['sc', 'query', 'WinDefend'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and 'RUNNING' in result.stdout.upper():
                        security_info['antivirus'].append('Windows Defender')
                except Exception:
                    pass
                
                # Check Windows Firewall
                try:
                    result = subprocess.run(['sc', 'query', 'MpsSvc'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and 'RUNNING' in result.stdout.upper():
                        security_info['firewall'].append('Windows Firewall')
                except Exception:
                    pass
                    
        except Exception as e:
            _dae_logger.debug("Security software detection failed: %s", e)
        
        return security_info
    
    def _analyze_network(self) -> Dict[str, Any]:
        """Analyze network connectivity and performance"""
        network_info = {
            'connectivity_test': {},
            'bandwidth_test': {},
            'dns_test': {},
            'latency_test': {}
        }
        
        try:
            # Test basic connectivity
            import socket
            try:
                start_time = time.time()
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                latency = (time.time() - start_time) * 1000
                network_info['connectivity_test'] = {
                    'status': 'connected',
                    'latency_ms': round(latency, 2)
                }
            except Exception:
                network_info['connectivity_test'] = {
                    'status': 'disconnected',
                    'latency_ms': None
                }
                
        except Exception as e:
            _dae_logger.debug("Network analysis failed: %s", e)
        
        return network_info
    
    def _analyze_security_context(self) -> Dict[str, Any]:
        """Analyze security context and permissions"""
        security_info = {
            'user_privileges': {},
            'uac_status': 'unknown',
            'firewall_status': 'unknown',
            'permissions': {}
        }
        
        try:
            # Check user privileges
            try:
                result = subprocess.run(['net', 'session'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    security_info['user_privileges'] = {
                        'admin_access': True,
                        'level': 'administrator'
                    }
                else:
                    security_info['user_privileges'] = {
                        'admin_access': False,
                        'level': 'standard_user'
                    }
            except Exception:
                security_info['user_privileges'] = {
                    'admin_access': False,
                    'level': 'unknown'
                }
                
        except Exception as e:
            _dae_logger.debug("Security context analysis failed: %s", e)
        
        return security_info
    
    def _analyze_performance_capabilities(self) -> Dict[str, Any]:
        """Analyze system performance capabilities"""
        performance_info = {
            'cpu_benchmark': {},
            'memory_benchmark': {},
            'storage_benchmark': {},
            'overall_score': 0,
            'performance_tier': 'unknown'
        }
        
        try:
            import psutil
            
            # Simple CPU benchmark
            start_time = time.time()
            end_time = start_time + 1.0
            count = 0
            while time.time() < end_time:
                count += 1
                x = [i**2 for i in range(1000)]
            
            performance_info['cpu_benchmark'] = {
                'operations_per_second': count,
                'relative_score': min(count / 1000000, 1.0) * 100
            }
            
            # Memory benchmark
            start_time = time.time()
            test_data = list(range(10000))
            sorted_data = sorted(test_data)
            memory_time = time.time() - start_time
            
            performance_info['memory_benchmark'] = {
                'sort_time_seconds': memory_time,
                'relative_score': max(0, (1.0 - memory_time) * 100)
            }
            
            # Calculate overall performance score
            cpu_score = performance_info['cpu_benchmark']['relative_score']
            memory_score = performance_info['memory_benchmark']['relative_score']
            performance_info['overall_score'] = (cpu_score + memory_score) / 2
            
            # Determine performance tier
            score = performance_info['overall_score']
            if score >= 80:
                performance_info['performance_tier'] = 'high_performance'
            elif score >= 60:
                performance_info['performance_tier'] = 'performance'
            elif score >= 40:
                performance_info['performance_tier'] = 'standard'
            elif score >= 20:
                performance_info['performance_tier'] = 'basic'
            else:
                performance_info['performance_tier'] = 'minimal'
                
        except ImportError:
            performance_info['performance_tier'] = 'unknown'
        except Exception as e:
            _dae_logger.debug("Performance analysis failed: %s", e)
        
        return performance_info
    
    def _analyze_user_context(self) -> Dict[str, Any]:
        """Analyze user context and usage patterns"""
        user_context = {
            'username': os.environ.get('USERNAME', 'unknown'),
            'domain': os.environ.get('USERDOMAIN', 'unknown'),
            'computer_name': os.environ.get('COMPUTERNAME', 'unknown'),
            'user_profile_path': os.environ.get('USERPROFILE', ''),
            'temp_path': os.environ.get('TEMP', ''),
            'app_data_path': os.environ.get('APPDATA', ''),
            'portable_mode': False
        }
        
        # Check if running from portable media
        try:
            app_dir = os.path.dirname(os.path.abspath(__file__))
            if any(drive in app_dir for drive in ['A:', 'B:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:', 'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:', 'U:', 'V:', 'W:', 'X:', 'Y:', 'Z:']):
                user_context['portable_mode'] = True
        except Exception:
            pass
        
        return user_context
    
    def _generate_adaptation_strategies(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate adaptation strategies based on analysis"""
        strategies = {
            'performance_optimization': {},
            'feature_adaptation': {},
            'ui_optimization': {},
            'security_adaptation': {},
            'resource_management': {}
        }
        
        device_type = analysis_result['device_type']
        hardware = analysis_result['hardware_profile']
        performance = analysis_result['performance_profile']
        security = analysis_result['security_profile']
        
        # Performance optimization strategies
        if performance['performance_tier'] == 'high_performance':
            strategies['performance_optimization'] = {
                'mode': 'maximum',
                'features': ['all_features', 'advanced_monitoring', 'real_time_analysis'],
                'resource_allocation': 'high'
            }
        elif performance['performance_tier'] == 'performance':
            strategies['performance_optimization'] = {
                'mode': 'enhanced',
                'features': ['core_features', 'standard_monitoring'],
                'resource_allocation': 'medium'
            }
        elif performance['performance_tier'] == 'standard':
            strategies['performance_optimization'] = {
                'mode': 'balanced',
                'features': ['essential_features', 'basic_monitoring'],
                'resource_allocation': 'balanced'
            }
        else:
            strategies['performance_optimization'] = {
                'mode': 'minimal',
                'features': ['core_features_only'],
                'resource_allocation': 'low'
            }
        
        # Device-specific adaptations
        if device_type == 'laptop':
            strategies['feature_adaptation'] = {
                'power_management': 'aggressive',
                'thermal_management': 'enabled',
                'battery_optimization': 'enabled',
                'adaptive_performance': 'enabled'
            }
        elif device_type == 'desktop':
            strategies['feature_adaptation'] = {
                'power_management': 'performance',
                'thermal_management': 'standard',
                'battery_optimization': 'disabled',
                'adaptive_performance': 'disabled'
            }
        elif device_type == 'virtual_machine':
            strategies['feature_adaptation'] = {
                'power_management': 'disabled',
                'thermal_management': 'disabled',
                'battery_optimization': 'disabled',
                'virtualization_optimization': 'enabled'
            }
        
        # Memory-based adaptations
        memory_gb = hardware['memory']['total_gb']
        if memory_gb >= 32:
            strategies['resource_management'] = {
                'cache_size': 'large',
                'buffer_size': 'large',
                'concurrent_operations': 'high',
                'memory_optimization': 'aggressive'
            }
        elif memory_gb >= 16:
            strategies['resource_management'] = {
                'cache_size': 'medium',
                'buffer_size': 'medium',
                'concurrent_operations': 'medium',
                'memory_optimization': 'standard'
            }
        elif memory_gb >= 8:
            strategies['resource_management'] = {
                'cache_size': 'small',
                'buffer_size': 'small',
                'concurrent_operations': 'low',
                'memory_optimization': 'conservative'
            }
        else:
            strategies['resource_management'] = {
                'cache_size': 'minimal',
                'buffer_size': 'minimal',
                'concurrent_operations': 'minimal',
                'memory_optimization': 'minimal'
            }
        
        # Security adaptations
        if security['user_privileges'].get('admin_access', False):
            strategies['security_adaptation'] = {
                'privilege_level': 'administrator',
                'system_access': 'full',
                'security_bypass': 'enabled'
            }
        else:
            strategies['security_adaptation'] = {
                'privilege_level': 'user',
                'system_access': 'limited',
                'security_bypass': 'adaptive'
            }
        
        # Graphics-based UI adaptations
        graphics = hardware['graphics']
        if graphics['gaming_capability'] in ['high_end', 'gaming']:
            strategies['ui_optimization'] = {
                'rendering_quality': 'high',
                'animations': 'enabled',
                'effects': 'enabled',
                'resolution': 'native'
            }
        elif graphics['gaming_capability'] == 'light_gaming':
            strategies['ui_optimization'] = {
                'rendering_quality': 'medium',
                'animations': 'limited',
                'effects': 'limited',
                'resolution': 'optimized'
            }
        else:
            strategies['ui_optimization'] = {
                'rendering_quality': 'basic',
                'animations': 'disabled',
                'effects': 'disabled',
                'resolution': 'standard'
            }
        
        return strategies
    
    def _save_device_profile(self):
        """Save device profile to file anchored to this module's directory."""
        try:
            profile_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'device_profile.json')
            with open(profile_path, 'w') as f:
                json.dump(self.device_profile, f, indent=2, default=str)
            _dae_logger.debug("Device profile saved to %s", profile_path)
        except Exception as exc:
            _dae_logger.debug("Could not save device profile: %s", exc)
    
    def get_optimization_settings(self) -> Dict[str, Any]:
        """Get optimization settings based on device analysis"""
        if not self.device_profile:
            self.comprehensive_device_analysis()
        
        return self.device_profile.get('adaptation_recommendations', {})

# Usage example and testing
if __name__ == "__main__":
    engine = DeviceAdaptationEngine()
    profile = engine.comprehensive_device_analysis()
    
    print("\n🎯 DEVICE ANALYSIS COMPLETE")
    print("=" * 50)
    print(f"Device Type: {profile['device_type']}")
    print(f"Performance Tier: {profile['performance_profile']['performance_tier']}")
    print(f"User Level: {profile['security_profile']['user_privileges'].get('level', 'unknown')}")
    
    strategies = profile['adaptation_recommendations']
    print(f"\n🧠 OPTIMIZATION STRATEGY:")
    print(f"Performance Mode: {strategies['performance_optimization'].get('mode', 'unknown')}")
    print(f"Features: {', '.join(strategies['performance_optimization'].get('features', []))}")
    print(f"Resource Allocation: {strategies['resource_management'].get('memory_optimization', 'unknown')}")
