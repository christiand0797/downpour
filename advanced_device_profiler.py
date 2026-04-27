"""
__version__ = "29.0.0"
Advanced Device Profiler for Downpour v29 Titanium
Sophisticated device analysis for admin-level operations and security bypass
"""

import os
import sys
import platform
import subprocess
import json
import time
import hashlib
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
import socket
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict
import re

@dataclass
class SystemCapability:
    """System capability assessment"""
    admin_access: bool
    uac_level: str
    defender_status: str
    firewall_status: str
    network_access: bool
    installation_permissions: bool
    registry_access: bool
    service_management: bool
    overall_capability: float

@dataclass
class HardwareProfile:
    """Detailed hardware profiling"""
    cpu_architecture: str
    cpu_features: List[str]
    memory_config: Dict[str, Any]
    storage_hierarchy: List[Dict[str, Any]]
    graphics_capabilities: Dict[str, Any]
    network_interfaces: List[Dict[str, Any]]
    peripheral_devices: List[Dict[str, Any]]
    thermal_capabilities: Dict[str, Any]
    power_management: Dict[str, Any]

@dataclass
class SecurityContext:
    """Security and privilege context analysis"""
    user_account: Dict[str, Any]
    group_memberships: List[str]
    privilege_tokens: List[str]
    security_policies: Dict[str, Any]
    defender_configuration: Dict[str, Any]
    firewall_rules: Dict[str, Any]
    uac_settings: Dict[str, Any]
    applocker_policies: Dict[str, Any]

class AdvancedDeviceProfiler:
    """Sophisticated device profiling for admin operations"""
    
    def __init__(self):
        self.system_capability = None
        self.hardware_profile = None
        self.security_context = None
        self.adaptation_strategies = {}
        self.bypass_methods = {}
        self.installation_capabilities = {}
        
    def comprehensive_admin_analysis(self) -> Dict[str, Any]:
        """Perform comprehensive analysis for admin-level operations"""
        import logging
        logging.info("[ANALYSIS] Starting comprehensive admin-level device analysis...")
        
        analysis_result = {
            'timestamp': time.time(),
            'system_capability': self._assess_system_capabilities(),
            'hardware_profile': self._profile_hardware_comprehensive(),
            'security_context': self._analyze_security_context(),
            'network_analysis': self._analyze_network_capabilities(),
            'installation_analysis': self._analyze_installation_capabilities(),
            'bypass_analysis': self._analyze_bypass_capabilities(),
            'adaptation_strategies': {},
            'success_probability': 0.0
        }
        
        # Generate sophisticated adaptation strategies
        analysis_result['adaptation_strategies'] = self._generate_adaptation_strategies(analysis_result)
        
        # Calculate success probability
        analysis_result['success_probability'] = self._calculate_success_probability(analysis_result)
        # Observability: log a quick summary of phase progress
        import logging
        try:
            log = logging.getLogger(__name__)
            log.info("Admin analysis progress: adaptation_strategies=%d, success_probability=%.2f",
                     len(analysis_result.get('adaptation_strategies', {})), analysis_result.get('success_probability', 0.0))
        except Exception:
            pass
        
        # Save comprehensive profile
        self._save_comprehensive_profile(analysis_result)
        
        return analysis_result
    
    def _assess_system_capabilities(self) -> SystemCapability:
        """Assess system capabilities for admin operations"""
        logging.info("[ANALYSIS] Assessing system capabilities...")
        
        capabilities = {
            'admin_access': False,
            'uac_level': 'unknown',
            'defender_status': 'unknown',
            'firewall_status': 'unknown',
            'network_access': False,
            'installation_permissions': False,
            'registry_access': False,
            'service_management': False,
            'overall_capability': 0.0
        }
        
        try:
            # Check administrator access
            try:
                result = subprocess.run(['net', 'session'], capture_output=True, text=True, timeout=5)
                capabilities['admin_access'] = result.returncode == 0
            except Exception as e:
                capabilities['admin_access'] = False
                _adp_logger.debug(f"Admin check unavailable: {e}")
            
            # Check UAC level
            try:
                result = subprocess.run(['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 
                                        '/v', 'EnableLUA'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if '0x1' in result.stdout:
                        capabilities['uac_level'] = 'enabled'
                    else:
                        capabilities['uac_level'] = 'disabled'
                else:
                    capabilities['uac_level'] = 'enabled'  # Default assumption
            except Exception:
                capabilities['uac_level'] = 'enabled'
            
            # Check Windows Defender status
            try:
                result = subprocess.run(['sc', 'query', 'WinDefend'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if 'RUNNING' in result.stdout:
                        capabilities['defender_status'] = 'active'
                    else:
                        capabilities['defender_status'] = 'stopped'
                else:
                    capabilities['defender_status'] = 'not_found'
            except Exception:
                capabilities['defender_status'] = 'unknown'
            
            # Check Firewall status
            try:
                result = subprocess.run(['sc', 'query', 'MpsSvc'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if 'RUNNING' in result.stdout:
                        capabilities['firewall_status'] = 'active'
                    else:
                        capabilities['firewall_status'] = 'stopped'
                else:
                    capabilities['firewall_status'] = 'not_found'
            except Exception:
                capabilities['firewall_status'] = 'unknown'
            
            # Check network access
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                capabilities['network_access'] = True
            except Exception:
                capabilities['network_access'] = False
            
            # Check installation permissions
            try:
                test_file = os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'admin_test.tmp')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                capabilities['installation_permissions'] = True
            except Exception:
                capabilities['installation_permissions'] = False
            
            # Check registry access
            try:
                result = subprocess.run(['reg', 'query', 'HKLM\\SOFTWARE'], capture_output=True, text=True, timeout=5)
                capabilities['registry_access'] = result.returncode == 0
            except Exception:
                capabilities['registry_access'] = False
            
            # Check service management
            try:
                result = subprocess.run(['sc', 'query', 'type=driver'], capture_output=True, text=True, timeout=5)
                capabilities['service_management'] = result.returncode == 0
            except Exception:
                capabilities['service_management'] = False
            
            # Calculate overall capability score
            score = 0
            if capabilities['admin_access']:
                score += 30
            if capabilities['installation_permissions']:
                score += 20
            if capabilities['registry_access']:
                score += 15
            if capabilities['service_management']:
                score += 15
            if capabilities['network_access']:
                score += 10
            if capabilities['uac_level'] == 'disabled':
                score += 10
            
            capabilities['overall_capability'] = min(score, 100)
            
            except Exception as e:
                logging.getLogger(__name__).warning(f"Capability assessment error: {e}")
        
        return SystemCapability(**capabilities)
    
    def _profile_hardware_comprehensive(self) -> HardwareProfile:
        """Comprehensive hardware profiling"""
        logging.info("[ANALYSIS] Profiling hardware capabilities...")
        
        profile = {
            'cpu_architecture': platform.machine(),
            'cpu_features': [],
            'memory_config': {},
            'storage_hierarchy': [],
            'graphics_capabilities': {},
            'network_interfaces': [],
            'peripheral_devices': [],
            'thermal_capabilities': {},
            'power_management': {}
        }
        
        try:
            # CPU analysis
            cpu_info = self._analyze_cpu_advanced()
            profile['cpu_features'] = cpu_info['features']
            
            # Memory analysis
            memory_info = self._analyze_memory_advanced()
            profile['memory_config'] = memory_info
            
            # Storage analysis
            storage_info = self._analyze_storage_advanced()
            profile['storage_hierarchy'] = storage_info
            
            # Graphics analysis
            graphics_info = self._analyze_graphics_advanced()
            profile['graphics_capabilities'] = graphics_info
            
            # Network analysis
            network_info = self._analyze_network_advanced()
            profile['network_interfaces'] = network_info
            
            # Peripheral analysis
            peripheral_info = self._analyze_peripherals_advanced()
            profile['peripheral_devices'] = peripheral_info
            
            # Thermal analysis
            thermal_info = self._analyze_thermal_capabilities()
            profile['thermal_capabilities'] = thermal_info
            
            # Power management analysis
            power_info = self._analyze_power_management()
            profile['power_management'] = power_info
            
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Hardware profiling error: {e}")
        
        return HardwareProfile(**profile)
    
    def _analyze_cpu_advanced(self) -> Dict[str, Any]:
        """Advanced CPU analysis"""
        cpu_info = {
            'name': 'Unknown',
            'features': [],
            'architecture': platform.machine(),
            'cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'max_frequency': 0.0,
            'cache_sizes': {},
            'instruction_sets': []
        }
        
        try:
            # Get CPU frequency
            freq = psutil.cpu_freq()
            if freq:
                cpu_info['max_frequency'] = freq.max
            
            # Get CPU name and features (Windows)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'cpu', 'get', 'name', 'description', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data and len(data) > 0:
                            cpu_info['name'] = data[0].get('Name', 'Unknown')
                            description = data[0].get('Description', '')
                            
                            # Extract features from description
                            if '64-bit' in description:
                                cpu_info['features'].append('x64')
                            if 'MMX' in description:
                                cpu_info['features'].append('MMX')
                            if 'SSE' in description:
                                cpu_info['features'].append('SSE')
                            if 'SSE2' in description:
                                cpu_info['features'].append('SSE2')
                            if 'AVX' in description:
                                cpu_info['features'].append('AVX')
                            if 'AVX2' in description:
                                cpu_info['features'].append('AVX2')
                except Exception:
                    pass
            
            # Determine performance class
            name_lower = cpu_info['name'].lower()
            if any(brand in name_lower for brand in ['intel i9', 'amd ryzen 9', 'threadripper']):
                cpu_info['features'].append('enthusiast_grade')
            elif any(brand in name_lower for brand in ['intel i7', 'amd ryzen 7']):
                cpu_info['features'].append('high_performance')
            elif any(brand in name_lower for brand in ['intel i5', 'amd ryzen 5']):
                cpu_info['features'].append('mainstream_performance')
            else:
                cpu_info['features'].append('standard_performance')
                
        except Exception as e:
            print(f"            [WARNING] CPU analysis error: {e}")
        
        return cpu_info
    
    def _analyze_memory_advanced(self) -> Dict[str, Any]:
        """Advanced memory analysis"""
        memory_info = {
            'total_gb': 0,
            'available_gb': 0,
            'speed_mhz': 0,
            'type': 'Unknown',
            'channels': 0,
            'form_factor': 'Unknown',
            'performance_tier': 'unknown'
        }
        
        try:
            virtual_memory = psutil.virtual_memory()
            memory_info['total_gb'] = virtual_memory.total // (1024**3)
            memory_info['available_gb'] = virtual_memory.available // (1024**3)
            
            # Try to get detailed memory info (Windows)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'memorychip', 'get', 'capacity,speed,devicelocator,formfactor', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data:
                            capacities = []
                            speeds = []
                            form_factors = []
                            
                            for chip in data:
                                if chip.get('Capacity'):
                                    capacities.append(int(chip['Capacity']) // (1024**3))
                                if chip.get('Speed'):
                                    speeds.append(int(chip['Speed']))
                                if chip.get('FormFactor'):
                                    form_factors.append(chip['FormFactor'])
                            
                            if speeds:
                                memory_info['speed_mhz'] = max(speeds)
                            if form_factors:
                                memory_info['form_factor'] = form_factors[0]
                            memory_info['channels'] = len(set(capacities))
                except Exception:
                    pass
            
            # Performance tier
            total_gb = memory_info['total_gb']
            if total_gb >= 64:
                memory_info['performance_tier'] = 'enthusiast'
            elif total_gb >= 32:
                memory_info['performance_tier'] = 'high_performance'
            elif total_gb >= 16:
                memory_info['performance_tier'] = 'performance'
            elif total_gb >= 8:
                memory_info['performance_tier'] = 'mainstream'
            else:
                memory_info['performance_tier'] = 'budget'
                
        except Exception as e:
            print(f"            [WARNING] Memory analysis error: {e}")
        
        return memory_info
    
    def _analyze_storage_advanced(self) -> List[Dict[str, Any]]:
        """Advanced storage analysis"""
        storage_devices = []
        
        try:
            disk_partitions = psutil.disk_partitions()
            
            for partition in disk_partitions:
                try:
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    
                    device_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total_gb': disk_usage.total // (1024**3),
                        'free_gb': disk_usage.free // (1024**3),
                        'used_gb': disk_usage.used // (1024**3),
                        'drive_type': 'unknown',
                        'interface': 'unknown',
                        'rpm': 0,
                        'cache_size_mb': 0
                    }
                    
                    # Get detailed drive info (Windows)
                    if platform.system() == 'Windows':
                        try:
                            # Get disk drive info
                            drive_letter = partition.device[:2]
                            result = subprocess.run(['wmic', 'diskdrive', 'where', f'Size={disk_usage.total}', 
                                                  'get', 'model,interface,type,mediatype', '/format:json'], 
                                                  capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                import json
                                data = json.loads(result.stdout)
                                if data and len(data) > 0:
                                    drive = data[0]
                                    model = drive.get('Model', '').lower()
                                    interface = drive.get('Interface', '').lower()
                                    media_type = drive.get('MediaType', '').lower()
                                    
                                    device_info['interface'] = interface
                                    
                                    # Determine drive type
                                    if 'ssd' in model or 'solid state' in model:
                                        device_info['drive_type'] = 'ssd'
                                    elif 'hdd' in model or 'hard disk' in model:
                                        device_info['drive_type'] = 'hdd'
                                    elif 'nvme' in model or 'pcie' in model:
                                        device_info['drive_type'] = 'nvme'
                                    elif media_type == 'fixed hard disk media':
                                        device_info['drive_type'] = 'hdd'
                                    elif 'ssd' in media_type.lower() or 'solid' in media_type.lower():
                                        device_info['drive_type'] = 'ssd'
                                    
                                    # Extract RPM for HDDs
                                    if 'rpm' in model:
                                        import re
                                        rpm_match = re.search(r'(\d+)\s*rpm', model)
                                        if rpm_match:
                                            device_info['rpm'] = int(rpm_match.group(1))
                        except Exception:
                            pass
                    
                    storage_devices.append(device_info)
                    
                except Exception as e:
                    print(f"                [WARNING] Storage analysis error for {partition.device}: {e}")
                    
        except Exception as e:
            print(f"        [WARNING] Storage analysis error: {e}")
        
        return storage_devices
    
    def _analyze_graphics_advanced(self) -> Dict[str, Any]:
        """Advanced graphics analysis"""
        graphics_info = {
            'gpus': [],
            'primary_gpu': 'unknown',
            'gpu_memory_mb': 0,
            'directx_version': 'unknown',
            'opengl_version': 'unknown',
            'vulkan_support': False,
            'cuda_support': False,
            'opencl_support': False,
            'ray_tracing_support': False,
            'gaming_capability': 'unknown'
        }
        
        try:
            # Get GPU information (Windows)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'path', 'win32_VideoController', 
                                          'get', 'name,adapterram,driverversion,driverdate', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data:
                            for gpu in data:
                                gpu_info = {
                                    'name': gpu.get('Name', 'Unknown'),
                                    'memory_mb': 0,
                                    'driver_version': gpu.get('DriverVersion', 'Unknown'),
                                    'driver_date': gpu.get('DriverDate', 'Unknown'),
                                    'type': 'unknown',
                                    'capabilities': []
                                }
                                
                                # Parse GPU memory
                                adapter_ram = gpu.get('AdapterRAM')
                                if adapter_ram and adapter_ram.isdigit():
                                    gpu_info['memory_mb'] = int(adapter_ram) // (1024**2)
                                
                                # Determine GPU type and capabilities
                                name = gpu_info['name'].lower()
                                if any(brand in name for brand in ['nvidia', 'geforce', 'quadro', 'tesla', 'rtx']):
                                    gpu_info['type'] = 'nvidia'
                                    gpu_info['capabilities'].append('cuda')
                                    graphics_info['cuda_support'] = True
                                    if 'rtx' in name:
                                        gpu_info['capabilities'].append('ray_tracing')
                                        graphics_info['ray_tracing_support'] = True
                                elif any(brand in name for brand in ['amd', 'radeon', 'radeon pro']):
                                    gpu_info['type'] = 'amd'
                                    gpu_info['capabilities'].append('opencl')
                                    graphics_info['opencl_support'] = True
                                elif any(brand in name for brand in ['intel', 'iris', 'uhd', 'hd graphics']):
                                    gpu_info['type'] = 'integrated'
                                    gpu_info['capabilities'].append('integrated')
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
            if graphics_info['gpu_memory_mb'] >= 8192:
                graphics_info['gaming_capability'] = 'enthusiast'
            elif graphics_info['gpu_memory_mb'] >= 4096:
                graphics_info['gaming_capability'] = 'high_end'
            elif graphics_info['gpu_memory_mb'] >= 2048:
                graphics_info['gaming_capability'] = 'gaming'
            elif graphics_info['gpu_memory_mb'] >= 1024:
                graphics_info['gaming_capability'] = 'light_gaming'
            else:
                graphics_info['gaming_capability'] = 'integrated'
                
        except Exception as e:
            print(f"        [WARNING] Graphics analysis error: {e}")
        
        return graphics_info
    
    def _analyze_network_advanced(self) -> List[Dict[str, Any]]:
        """Advanced network analysis"""
        network_interfaces = []
        
        try:
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, addresses in net_if_addrs.items():
                interface_info = {
                    'name': interface_name,
                    'addresses': [],
                    'is_up': False,
                    'speed_mbps': 0,
                    'mtu': 0,
                    'type': 'unknown',
                    'mac_address': '',
                    'ipv4_addresses': [],
                    'ipv6_addresses': []
                }
                
                # Get interface stats
                if interface_name in net_if_stats:
                    stats = net_if_stats[interface_name]
                    interface_info['is_up'] = stats.isup
                    interface_info['speed_mbps'] = stats.speed
                    interface_info['mtu'] = stats.mtu
                
                # Process addresses
                for addr in addresses:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_info['addresses'].append(addr_info)
                    
                    # Extract MAC address
                    if addr.family.name == 'AF_LINK':
                        interface_info['mac_address'] = addr.address
                    # Extract IP addresses
                    elif addr.family.name == 'AF_INET':
                        interface_info['ipv4_addresses'].append(addr.address)
                    elif addr.family.name == 'AF_INET6':
                        interface_info['ipv6_addresses'].append(addr.address)
                
                # Determine interface type
                name_lower = interface_name.lower()
                if any(keyword in name_lower for keyword in ['wi-fi', 'wifi', 'wlan', 'wireless']):
                    interface_info['type'] = 'wifi'
                elif any(keyword in name_lower for keyword in ['ethernet', 'lan', 'local', 'wired']):
                    interface_info['type'] = 'ethernet'
                elif any(keyword in name_lower for keyword in ['bluetooth', 'bt']):
                    interface_info['type'] = 'bluetooth'
                elif 'loopback' in name_lower:
                    interface_info['type'] = 'loopback'
                else:
                    interface_info['type'] = 'unknown'
                
                network_interfaces.append(interface_info)
                
        except Exception as e:
            print(f"        [WARNING] Network analysis error: {e}")
        
        return network_interfaces
    
    def _analyze_peripherals_advanced(self) -> List[Dict[str, Any]]:
        """Advanced peripheral analysis"""
        peripherals = []
        
        try:
            # Monitor analysis (Windows)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['wmic', 'desktopmonitor', 'get', 'screenheight,screenwidth,monitormanufacturer', '/format:json'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        if data:
                            for monitor in data:
                                monitor_info = {
                                    'type': 'monitor',
                                    'width': monitor.get('ScreenWidth', 0),
                                    'height': monitor.get('ScreenHeight', 0),
                                    'manufacturer': monitor.get('MonitorManufacturer', 'Unknown'),
                                    'resolution': f"{monitor.get('ScreenWidth', 0)}x{monitor.get('ScreenHeight', 0)}",
                                    'refresh_rate': 60  # Default assumption
                                }
                                peripherals.append(monitor_info)
                except Exception as e:
                    print(f"                [WARNING] Monitor analysis error: {e}")
            
            # Keyboard analysis
            try:
                result = subprocess.run(['wmic', 'path', 'win32_keyboard', 'get', 'name,description', '/format:json'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout)
                    if data:
                        for keyboard in data:
                            keyboard_info = {
                                'type': 'keyboard',
                                'name': keyboard.get('Name', 'Unknown'),
                                'description': keyboard.get('Description', 'Unknown'),
                                'layout': 'unknown'
                            }
                            peripherals.append(keyboard_info)
            except Exception as e:
                print(f"                [WARNING] Keyboard analysis error: {e}")
            
            # Mouse analysis
            try:
                result = subprocess.run(['wmic', 'path', 'win32_pointingdevice', 'get', 'name,description,hardwaretype', '/format:json'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout)
                    if data:
                        for mouse in data:
                            mouse_info = {
                                'type': 'pointing_device',
                                'name': mouse.get('Name', 'Unknown'),
                                'description': mouse.get('Description', 'Unknown'),
                                'hardware_type': mouse.get('HardwareType', 'Unknown')
                            }
                            peripherals.append(mouse_info)
            except Exception as e:
                print(f"                [WARNING] Mouse analysis error: {e}")
            
            # Printer analysis
            try:
                result = subprocess.run(['wmic', 'printer', 'get', 'name,drivername,local', '/format:json'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout)
                    if data:
                        for printer in data:
                            printer_info = {
                                'type': 'printer',
                                'name': printer.get('Name', 'Unknown'),
                                'driver': printer.get('DriverName', 'Unknown'),
                                'local': printer.get('Local', 'Unknown')
                            }
                            peripherals.append(printer_info)
            except Exception as e:
                print(f"                [WARNING] Printer analysis error: {e}")
                
        except Exception as e:
            print(f"        [WARNING] Peripheral analysis error: {e}")
        
        return peripherals
    
    def _analyze_thermal_capabilities(self) -> Dict[str, Any]:
        """Analyze thermal management capabilities"""
        thermal_info = {
            'temperature_sensors': [],
            'fan_sensors': [],
            'thermal_throttling': False,
            'cooling_system': 'unknown',
            'thermal_management': 'unknown'
        }
        
        try:
            import psutil
            
            # Check for temperature sensors
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
                        thermal_info['temperature_sensors'].append(sensor_info)
            
            # Check for battery (indicates laptop with thermal management)
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    thermal_info['thermal_management'] = 'laptop_thermal'
                    thermal_info['thermal_throttling'] = True
                else:
                    thermal_info['thermal_management'] = 'desktop_cooling'
            
            # Detect cooling system based on device type
            if thermal_info['temperature_sensors']:
                thermal_info['cooling_system'] = 'active_cooling'
            else:
                thermal_info['cooling_system'] = 'passive_cooling'
                
        except ImportError:
            pass
        except Exception as e:
            print(f"        [WARNING] Thermal analysis error: {e}")
        
        return thermal_info
    
    def _analyze_power_management(self) -> Dict[str, Any]:
        """Analyze power management capabilities"""
        power_info = {
            'battery_present': False,
            'battery_info': {},
            'power_plans': [],
            'sleep_states': [],
            'hibernate_available': False,
            'power_management_type': 'unknown'
        }
        
        try:
            import psutil
            
            # Check for battery
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    power_info['battery_present'] = True
                    power_info['battery_info'] = {
                        'percent': battery.percent,
                        'plugged_in': battery.power_plugged,
                        'seconds_left': battery.secsleft if not battery.power_plugged else None
                    }
                    power_info['power_management_type'] = 'mobile_power'
                else:
                    power_info['power_management_type'] = 'desktop_power'
            
            # Check power plans (Windows)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['powercfg', '/list'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if '*' in line:  # Active power plan
                                plan_name = line.split('*')[1].strip()
                                power_info['power_plans'].append({
                                    'name': plan_name,
                                    'active': True
                                })
                except Exception:
                    pass
            
            # Check hibernation availability
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(['powercfg', '/availablesleepstates'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        if 'hibernate' in result.stdout.lower():
                            power_info['hibernate_available'] = True
                except Exception:
                    pass
                    
        except ImportError:
            pass
        except Exception as e:
            print(f"        [WARNING] Power management analysis error: {e}")
        
        return power_info
    
    def _analyze_security_context(self) -> SecurityContext:
        """Analyze security and privilege context"""
        print("    [SEARCH] Analyzing security context...")
        
        context = {
            'user_account': {},
            'group_memberships': [],
            'privilege_tokens': [],
            'security_policies': {},
            'defender_configuration': {},
            'firewall_rules': {},
            'uac_settings': {},
            'applocker_policies': {}
        }
        
        try:
            # User account analysis
            username = os.environ.get('USERNAME', 'unknown')
            domain = os.environ.get('USERDOMAIN', 'unknown')
            context['user_account'] = {
                'username': username,
                'domain': domain,
                'sid': self._get_user_sid(),
                'profile_path': os.environ.get('USERPROFILE', ''),
                'account_type': self._determine_account_type()
            }
            
            # Group memberships
            context['group_memberships'] = self._get_group_memberships()
            
            # Privilege tokens
            context['privilege_tokens'] = self._get_privilege_tokens()
            
            # Security policies
            context['security_policies'] = self._analyze_security_policies()
            
            # Windows Defender configuration
            context['defender_configuration'] = self._analyze_defender_configuration()
            
            # Firewall rules
            context['firewall_rules'] = self._analyze_firewall_rules()
            
            # UAC settings
            context['uac_settings'] = self._analyze_uac_settings()
            
            # AppLocker policies
            context['applocker_policies'] = self._analyze_applocker_policies()
            
        except Exception as e:
            print(f"        [WARNING] Security context analysis error: {e}")
        
        return SecurityContext(**context)
    
    def _get_user_sid(self) -> str:
        """Get user SID"""
        try:
            result = subprocess.run(['whoami', '/user'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'S-' in line:
                        return line.strip()
        except Exception:
            pass
        return 'unknown'
    
    def _determine_account_type(self) -> str:
        """Determine account type"""
        try:
            result = subprocess.run(['net', 'user', os.environ.get('USERNAME', '')], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'administrator' in output:
                    return 'administrator'
                elif 'standard' in output:
                    return 'standard'
                elif 'guest' in output:
                    return 'guest'
        except Exception:
            pass
        return 'unknown'
    
    def _get_group_memberships(self) -> List[str]:
        """Get user group memberships"""
        groups = []
        try:
            result = subprocess.run(['whoami', '/groups'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '\\' in line:
                        group_name = line.split('\\')[-1].strip()
                        if group_name and group_name != 'None':
                            groups.append(group_name)
        except Exception:
            pass
        return groups
    
    def _get_privilege_tokens(self) -> List[str]:
        """Get privilege tokens"""
        tokens = []
        try:
            result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Enabled' in line:
                        privilege = line.split(' ')[0].strip()
                        if privilege:
                            tokens.append(privilege)
        except Exception:
            pass
        return tokens
    
    def _analyze_security_policies(self) -> Dict[str, Any]:
        """Analyze security policies"""
        policies = {}
        try:
            # Check local security policies
            result = subprocess.run(['secedit', '/export', '/cfg', 'secpolicy.inf'], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                policies['secpolicy_available'] = True
            else:
                policies['secpolicy_available'] = False
        except Exception:
            policies['secpolicy_available'] = False
        
        return policies
    
    def _analyze_defender_configuration(self) -> Dict[str, Any]:
        """Analyze Windows Defender configuration"""
        defender_config = {}
        try:
            # Check Defender status
            result = subprocess.run(['sc', 'query', 'WinDefend'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                defender_config['status'] = 'running' if 'RUNNING' in result.stdout else 'stopped'
            else:
                defender_config['status'] = 'not_found'
            
            # Check Defender settings
            try:
                result = subprocess.run(['powershell', '-Command', 'Get-MpPreference'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    defender_config['config_accessible'] = True
                else:
                    defender_config['config_accessible'] = False
            except Exception:
                defender_config['config_accessible'] = False
                
        except Exception as e:
            defender_config['status'] = 'error'
        
        return defender_config
    
    def _analyze_firewall_rules(self) -> Dict[str, Any]:
        """Analyze firewall rules"""
        firewall_rules = {}
        try:
            # Check firewall status
            result = subprocess.run(['sc', 'query', 'MpsSvc'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                firewall_rules['status'] = 'running' if 'RUNNING' in result.stdout else 'stopped'
            else:
                firewall_rules['status'] = 'not_found'
            
            # Check firewall rules
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    firewall_rules['rules_accessible'] = True
                else:
                    firewall_rules['rules_accessible'] = False
            except Exception:
                firewall_rules['rules_accessible'] = False
                
        except Exception as e:
            firewall_rules['status'] = 'error'
        
        return firewall_rules
    
    def _analyze_uac_settings(self) -> Dict[str, Any]:
        """Analyze UAC settings"""
        uac_settings = {}
        try:
            # Check UAC registry setting
            result = subprocess.run(['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 
                                  '/v', 'EnableLUA'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                if '0x1' in result.stdout:
                    uac_settings['enabled'] = True
                else:
                    uac_settings['enabled'] = False
            else:
                uac_settings['enabled'] = True  # Default assumption
            
            # Check UAC level
            try:
                result = subprocess.run(['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 
                                      '/v', 'ConsentPromptBehaviorAdmin'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    uac_settings['level'] = 'configured'
                else:
                    uac_settings['level'] = 'default'
            except Exception:
                uac_settings['level'] = 'default'
                
        except Exception as e:
            uac_settings['enabled'] = 'unknown'
        
        return uac_settings
    
    def _analyze_applocker_policies(self) -> Dict[str, Any]:
        """Analyze AppLocker policies"""
        applocker_policies = {}
        try:
            # Check if AppLocker is configured
            result = subprocess.run(['reg', 'query', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\AppLocker'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                applocker_policies['configured'] = True
            else:
                applocker_policies['configured'] = False
        except Exception:
            applocker_policies['configured'] = False
        
        return applocker_policies
    
    def _analyze_network_capabilities(self) -> Dict[str, Any]:
        """Analyze network capabilities for bypass operations"""
        network_analysis = {
            'internet_access': False,
            'dns_resolution': False,
            'proxy_detection': {},
            'firewall_bypass_potential': 'unknown',
            'network_adapters': [],
            'connectivity_test': {}
        }
        
        try:
            # Test internet connectivity
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                network_analysis['internet_access'] = True
            except Exception:
                network_analysis['internet_access'] = False
            
            # Test DNS resolution
            try:
                socket.gethostbyname('google.com')
                network_analysis['dns_resolution'] = True
            except Exception:
                network_analysis['dns_resolution'] = False
            
            # Get network adapters
            network_analysis['network_adapters'] = self._analyze_network_advanced()
            
            # Check for proxy
            try:
                proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'NO_PROXY']
                proxy_config = {}
                for var in proxy_vars:
                    if var in os.environ:
                        proxy_config[var] = os.environ[var]
                network_analysis['proxy_detection'] = proxy_config
            except Exception:
                pass
            
            # Assess firewall bypass potential
            if network_analysis['internet_access'] and network_analysis['dns_resolution']:
                network_analysis['firewall_bypass_potential'] = 'high'
            elif network_analysis['internet_access']:
                network_analysis['firewall_bypass_potential'] = 'medium'
            else:
                network_analysis['firewall_bypass_potential'] = 'low'
                
        except Exception as e:
            print(f"        [WARNING] Network analysis error: {e}")
        
        return network_analysis
    
    def _analyze_installation_capabilities(self) -> Dict[str, Any]:
        """Analyze installation and deployment capabilities"""
        installation_analysis = {
            'temp_directory_access': False,
            'program_files_access': False,
            'system32_access': False,
            'registry_write_access': False,
            'service_creation': False,
            'task_scheduling': False,
            'driver_installation': False,
            'overall_install_capability': 0.0
        }
        
        try:
            # Test temp directory access
            try:
                temp_file = os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'install_test.tmp')
                with open(temp_file, 'w') as f:
                    f.write('test')
                os.remove(temp_file)
                installation_analysis['temp_directory_access'] = True
            except Exception:
                installation_analysis['temp_directory_access'] = False
            
            # Test Program Files access
            try:
                prog_files = os.environ.get('ProgramFiles', 'C:\\Program Files')
                test_file = os.path.join(prog_files, 'install_test.tmp')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                installation_analysis['program_files_access'] = True
            except Exception:
                installation_analysis['program_files_access'] = False
            
            # Test System32 access
            try:
                system32 = os.environ.get('SystemRoot', 'C:\\Windows') + '\\System32'
                test_file = os.path.join(system32, 'install_test.tmp')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                installation_analysis['system32_access'] = True
            except Exception:
                installation_analysis['system32_access'] = False
            
            # Test registry write access
            try:
                result = subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\DownpourTest', '/v', 'Test', '/t', 'REG_SZ', '/d', 'test', '/f'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    installation_analysis['registry_write_access'] = True
                    # Clean up
                    subprocess.run(['reg', 'delete', 'HKLM\\SOFTWARE\\DownpourTest', '/f'], capture_output=True, text=True, timeout=5)
                else:
                    installation_analysis['registry_write_access'] = False
            except Exception:
                installation_analysis['registry_write_access'] = False
            
            # Test service creation
            try:
                result = subprocess.run(['sc', 'create', 'DownpourTest', 'binPath= "cmd.exe /c echo test"'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    installation_analysis['service_creation'] = True
                    # Clean up
                    subprocess.run(['sc', 'delete', 'DownpourTest', 'f'], capture_output=True, text=True, timeout=5)
                else:
                    installation_analysis['service_creation'] = False
            except Exception:
                installation_analysis['service_creation'] = False
            
            # Test task scheduling
            try:
                result = subprocess.run(['schtasks', '/create', '/tn', 'DownpourTest', '/tr', 'echo test', '/f'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    installation_analysis['task_scheduling'] = True
                    # Clean up
                    subprocess.run(['schtasks', '/delete', '/tn', 'DownpourTest', '/f'], capture_output=True, text=True, timeout=5)
                else:
                    installation_analysis['task_scheduling'] = False
            except Exception:
                installation_analysis['task_scheduling'] = False
            
            # Test driver installation (simplified check)
            try:
                # Check if we can access driver-related registry keys
                result = subprocess.run(['reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services'], 
                                      capture_output=True, text=True, timeout=10)
                installation_analysis['driver_installation'] = result.returncode == 0
            except Exception:
                installation_analysis['driver_installation'] = False
            
            # Calculate overall installation capability
            score = 0
            if installation_analysis['temp_directory_access']:
                score += 15
            if installation_analysis['program_files_access']:
                score += 25
            if installation_analysis['system32_access']:
                score += 20
            if installation_analysis['registry_write_access']:
                score += 20
            if installation_analysis['service_creation']:
                score += 10
            if installation_analysis['task_scheduling']:
                score += 5
            if installation_analysis['driver_installation']:
                score += 5
            
            installation_analysis['overall_install_capability'] = min(score, 100)
            
        except Exception as e:
            print(f"        [WARNING] Installation analysis error: {e}")
        
        return installation_analysis
    
    def _analyze_bypass_capabilities(self) -> Dict[str, Any]:
        """Analyze security bypass capabilities"""
        bypass_analysis = {
            'defender_bypass_methods': [],
            'firewall_bypass_methods': [],
            'uac_bypass_methods': [],
            'registry_bypass_methods': [],
            'service_bypass_methods': [],
            'overall_bypass_capability': 0.0,
            'recommended_bypass_strategy': 'unknown'
        }
        
        try:
            # Analyze Defender bypass capabilities
            defender_status = self.system_capability.defender_status
            if defender_status == 'active':
                bypass_analysis['defender_bypass_methods'] = [
                    'powershell_exclusions',
                    'registry_modifications',
                    'group_policy_changes',
                    'service_configuration',
                    'memory_injection'
                ]
            elif defender_status == 'stopped':
                bypass_analysis['defender_bypass_methods'] = ['direct_execution']
            
            # Analyze firewall bypass capabilities
            firewall_status = self.system_capability.firewall_status
            if firewall_status == 'active':
                bypass_analysis['firewall_bypass_methods'] = [
                    'rule_modification',
                    'service_stop',
                    'port_whitelisting',
                    'program_exclusions'
                ]
            elif firewall_status == 'stopped':
                bypass_analysis['firewall_bypass_methods'] = ['direct_access']
            
            # Analyze UAC bypass capabilities
            uac_level = self.system_capability.uac_level
            if uac_level == 'disabled':
                bypass_analysis['uac_bypass_methods'] = ['direct_execution']
            else:
                bypass_analysis['uac_bypass_methods'] = [
                    'code_injection',
                    'token_manipulation',
                    'service_impersonation',
                    'registry_exploits'
                ]
            
            # Analyze registry bypass capabilities
            if self.system_capability.registry_access:
                bypass_analysis['registry_bypass_methods'] = [
                    'direct_modification',
                    'policy_override',
                    'key_deletion',
                    'value_manipulation'
                ]
            
            # Analyze service bypass capabilities
            if self.system_capability.service_management:
                bypass_analysis['service_bypass_methods'] = [
                    'service_stop',
                    'service_disable',
                    'service_modification',
                    'service_replacement'
                ]
            
            # Calculate overall bypass capability
            total_methods = (len(bypass_analysis['defender_bypass_methods']) +
                            len(bypass_analysis['firewall_bypass_methods']) +
                            len(bypass_analysis['uac_bypass_methods']) +
                            len(bypass_analysis['registry_bypass_methods']) +
                            len(bypass_analysis['service_bypass_methods']))
            
            bypass_analysis['overall_bypass_capability'] = min(total_methods * 4, 100)
            
            # Determine recommended bypass strategy
            if bypass_analysis['overall_bypass_capability'] >= 80:
                bypass_analysis['recommended_bypass_strategy'] = 'comprehensive'
            elif bypass_analysis['overall_bypass_capability'] >= 60:
                bypass_analysis['recommended_bypass_strategy'] = 'multi_method'
            elif bypass_analysis['overall_bypass_capability'] >= 40:
                bypass_analysis['recommended_bypass_strategy'] = 'targeted'
            else:
                bypass_analysis['recommended_bypass_strategy'] = 'minimal'
                
        except Exception as e:
            print(f"        [WARNING] Bypass analysis error: {e}")
        
        return bypass_analysis
    
    def _generate_adaptation_strategies(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate sophisticated adaptation strategies"""
        print("    [*] Generating adaptation strategies...")
        
        strategies = {
            'installation_strategy': {},
            'bypass_strategy': {},
            'security_strategy': {},
            'performance_strategy': {},
            'fallback_strategy': {},
            'optimization_priority': []
        }
        
        try:
            system_cap = analysis_result['system_capability']
            hardware = analysis_result['hardware_profile']
            security = analysis_result['security_context']
            network = analysis_result['network_analysis']
            installation = analysis_result['installation_analysis']
            bypass = analysis_result['bypass_analysis']
            
            # Installation strategy
            if installation['overall_install_capability'] >= 80:
                strategies['installation_strategy'] = {
                    'method': 'full_system_installation',
                    'target_locations': ['ProgramFiles', 'System32', 'SystemRoot'],
                    'privilege_level': 'administrator',
                    'registry_integration': True,
                    'service_creation': True,
                    'task_scheduling': True
                }
            elif installation['overall_install_capability'] >= 60:
                strategies['installation_strategy'] = {
                    'method': 'user_space_installation',
                    'target_locations': ['AppData', 'Temp', 'UserProfile'],
                    'privilege_level': 'user',
                    'registry_integration': True,
                    'service_creation': False,
                    'task_scheduling': True
                }
            else:
                strategies['installation_strategy'] = {
                    'method': 'portable_installation',
                    'target_locations': ['CurrentDirectory'],
                    'privilege_level': 'current',
                    'registry_integration': False,
                    'service_creation': False,
                    'task_scheduling': False
                }
            
            # Bypass strategy
            bypass_strategy = bypass['recommended_bypass_strategy']
            if bypass_strategy == 'comprehensive':
                strategies['bypass_strategy'] = {
                    'primary_method': 'multi_vector_attack',
                    'defender_methods': bypass['defender_bypass_methods'],
                    'firewall_methods': bypass['firewall_bypass_methods'],
                    'uac_methods': bypass['uac_bypass_methods'],
                    'execution_order': ['defender', 'firewall', 'uac', 'registry', 'services']
                }
            elif bypass_strategy == 'multi_method':
                strategies['bypass_strategy'] = {
                    'primary_method': 'targeted_bypass',
                    'defender_methods': bypass['defender_bypass_methods'][:2],
                    'firewall_methods': bypass['firewall_bypass_methods'][:2],
                    'uac_methods': bypass['uac_bypass_methods'][:1],
                    'execution_order': ['defender', 'uac']
                }
            elif bypass_strategy == 'targeted':
                strategies['bypass_strategy'] = {
                    'primary_method': 'single_vector',
                    'defender_methods': bypass['defender_bypass_methods'][:1],
                    'firewall_methods': [],
                    'uac_methods': bypass['uac_bypass_methods'][:1],
                    'execution_order': ['defender']
                }
            else:
                strategies['bypass_strategy'] = {
                    'primary_method': 'minimal_bypass',
                    'defender_methods': [],
                    'firewall_methods': [],
                    'uac_methods': [],
                    'execution_order': []
                }
            
            # Security strategy
            if system_cap.admin_access and system_cap.registry_access:
                strategies['security_strategy'] = {
                    'privilege_escalation': 'automatic',
                    'token_manipulation': 'enabled',
                    'impersonation': 'enabled',
                    'policy_override': 'enabled'
                }
            else:
                strategies['security_strategy'] = {
                    'privilege_escalation': 'manual',
                    'token_manipulation': 'disabled',
                    'impersonation': 'disabled',
                    'policy_override': 'disabled'
                }
            
            # Performance strategy
            memory_gb = hardware.memory_config.get('total_gb', 0)
            gpu_memory = hardware.graphics_capabilities.get('gpu_memory_mb', 0)
            
            if memory_gb >= 16 and gpu_memory >= 4096:
                strategies['performance_strategy'] = {
                    'resource_allocation': 'maximum',
                    'parallel_operations': 'high',
                    'cache_size': 'large',
                    'monitoring_intensity': 'comprehensive'
                }
            elif memory_gb >= 8 and gpu_memory >= 2048:
                strategies['performance_strategy'] = {
                    'resource_allocation': 'balanced',
                    'parallel_operations': 'medium',
                    'cache_size': 'medium',
                    'monitoring_intensity': 'standard'
                }
            else:
                strategies['performance_strategy'] = {
                    'resource_allocation': 'conservative',
                    'parallel_operations': 'low',
                    'cache_size': 'small',
                    'monitoring_intensity': 'minimal'
                }
            
            # Fallback strategy
            strategies['fallback_strategy'] = {
                'primary_fallback': 'portable_mode',
                'secondary_fallback': 'minimal_mode',
                'tertiary_fallback': 'safe_mode',
                'final_fallback': 'diagnostic_mode'
            }
            
            # Optimization priority
            strategies['optimization_priority'] = [
                'security_bypass',
                'installation_completion',
                'system_integration',
                'performance_optimization',
                'user_experience'
            ]
            
        except Exception as e:
            print(f"        [WARNING] Strategy generation error: {e}")
        
        return strategies
    
    def _calculate_success_probability(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate probability of successful operation completion"""
        try:
            system_cap = analysis_result['system_capability']
            installation = analysis_result['installation_analysis']
            bypass = analysis_result['bypass_analysis']
            network = analysis_result['network_analysis']
            
            # Weight different factors
            weights = {
                'admin_access': 25,
                'installation_capability': 25,
                'bypass_capability': 20,
                'network_access': 15,
                'registry_access': 10,
                'service_management': 5
            }
            
            score = 0
            
            if system_cap.admin_access:
                score += weights['admin_access']
            
            score += (installation['overall_install_capability'] / 100) * weights['installation_capability']
            score += (bypass['overall_bypass_capability'] / 100) * weights['bypass_capability']
            
            if network['internet_access']:
                score += weights['network_access']
            
            if system_cap.registry_access:
                score += weights['registry_access']
            
            if system_cap.service_management:
                score += weights['service_management']
            
            return min(score, 100.0)
            
        except Exception as e:
            print(f"        [WARNING] Success probability calculation error: {e}")
            return 50.0  # Default to 50%
    
    def _save_comprehensive_profile(self, analysis_result: Dict[str, Any]):
        """Save comprehensive analysis profile"""
        try:
            profile_path = os.path.join(os.path.dirname(__file__), 'comprehensive_device_profile.json')
            with open(profile_path, 'w') as f:
                json.dump(analysis_result, f, indent=2, default=str)
            print(f"    [*] Comprehensive profile saved to {profile_path}")
        except Exception as e:
            print(f"    [WARNING] Could not save comprehensive profile: {e}")

# Usage example
if __name__ == "__main__":
    profiler = AdvancedDeviceProfiler()
    profile = profiler.comprehensive_admin_analysis()
    
    print("\n[*] COMPREHENSIVE ADMIN ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"System Capability: {profile['system_capability'].overall_capability:.1f}%")
    print(f"Success Probability: {profile['success_probability']:.1f}%")
    print(f"Installation Capability: {profile['installation_analysis']['overall_install_capability']:.1f}%")
    print(f"Bypass Capability: {profile['bypass_analysis']['overall_bypass_capability']:.1f}%")
    
    strategies = profile['adaptation_strategies']
    print(f"\n[*] ADAPTATION STRATEGIES:")
    print(f"Installation: {strategies['installation_strategy'].get('method', 'unknown')}")
    print(f"Bypass: {strategies['bypass_strategy'].get('primary_method', 'unknown')}")
    print(f"Security: {strategies['security_strategy'].get('privilege_escalation', 'unknown')}")
