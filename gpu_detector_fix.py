"""GPUDetector - defensive NVIDIA GPU monitoring helper.

Provides a single `GPUDetector` class whose `get_gpu_info()` returns a dict
with the schema consumed by `enhanced_security_dashboard.py`:

    {name, usage, memory_used, memory_total, memory_percent,
     temperature, fan_speed, power_draw, clock_speed, memory_clock,
     driver_version, available, gpu_count, multi_gpu}

Detection order (first that works wins):
  1. NVML via nvidia_ml_py (maintained) or pynvml (legacy) - most detailed.
  2. nvidia-smi CLI query (always present with NVIDIA drivers, works even
     when the NVML Python bindings are missing).
  3. GPUtil.
  4. WMI Win32_VideoController (basic name only).

Every path is wrapped so this module can NEVER crash its importer - callers
already guard with try/except ImportError, and runtime failures degrade to
`available: False` rather than raising.
"""

import subprocess
import sys


class GPUDetector:
    """Minimal GPU info provider with layered NVIDIA/fallback detection."""

    def __init__(self):
        self.logger = None
        self._nvml_handle = None
        self._nvml_api = None
        self._init_nvml()

    # -- internal -----------------------------------------------------------
    def _init_nvml(self):
        # Suppress the pynvml deprecation warning since nvidia-ml-py 13.x is pynvml
        import warnings
        warnings.filterwarnings('ignore', message='.*pynvml.*deprecated.*', category=FutureWarning)
        
        try:
            # nvidia-ml-py 13.x installs itself as pynvml - use pynvml directly
            import pynvml
            pynvml.nvmlInit()
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            self._nvml_api = {
                'name': 'pynvml', 'nvmlDeviceGetName': pynvml.nvmlDeviceGetName,
                'nvmlDeviceGetMemoryInfo': pynvml.nvmlDeviceGetMemoryInfo,
                'nvmlDeviceGetUtilizationRates': pynvml.nvmlDeviceGetUtilizationRates,
                'nvmlDeviceGetTemperature': pynvml.nvmlDeviceGetTemperature,
                'nvmlDeviceGetFanSpeed': pynvml.nvmlDeviceGetFanSpeed,
                'nvmlDeviceGetPowerUsage': pynvml.nvmlDeviceGetPowerUsage,
                'nvmlDeviceGetClockInfo': pynvml.nvmlDeviceGetClockInfo,
                'nvmlSystemGetDriverVersion': pynvml.nvmlSystemGetDriverVersion,
            }
            self._nvml_handle = handle
        except Exception:
            self._nvml_api = None
            self._nvml_handle = None

    def _default(self):
        return {
            'name': 'No GPU detected', 'usage': 0, 'memory_used': 0,
            'memory_total': 0, 'memory_percent': 0, 'temperature': 0,
            'fan_speed': 0, 'power_draw': 0, 'clock_speed': 0,
            'memory_clock': 0, 'driver_version': 'Unknown',
            'available': False, 'gpu_count': 0, 'multi_gpu': False,
        }

    def _from_nvml(self, info):
        a = self._nvml_api
        h = self._nvml_handle
        try:
            name = a['nvmlDeviceGetName'](h)
            info['name'] = (name.decode('utf-8', 'replace')
                            if isinstance(name, bytes) else name)
            info['available'] = True
            info['gpu_count'] = 1
        except Exception:
            pass
        try:
            util = a['nvmlDeviceGetUtilizationRates'](h)
            info['usage'] = util.gpu
        except Exception:
            pass
        try:
            mem = a['nvmlDeviceGetMemoryInfo'](h)
            info['memory_used'] = mem.used // (1024 ** 2)
            info['memory_total'] = mem.total // (1024 ** 2)
            if mem.total > 0:
                info['memory_percent'] = (mem.used / mem.total) * 100
        except Exception:
            pass
        try:
            info['temperature'] = a['nvmlDeviceGetTemperature'](
                h, 0)  # NVML_TEMPERATURE_GPU = 0
        except Exception:
            pass
        try:
            info['fan_speed'] = a['nvmlDeviceGetFanSpeed'](h)
        except Exception:
            pass
        try:
            info['power_draw'] = a['nvmlDeviceGetPowerUsage'](h) / 1000.0
        except Exception:
            pass
        try:
            info['clock_speed'] = a['nvmlDeviceGetClockInfo'](h, 0)
            info['memory_clock'] = a['nvmlDeviceGetClockInfo'](h, 1)
        except Exception:
            pass
        try:
            dv = a['nvmlSystemGetDriverVersion']()
            info['driver_version'] = (dv.decode('utf-8', 'replace')
                                      if isinstance(dv, bytes) else dv)
        except Exception:
            pass
        return info

    def _from_nvidia_smi(self, info):
        try:
            # Try to find nvidia-smi in common locations first
            import os
            nvidia_smi_candidates = [
                'nvidia-smi',
                r'C:\Windows\System32\nvidia-smi.exe',
                r'C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe',
                r'C:\Program Files\NVIDIA Corporation\NVIDIA Corporation\nvidia-smi.exe',
            ]
            
            nvidia_smi_path = None
            for candidate in nvidia_smi_candidates:
                if candidate == 'nvidia-smi' or os.path.isfile(candidate):
                    nvidia_smi_path = candidate
                    break
            
            if nvidia_smi_path is None:
                return info
                
            q = ['--query-gpu=name,utilization.gpu,memory.used,'
                 'memory.total,temperature.gpu',
                 '--format=csv,noheader,nounits']
            r = subprocess.run([nvidia_smi_path] + q,
                               capture_output=True, text=True, timeout=8,
                               creationflags=0x08000000)
            if r.returncode != 0 or not r.stdout.strip():
                return info
            parts = [x.strip() for x in r.stdout.splitlines()[0].split(',')]
            if len(parts) >= 5:
                def _num(v):
                    try:
                        # Handle [N/A] values and clean them
                        cleaned = v.replace('[N/A]', '').replace('N/A', '').strip()
                        return float(cleaned) if cleaned else 0.0
                    except Exception:
                        return 0.0
                info['name'] = parts[0]
                info['usage'] = _num(parts[1])
                info['memory_used'] = _num(parts[2])
                info['memory_total'] = _num(parts[3])
                if info['memory_total'] > 0:
                    info['memory_percent'] = (
                        info['memory_used'] / info['memory_total']) * 100
                info['temperature'] = _num(parts[4])
                info['available'] = True
                info['gpu_count'] = 1
            return info
        except FileNotFoundError:
            # nvidia-smi not found - this is expected on systems without NVIDIA
            return info
        except subprocess.TimeoutExpired:
            # nvidia-smi hung - degrade gracefully
            return info
        except Exception as e:
            # Log the error but don't crash
            if self.logger:
                self.logger.warning(f"nvidia-smi query failed: {e}")
            return info

    def _from_gputil(self, info):
        try:
            import GPUtil  # type: ignore[import-untyped]
            gpus = GPUtil.getGPUs()
            if gpus:
                g = gpus[0]
                info.update({
                    'name': g.name, 'usage': g.load * 100,
                    'memory_used': g.memoryUsed,
                    'memory_total': g.memoryTotal,
                    'memory_percent': (g.memoryUsed / g.memoryTotal) * 100
                    if g.memoryTotal > 0 else 0,
                    'temperature': g.temperature, 'available': True,
                    'gpu_count': len(gpus), 'multi_gpu': len(gpus) > 1,
                })
            return info
        except Exception:
            return info

    def _from_wmi(self, info):
        try:
            import wmi  # type: ignore[import-untyped]
            _w = wmi.WMI()
            gpus = _w.Win32_VideoController()
            if gpus:
                info['name'] = gpus[0].Name or 'Unknown GPU'
                info['available'] = True
                info['gpu_count'] = len(gpus)
            return info
        except Exception:
            return info

    # -- public -------------------------------------------------------------
    def get_gpu_info(self):
        """Return GPU info dict; degrades gracefully on every failure."""
        info = self._default()
        if self._nvml_api and self._nvml_handle is not None:
            info = self._from_nvml(info)
            if info['available']:
                return info
        if info is None or not info.get('available'):
            info = self._from_nvidia_smi(self._default())
        if info.get('available'):
            return info
        info = self._from_gputil(self._default())
        if info.get('available'):
            return info
        return self._from_wmi(self._default())


if __name__ == '__main__':
    det = GPUDetector()
    g = det.get_gpu_info()
    print('GPU Detector self-test:')
    print(f"  available   : {g['available']}")
    print(f"  name        : {g['name']}")
    print(f"  usage       : {g['usage']}%")
    print(f"  vram        : {g['memory_used']}/{g['memory_total']} MB")
    print(f"  temperature : {g['temperature']} degC")
