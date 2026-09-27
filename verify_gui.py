import sys
sys.path.insert(0, '.')
import downpour_v29_titanium as dp

methods = [
    '_build_dashboard',
    '_build_threats_tab',
    '_build_intel_tab',
    '_build_network_tab',
    '_build_forensics_tab',
    '_build_defense_tab',
    '_build_performance_tab',
    '_build_tools_tab',
    '_build_processes_tab',
    '_build_cis_tab',
]

app = dp.downpour()
print("=== Method Verification ===")
for m in methods:
    has = hasattr(dp.downpour, m)
    print(f'{"OK" if hasattr(dp.downpour, m) else "MISSING"} {m}')