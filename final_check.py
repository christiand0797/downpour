import sys
sys.path.insert(0, '.')
import downpour_v29_titanium as dp

methods = [
    '_build_dashboard', '_build_threats_tab', '_build_intel_tab', '_build_network_tab',
    '_build_forensics_tab', '_build_defense_tab', '_build_performance_tab',
    '_build_tools_tab', '_build_processes_tab', '_build_cis_tab',
    '_threats_apply_filter', '_threats_filter_changed',
    '_intel_view_changed', '_net_view_changed', '_forensics_view_changed',
    '_defense_view_changed', '_tools_view_changed',
]

app = dp.downpour()

print('=== Method Verification ===')
for m in methods:
    has = hasattr(dp.downpour, m)
    print(f'{"OK" if hasattr(dp.downpour, m) else "MISSING"} {m}')

# Check tab count
import re
with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()
idx = content.find('_TAB_DEFS: Any = [')
end_idx = content.find(']', content.find('_TAB_DEFS: Any = ['))
tab_defs = content[idx:end_idx]
import re
labels = re.findall(r"'\\U[0-9a-f]+ ([^']+)'", content[content.find('_TAB_DEFS: Any = ['):content.find(']', content.find('_TAB_DEFS: Any = ['))])
print(f'\nTab count: {len(labels)}')
for i, label in enumerate(labels, 1):
    print(f'  {i}: {label}')