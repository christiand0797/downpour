import re
with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()

idx = content.find('_TAB_DEFS: Any = [')
end_idx = content.find(']', content.find('_TAB_DEFS: Any = ['))
tab_defs = content[idx:end_idx]

print('Tabs in _TAB_DEFS:')
for tab in ['_tab_defense', '_tab_forensics', '_tab_tools', '_tab_forensic', '_tab_defense']:
    if tab in tab_defs:
        print(f'  FOUND: {tab}')
    else:
        print(f'  MISSING: {tab}')

# Count total tabs
labels = re.findall(r"'\\U[0-9a-f]+ ([^']+)'", tab_defs)
print(f'\nTotal tabs: {len(labels)}')
for i, label in enumerate(labels, 1):
    print(f'  {i}: {label}')