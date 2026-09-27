import re
with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()
idx = content.find('_TAB_DEFS: Any = [')
end_idx = content.find(']', content.find('_TAB_DEFS: Any = ['))
tab_defs = content[idx:end_idx]
labels = re.findall(r"'\\U[0-9a-f]+ ([^']+)'", tab_defs)
print('Tab count:', len(labels))
for i, label in enumerate(labels, 1):
    print(f'  {i}: {label}')