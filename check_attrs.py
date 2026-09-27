import re
from collections import Counter

with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()

idx = content.find('_TAB_DEFS: Any = [')
end_idx = content.find(']', idx)
tab_defs = content[idx:end_idx]
attrs = re.findall(r"'_tab_([^']+)'", tab_defs)
counts = Counter(attrs)
for attr, count in counts.items():
    if count > 1:
        print(f'DUPLICATE attr: {attr} appears {count} times')
print('All unique' if all(c == 1 for c in counts.values()) else 'Duplicates found')