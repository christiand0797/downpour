with open('downpour_v29_titanium.py', 'r') as f:
    lines = f.readlines()

# Fix line 20807 (try: inside _play_thunder) - should be 8 spaces
# Line 20807 in editor = index 20806
if lines[20806].startswith('    try:'):
    lines[20806] = '        ' + lines[20806].lstrip()
    print('Fixed line 20807 (try:)')

# Fix line 20809 (_rumble function) - should be 8 spaces
# Line 20809 in editor = index 20808
if lines[20808].startswith('            def _rumble'):
    lines[20808] = '        ' + lines[20808].lstrip()
    print('Fixed line 20809 (_rumble)')

# Fix line 20901 (_fmark) - should be 8 spaces
# Line 20901 in editor = index 20900
if lines[20900].startswith('            def _fmark'):
    lines[20900] = '        ' + lines[20900].lstrip()
    print('Fixed line 20901 (_fmark)')

# Fix line 21681 (_update_lightning) - should be 4 spaces
if lines[21680].startswith('def _update_lightning'):
    lines[21680] = '    ' + lines[21680]
    print('Fixed line 21681 (_update_lightning)')

# Write back
with open('downpour_v29_titanium.py', 'w') as f:
    f.write(''.join(lines))

print('Done')