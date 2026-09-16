"""
Fix indentation for ImmersiveRainCanvas class methods.
Only fix methods that are at wrong indentation level (0 spaces instead of 4).
Preserve nested function indentation.
"""
with open('downpour_v29_titanium.py', 'r') as f:
    lines = f.readlines()

# Lines that need fixing (from our analysis)
# Line 20808: _rumble - should be 8 spaces (nested in _play_thunder)
# Line 20901: _fmark - should be 8 spaces (nested in _animate) - already correct at 8
# Line 21681: _update_lightning - 0 spaces, should be 4

# Read the file content
with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()

# Fix specific lines
lines = content.split('\n')

# Fix line 21681 (0-indexed: 21680) - _update_lightning should be 4 spaces
# Current: 0 spaces
# Lines are 1-indexed in editor, 0-indexed in list
# Line 21681 -> index 21680

# Check current state
print(f'Line 21681 (idx 21680): {repr(lines[21680])}')
print(f'Line 20808 (idx 20807): {repr(lines[20807])}')
print(f'Line 20901 (idx 20900): {repr(lines[20900])}')

# Fix line 21681 (0-indexed: 21680) - add 4 spaces
if not lines[21680].startswith('    '):
    lines[21680] = '    ' + lines[21680]
    print('Fixed line 21681')

# Fix line 20808 (_rumble) - should be 8 spaces (currently 12)
# Line 20808 -> index 20807
if lines[20807].startswith('        def _rumble'):
    # Currently 8 spaces, should be 8 (it's a nested function in _play_thunder)
    # But the script earlier said it was 12 spaces. Let me check.
    pass

# Fix line 20807 (the try: before _rumble) - should be 8 spaces
# Line 20808 in editor = index 20807 in list
if lines[20806].startswith('    try:'):  # 4 spaces
    # This is inside _play_thunder (4 spaces), so try: should be 8 spaces
    lines[20806] = '        ' + lines[20806].lstrip()
    print('Fixed line 20807 (try:)')

# Fix the _rumble function definition (line 20809 in editor = index 20808)
if lines[20808].startswith('        def _rumble'):  # 8 spaces
    # This is correct for a nested function (8 spaces)
    pass
elif lines[20808].startswith('            def _rumble'):  # 12 spaces
    lines[20808] = '        ' + lines[20808].lstrip()
    print('Fixed line 20809 (_rumble)')

# Fix line 20900 (_fmark) - should be 8 spaces (inside _animate)
# Line 20901 in editor = index 20900
if lines[20900].startswith('        def _fmark'):  # 8 spaces - correct
    pass
elif lines[20900].startswith('            def _fmark'):  # 12 spaces
    lines[20900] = '        ' + lines[20900].lstrip()
    print('Fixed line 20901 (_fmark)')

# Fix line 21681 (_update_lightning) - should be 4 spaces
if lines[21680].startswith('def _update_lightning'):  # 0 spaces
    lines[21680] = '    ' + lines[21680]
    print('Fixed line 21681 (_update_lightning)')

# Write back
with open('downpour_v29_titanium.py', 'w') as f:
    f.write('\n'.join(lines))

print('Done')