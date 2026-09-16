with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()

# Find the ImmersiveRainCanvas class
class_start = content.find('class ImmersiveRainCanvas(tk.Canvas):')
if class_start == -1:
    print('Class not found')
    exit(1)

# Find the next class definition after ImmersiveRainCanvas
next_class = content.find('\nclass ', class_start + 1)
if next_class == -1:
    next_class = len(content)

# Extract the class body
class_body = content[class_start:next_class]

# The class definition line
class_def_end = class_body.find('\n')
class_def = class_body[:class_def_end + 1]
class_body_content = class_body[class_def_end + 1:]

# Split into lines
lines = class_body_content.split('\n')

# Fix indentation: class methods should be 4 spaces, nested functions 8 spaces
# Current state: some methods at 0, some at 8, some at 12
# Expected: class methods at 4, nested functions at 8

fixed_lines = []
in_method = False
method_indent = 0
base_indent = 4  # Class methods should be 4 spaces

for line in lines:
    stripped = line.lstrip(' ')
    leading_spaces = len(line) - len(stripped)
    
    if stripped.startswith('def '):
        # This is a method definition
        if leading_spaces == 0:
            # Method at module level - should be 4 spaces
            line = '    ' + line
        elif leading_spaces == 8:
            # Nested function at 8 spaces - should be 8 (4 for method + 4 for nested)
            # But if it's a method at 8 spaces, it should be 4
            # Check if it's a method or nested function
            # If previous line was a method def at 4 spaces, this is nested
            pass  # Keep as is for now
        elif leading_spaces == 12:
            # Nested function at 12 spaces - should be 8
            line = line[4:]  # Remove 4 spaces
    
    fixed_lines.append(line)

# Reconstruct
fixed_class = class_def + '\n' + '\n'.join(fixed_lines)

# Replace in content
new_content = content[:class_start] + fixed_class + content[next_class:]

with open('downpour_v29_titanium.py', 'w') as f:
    f.write(new_content)

print('Fixed')