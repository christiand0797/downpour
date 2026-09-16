with open('downpour_v29_titanium.py', 'r') as f:
    lines = f.readlines()
    class_start = 20256  # 0-indexed
    class_end = 22108    # 0-indexed (line 22109 - 1)
    class_indent = 0
    method_indent = 4  # Expected indentation for class methods
    
    for i in range(class_start, class_end + 1):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith('def '):
            actual_indent = len(line) - len(line.lstrip(' '))
            if actual_indent != method_indent:
                print(f'Line {i+1}: {actual_indent} spaces - {line.strip()[:80]}')