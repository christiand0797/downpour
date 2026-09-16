with open('downpour_v29_titanium.py', 'r') as f:
    lines = f.readlines()
    in_class = False
    class_start = -1
    class_indent = 0
    for i, line in enumerate(lines):
        if 'class ImmersiveRainCanvas' in line:
            in_class = True
            class_start = i
            class_indent = len(line) - len(line.lstrip(' '))
            print('Class starts at line', i+1, 'indent:', class_indent)
        if i > class_start and class_start >= 0:
            stripped = line.strip()
            if stripped.startswith('class ') and len(line) - len(line.lstrip(' ')) <= class_indent:
                print('Next class at line', i+1, 'indent:', len(line) - len(line.lstrip(' ')))
                break
    print('Class ends around line', i+1)