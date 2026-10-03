with open('threat_intelligence.py', 'r') as f:
    lines = f.readlines()
    for i in range(2085, len(lines)):
        print(f'{i+1}: {repr(lines[i])}')