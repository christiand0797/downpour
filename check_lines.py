with open('threat_intelligence.py', 'r') as f:
    lines = f.readlines()
    for i in range(44, 60):
        print(f'{i+1}: {repr(lines[i])}')