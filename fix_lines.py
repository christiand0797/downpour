with open('threat_intelligence.py', 'r') as f:
    lines = f.readlines()

# Remove lines 51-54 (0-indexed 50-53)
del lines[50:54]

with open('threat_intelligence.py', 'w') as f:
    f.writelines(lines)

print("Fixed")