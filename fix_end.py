with open('threat_intelligence.py', 'r') as f:
    lines = f.readlines()

# Remove the extra closing triple-quote at the end
if lines[-1].strip() == '"""':
    lines.pop()

with open('threat_intelligence.py', 'w') as f:
    f.writelines(lines)

print("Fixed end")