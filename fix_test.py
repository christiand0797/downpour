with open('cognitive_immune_system.py', 'r') as f:
    content = f.read()

# Find all occurrences
import re
matches = list(re.finditer(r'if __name__ == "__main__":', content))
for m in matches:
    print(f"Found at {m.start()}: {content[m.start():m.start()+100]}")