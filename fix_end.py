with open('cognitive_immune_system.py', 'r') as f:
    content = f.read()

idx = content.find('if __name__ == "__main__":')
if idx >= 0:
    # Find the end of the file
    end = len(content)
    # Check what's after the if __main__ line
    print("Found at:", idx)
    print("Context:", repr(content[idx:idx+200]))
else:
    print("Not found")