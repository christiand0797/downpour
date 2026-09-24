with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()
idx = content.find('_TAB_DEFS: Any = [')
if idx >= 0:
    end = min(len(content), idx + 5000)
    print(content[idx:end])