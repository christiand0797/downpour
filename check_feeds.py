with open('ultimate_threat_intel/__init__.py', 'r') as f:
    content = f.read()
import re
feeds = re.findall(r'"(\w+)":\s*\{', content)
print('Feed count in regex:', len(feeds))
new_feeds = ['vt_popular_threat', 'hybrid_analysis_popular', 'any_run_popular', 'joe_sandbox_popular', 'cape_sandbox']
for f in new_feeds:
    if f in content:
        print('Found:', f)
    else:
        print('Missing:', f)