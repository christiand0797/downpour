import re

with open('ultimate_threat_intel/__init__.py', 'r') as f:
    content = f.read()

# Find the start of new feeds
start_new = content.find('vt_popular_threat')
if start_new == -1:
    print("vt_popular_threat not found")
    exit(1)

# Find the next class definition after the new feeds
class_idx = content.find('class ThreatDatabase:', start_new)
if class_idx == -1:
    # If not found, try to find the end of the file or another marker
    class_idx = content.find('class ThreatDatabase:')
    if class_idx == -1:
        class_idx = len(content)
print('New feeds section starts at:', start_new)
print('Next class at:', class_idx)

# Extract the new feeds section
new_feeds_section = content[start_new:class_idx].rstrip()
print('Extracted length:', len(new_feeds_section))
print('First 300 chars:', new_feeds_section[:300])
print('Last 200 chars:', new_feeds_section[-200:])

# Remove the new feeds from their current location
content_without_new = content[:start_new] + content[class_idx:]

# Insert before the FEEDS dict closing brace at position 11703
feeds_end = 11703

# Insert before the FEEDS closing brace
new_content = content_without_new[:feeds_end] + new_feeds_section + '\n        ' + content_without_new[feeds_end:]

# Verify the new content
import re
feeds_in_new = re.findall(r'"(\w+)":\s*\{', new_content)
print(f'Total feeds in new content: {len(feeds_in_new)}')

# Count specific feeds
vt_count = new_content.count('vt_popular_threat')
print(f'vt_popular_threat count: {vt_count}')

# Write the new content
with open('ultimate_threat_intel/__init__.py', 'w') as f:
    f.write(new_content)

print('File updated successfully')