import json
from collections import Counter

with open('downpour_data/logs/events.jsonl', 'r') as f:
    lines = f.readlines()

events = []
for line in lines[1:]:  # Skip first line (it's a header)
    line = line.strip()
    if line:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass

print(f'Total events: {len(events)}')

# Event types
event_types = Counter(e.get('event_type', 'unknown') for e in events)
print('\nEvent types:')
for et, count in event_types.most_common():
    print(f'  {et}: {count}')

# Levels
levels = Counter(e.get('level', 'unknown') for e in events)
print('\nLevels:')
for lvl, count in levels.most_common():
    print(f'  {lvl}: {count}')

# Recent events
print('\nLast 10 events:')
for e in events[-10:]:
    ts = e.get('timestamp', '')
    et = e.get('event_type', '')
    lvl = e.get('level', '')
    msg = e.get('message', '')[:80]
    print(f'  {ts} | {et} | {lvl} | {msg}')