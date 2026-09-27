"""Check which candidate copies of the app still have the __main__ entry point."""
import io
import os

FILES = [
    'downpour_v29_titanium.py',
    '_temp_scripts/pre_restore_snapshot.py',
    '_temp_scripts/other_agent_0207_snapshot.py',
    '_temp_scripts/head_v29107.py',
    'downpour_v29_titanium.py.v29108.bak',
    'downpour_v29_titanium.py.v29110pre_restore.bak',
]

GUARDS = ("__name__ == '__main__'", '__name__ == "__main__"')

for path in FILES:
    if not os.path.exists(path):
        print(f'{path:<55} MISSING')
        continue
    src = io.open(path, encoding='utf-8', errors='replace', newline='').read()
    print(f'{path:<55} lines={src.count(chr(10)):<7} '
          f'def main()={"def main(" in src} '
          f'guard={any(g in src for g in GUARDS)}')
