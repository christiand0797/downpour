"""Print the boundaries/indentation of the restored block."""
import io

PATH = 'downpour_v29_titanium.py'
src = io.open(PATH, encoding='utf-8', errors='replace', newline='').read()
lines = src.split('\r\n')
start = None
for i, l in enumerate(lines, 1):
    if 'RESTORED v29.111' in l:
        start = i - 2
        break
print('header starts near line', start)
# print every def/class line indentation from the header to +1300
end = min(len(lines), start + 1300)
prev = None
for i in range(start, end):
    t = lines[i - 1]
    stripped = t.lstrip(' ')
    if stripped.startswith(('def ', 'class ', '#')) or not stripped:
        ind = len(t) - len(stripped)
        if stripped.startswith(('def ', 'class ')) and ind != 4:
            print(f'  !! line {i} ind={ind}: {t[:80]!r}')
        if stripped.startswith('def ') and prev is not None and ind < prev:
            print(f'  dedent line {i} ind={ind} (prev def ind={prev})')
        if stripped.startswith('def '):
            prev = ind
print('--- first 12 lines of block ---')
for i in range(start, start + 12):
    t = lines[i - 1]
    print(f'{i:>7} ind={len(t) - len(t.lstrip(" ")):>3} {t[:90]!r}')
print('--- last defs in file ---')
for i in range(end - 5, min(len(lines), end + 5)):
    t = lines[i - 1]
    print(f'{i:>7} ind={len(t) - len(t.lstrip(" ")):>3} {t[:90]!r}')
