"""Diagnose the IndentationError location in downpour_v29_titanium.py."""
import io

PATH = 'downpour_v29_titanium.py'
src = io.open(PATH, encoding='utf-8', errors='replace', newline='').read()
lines = src.split('\r\n')
try:
    compile(src, PATH, 'exec')
    print('compiles fine')
except SyntaxError as e:
    print(f'SyntaxError: {e.msg}  line={e.lineno} offset={e.offset}')
    lo = max(1, (e.lineno or 1) - 25)
    hi = min(len(lines), (e.lineno or 1) + 5)
    for i in range(lo, hi + 1):
        _t = lines[i - 1]
        _ind = len(_t) - len(_t.lstrip(' '))
        print(f'{i:>7} ind={_ind:>3} {ascii(_t[:110])}')
