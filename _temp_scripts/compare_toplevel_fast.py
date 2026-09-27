"""Fast regex compare of module-level defs/classes (no AST) + entry-point check."""
import io
import re

PAT = re.compile(r'^(def|class)\s+([A-Za-z_]\w*)', re.M)


def top_names(path):
    src = io.open(path, encoding='utf-8', errors='replace', newline='').read()
    return set(m.group(2) for m in PAT.finditer(src)), src


for label, path in (('HEAD', '_temp_scripts/head_v29107.py'),
                    ('v29108.bak', 'downpour_v29_titanium.py.v29108.bak')):
    names, _src = top_names(path)
    _wt_names, wt_src = top_names('downpour_v29_titanium.py')
    missing = sorted(n for n in names if not re.search(
        r'^(def|class)\s+' + re.escape(n) + r'\b', wt_src, re.M))
    print(f'vs {label}: {len(missing)} module-level names missing -> {missing}')

_wt_names, wt_src = top_names('downpour_v29_titanium.py')
for probe in ('def main(', "if __name__ == '__main__'", 'check_admin_privileges',
              'restart_as_admin', 'def _finish_init', 'ImmersiveRainCanvas'):
    print(f'working file has {probe!r}: {probe in wt_src}')
