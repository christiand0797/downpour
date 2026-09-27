"""v29.111b: restore the module-level entry point the working file lost.

The working tree file ends mid-class (line 60361) and no longer defines
`check_admin_privileges`, `restart_as_admin`, `main` or the
`if __name__ == '__main__':` block.  Running it therefore just defines the
class and exits - no window ever appears (that is the "GUI not opening" bug).

Appends those pieces verbatim from HEAD (v29.107), then the caller should run
py_compile and launch the app.

    .venv\\Scripts\\python.exe _temp_scripts\\append_entry.py
"""
import ast
import io
import shutil
import sys

HEAD = '_temp_scripts/head_v29107.py'
WT = 'downpour_v29_titanium.py'
BAK = 'downpour_v29_titanium.py.v29111pre_entry.bak'
WANTED = ('check_admin_privileges', 'restart_as_admin', 'main')


def main() -> int:
    head_src = io.open(HEAD, encoding='utf-8', errors='replace',
                       newline='').read().replace('\r\n', '\n')
    tree = ast.parse(head_src)
    lines = head_src.split('\n')

    pieces = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name in WANTED:
            pieces.append((' '.join(['# restored entry helper:']), node))
    # the __main__ guard block (last top-level statement)
    guard = [n for n in tree.body if isinstance(n, ast.If)
             and '__main__' in ast.unparse(n.test)]
    if len(guard) != 1:
        raise SystemExit(f'expected exactly 1 __main__ guard, got {len(guard)}')

    out = ['', '',
           '# ==========================================================================',
           '#  RESTORED v29.111 - module entry point',
           '# --------------------------------------------------------------------------',
           '# These were missing from the working tree, so `python downpour_v29_titanium.py`',
           '# only defined the class and exited: no window, no error.  Bodies below are',
           '# the verified v29.107 originals.',
           '# ==========================================================================',
           '']
    for _comment, node in pieces:
        out.extend(lines[node.lineno - 1:node.end_lineno])
        out.append('')
        out.append('')
    g = guard[0]
    out.extend(lines[g.lineno - 1:g.end_lineno])
    out.append('')

    wt_src = io.open(WT, encoding='utf-8', errors='replace',
                     newline='').read()
    if "if __name__ == '__main__':" in wt_src:
        print('entry point already present - nothing to do')
        return 0
    trailing = '' if wt_src.endswith('\r\n') else '\r\n'
    shutil.copy2(WT, BAK)
    with io.open(WT, 'a', encoding='utf-8', newline='') as _f:
        _f.write(trailing + '\r\n'.join(out))
    print(f'appended {len(pieces)} functions + __main__ guard; backup {BAK}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
