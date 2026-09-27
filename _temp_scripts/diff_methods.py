"""Compare class `downpour` methods between HEAD (v29.107) and the working tree.

Usage:  .venv\\Scripts\\python.exe _temp_scripts\\diff_methods.py
"""
import ast
import io
import sys


def methods(path):
    src = io.open(path, encoding='utf-8', errors='replace').read()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == 'downpour':
            return src, tree, node
    raise SystemExit('class downpour not found in ' + path)


def order(node):
    return [n.name for n in node.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def main():
    _hs, _ht, head = methods('_temp_scripts/head_v29107.py')
    _ws, _wt, wt = methods('downpour_v29_titanium.py')
    h, w = set(order(head)), set(order(wt))
    gone = [n for n in order(head) if n not in w]
    added = [n for n in order(wt) if n not in h]
    print(f'HEAD methods: {len(h)}   WT methods: {len(w)}')
    print(f'\nDELETED in WT ({len(gone)}):')
    for n in gone:
        print('   -', n)
    print(f'\nNEW in WT ({len(added)}):')
    for n in added:
        print('   +', n)
    return 0


if __name__ == '__main__':
    sys.exit(main())
