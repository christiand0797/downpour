"""Compare module-level (top-level) defs/classes: HEAD vs working tree."""
import ast
import io

def top_names(path):
    src = io.open(path, encoding='utf-8', errors='replace', newline='').read()
    tree = ast.parse(src)
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name] = (node.lineno, node.end_lineno)
    return out

head = top_names('_temp_scripts/head_v29107.py')
bak = top_names('downpour_v29_titanium.py.v29108.bak')
wt = top_names('downpour_v29_titanium.py')

for label, other in (('HEAD', head), ('v29108.bak', bak)):
    missing = [n for n in other if n not in wt]
    extra = [n for n in wt if n not in other]
    print(f'--- vs {label}: missing from working file ({len(missing)}): {missing}')
    print(f'    only in working file ({len(extra)}): {extra}')
