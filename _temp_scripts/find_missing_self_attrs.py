"""Report self.<name> references in class `downpour` that are never defined.

Catches "method was deleted by a refactor but call sites remain" - the classic
AttributeError-at-startup bug.  Run from the project root:

    .venv\\Scripts\\python.exe _temp_scripts\\find_missing_self_attrs.py
"""
import ast
import io
import sys

TARGET = 'downpour_v29_titanium.py'


def main() -> int:
    src = io.open(TARGET, encoding='utf-8', errors='replace').read()
    tree = ast.parse(src)
    cls = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == TARGET.replace('.py', ''):
            pass
    # class name is 'downpour' (lowercase)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == 'downpour':
            cls = node
            break
    if cls is None:
        print('class downpour not found')
        return 1

    defined = set()
    for node in ast.walk(cls):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(node.name)
    # names defined as class-level attributes (self.X read -> class attr X)
    for node in cls.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    defined.add(tgt.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
    # Tk/Toplevel inherited methods (this class subclasses tk.Tk)
    try:
        import tkinter
        defined.update(dir(tkinter.Tk))
        defined.update(dir(tkinter.Misc))
    except Exception:
        pass
    # instance attributes assigned anywhere as self.x = ...
    assigned = set()
    for node in ast.walk(cls):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if isinstance(node.value, ast.Name) and node.value.id == 'self':
                assigned.add(node.attr)
        elif isinstance(node, ast.AnnAssign):
            tgt = node.target
            if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) \
                    and tgt.value.id == 'self':
                assigned.add(tgt.attr)
        elif isinstance(node, ast.AugAssign):
            tgt = node.target
            if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) \
                    and tgt.value.id == 'self':
                assigned.add(tgt.attr)

    # dynamic guards: any string literal used with hasattr/getattr/setattr
    dynamic = set()
    for node in ast.walk(cls):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in ('hasattr', 'getattr', 'setattr'):
            for arg in node.args[1:2]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    dynamic.add(arg.value)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ('getattr', 'setattr', 'hasattr'):
            for arg in node.args[1:2]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    dynamic.add(arg.value)

    missing = {}
    for node in ast.walk(cls):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id == 'self' and isinstance(node.ctx, ast.Load):
            name = node.attr
            if name in defined or name in assigned or name in dynamic:
                continue
            missing.setdefault(name, []).append(node.lineno)

    if not missing:
        print(f'OK - no unresolved self.<attr> in class downpour '
              f'({len(defined)} methods, {len(assigned)} attrs)')
        return 0

    print(f'{len(missing)} self.<attr> references with no definition:')
    for name in sorted(missing, key=lambda n: missing[n][0]):
        lines = missing[name]
        print(f'  self.{name:<45} {len(lines):>3}x  lines {lines[:6]}')
    return 2


if __name__ == '__main__':
    sys.exit(main())
