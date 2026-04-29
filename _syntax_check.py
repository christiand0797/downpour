"""Syntax check all active .py files in the Downpour project."""

__version__ = "29.0.0"

import py_compile, os, sys
from pathlib import Path

_DIR = Path(__file__).parent

passed = 0
failed = 0

for f in sorted(_DIR.glob('*.py')):
    if f.name.startswith('_') and f.name != '_syntax_check.py':
        continue
    try:
        py_compile.compile(str(f), doraise=True)
        passed += 1
    except py_compile.PyCompileError as e:
        print(f'FAIL: {f.name}: {e}')
        failed += 1

print(f'\n{passed} PASS, {failed} FAIL out of {passed + failed} files')
sys.exit(1 if failed else 0)
