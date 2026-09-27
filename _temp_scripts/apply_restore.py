"""v29.111 repair: restore the full tab set the v29.110 "tab merge" destroyed.

What happened (verified against logs + AST):
  * The uncommitted v29.110 refactor replaced HEAD's 31-tab `_TAB_DEFS` with
    10 "consolidated" tabs whose builders are stubs (a single tk.Label each).
  * 48 real helper methods (_threats_*, _intel_*, _alert_action_*, ...) were
    deleted while their call sites stayed behind.
  * Result: 7 of 10 tabs raised during build
      - AttributeError: '_tkinter.tkapp' object has no attribute '_threats_*'
      - TclError: cannot use geometry manager pack inside . which already has
        slaves managed by grid        (stub builders pack into the root window)
    leaving an almost empty GUI.  The window itself opened, the tabs did not.

This script keeps the *good* new work (HUD theme + neon tab board, v29.109)
and restores, verbatim from HEAD (v29.107):
  1. the 31-entry `_TAB_DEFS` list,
  2. the real bodies of _build_threats_tab / _build_intel_tab / _build_network_tab,
  3. the 48 deleted helper methods.

Run from the project root:
    .venv\\Scripts\\python.exe _temp_scripts\\apply_restore.py
"""
import ast
import io
import shutil
import sys

HEAD_PATH = '_temp_scripts/head_v29107.py'
WT_PATH = 'downpour_v29_titanium.py'
BAK_PATH = 'downpour_v29_titanium.py.v29110pre_restore.bak'

# builders that exist in BOTH revisions but were rewritten into stubs
REWRITTEN = ('_build_threats_tab', '_build_intel_tab', '_build_network_tab')


def read(path, normalize=False):
    _src = io.open(path, encoding='utf-8', errors='replace', newline='').read()
    return _src.replace('\r\n', '\n') if normalize else _src


def get_class(tree, name='downpour'):
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise SystemExit(f'class {name} not found')


def methods(node):
    return {n.name: n for n in node.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def seg(src, node):
    """Source of a class-body node, with the leading indent put back.

    `ast.get_source_segment` starts at the node's col_offset, so the first
    line loses its indentation - which breaks a class-body splice.
    """
    text = ast.get_source_segment(src, node)
    return ' ' * node.col_offset + text


def tabdefs_range(src, tree, cls):
    """Return (lineno, end_lineno) of the _TAB_DEFS annotated assignment."""
    for n in cls.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and n.name == '_build_ui':
            for sub in ast.walk(n):
                if isinstance(sub, ast.AnnAssign) \
                        and isinstance(sub.target, ast.Name) \
                        and sub.target.id == '_TAB_DEFS':
                    return sub.lineno, sub.end_lineno
    raise SystemExit('_TAB_DEFS not found')


def main():
    head_src = read(HEAD_PATH, normalize=True)
    head_tree = ast.parse(head_src)
    head_cls = get_class(head_tree)
    head_m = methods(head_cls)

    wt_src = read(WT_PATH)
    wt_tree = ast.parse(wt_src)
    wt_cls = get_class(wt_tree)
    wt_m = methods(wt_cls)

    missing = [n for n in head_m if n not in wt_m]
    print(f'HEAD methods {len(head_m)}, WT methods {len(wt_m)}, '
          f'to restore {len(missing)}')

    # sanity: every builder HEAD's _TAB_DEFS points at must exist in WT after
    # the restore (either it already exists, or it is in `missing`)
    h_lo, h_hi = tabdefs_range(head_src, head_tree, head_cls)
    head_tabdefs = head_src.split('\n')[h_lo - 1:h_hi]
    _flat = '\n'.join(line.strip() for line in head_tabdefs)

    class _Self:
        """stands in for the app instance so `self._build_x` evals to its name"""
        def __getattr__(self, item):
            return '_' + item.lstrip('_')

    for _attr, _label, _bname in eval(_flat.split('=', 1)[1],
                                      {'self': _Self()}):
        if _bname.strip() not in wt_m and _bname.strip() not in missing:
            raise SystemExit(f'builder {_bname} exists in neither revision')

    lines = wt_src.split('\r\n')
    ops = []  # (start_line, end_line, text) 1-based inclusive

    # ---- 1. _TAB_DEFS: 10 stub tabs -> 31 real tabs ------------------------
    w_lo, w_hi = tabdefs_range(wt_src, wt_tree, wt_cls)
    ops.append((w_lo, w_hi, '\n'.join(
        ['        # v29.111: 31-tab board restored.  The v29.110 tab merge left',
         '        # stub builders behind (7/10 tabs failed to build, 48 real',
         '        # helpers deleted) - the verified v29.86 tab set is back and the',
         '        # v29.109 HUD board / theme work on top of it unchanged.']
        + head_tabdefs)))

    # ---- 2. the three rewritten tab builders -> HEAD's real bodies ---------
    for name in REWRITTEN:
        ops.append((wt_m[name].lineno, wt_m[name].end_lineno,
                    seg(head_src, head_m[name])))

    # ---- 3. the 48 deleted helpers -> HEAD's bodies ------------------------
    restored = '\n\n'.join(seg(head_src, head_m[n]) for n in missing)

    # ---- apply replacements high line number first ------------------------
    for start, end, text in sorted(ops, key=lambda o: o[0], reverse=True):
        lines[start - 1:end] = text.split('\n')

    # ---- insert restored helpers before the v29.110 section ---------------
    anchor = None
    for i, line in enumerate(lines):
        if 'CONSOLIDATED TAB BUILDERS' in line:
            anchor = i
            break
    if anchor is None:
        raise SystemExit('anchor comment not found')
    while anchor > 0 and lines[anchor - 1].strip().startswith('# ='):
        anchor -= 1

    header = [
        '',
        '    # ==========================================================================',
        '    #  RESTORED v29.111 - tab content rolled back from the v29.110 merge',
        '    # --------------------------------------------------------------------------',
        '    # v29.110 kept only 10 stub tabs and deleted the 48 helpers they used, so',
        '    # 7 of 10 tabs raised while building (AttributeError on _threats_* /',
        '    # TclError pack-vs-grid) and the GUI came up nearly empty.  The methods',
        '    # below are the verified v29.107 bodies, restored verbatim.  The v29.109',
        '    # HUD theme + neon tab board are kept on top.',
        '    # ==========================================================================',
        '',
    ]
    lines[anchor:anchor] = header + restored.split('\n') + ['']

    shutil.copy2(WT_PATH, BAK_PATH)
    io.open(WT_PATH, 'w', encoding='utf-8', newline='').write('\r\n'.join(lines))
    print(f'restored {len(missing)} methods, _TAB_DEFS entries: '
          f'{len(head_tabdefs) - 1}; backup at {BAK_PATH}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
