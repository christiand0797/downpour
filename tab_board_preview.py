"""Downpour GUI preview (v29.109) - renders the REAL tab-board / HUD-theme code.

The full app takes a while to start and scans the machine, so this tool pulls
only the GUI pieces out of downpour_v29_titanium.py (via AST) and draws them in
a mock window. That makes it a faithful, fast way to eyeball layout changes and
grab screenshots.

Usage (from the app folder):
    .venv\\Scripts\\python.exe tab_board_preview.py --mode compare
    .venv\\Scripts\\python.exe tab_board_preview.py --mode board --rows 4
    .venv\\Scripts\\python.exe tab_board_preview.py --mode theme
A PNG is written next to this file (preview_<mode>.png).
"""
import argparse
import ast
import os
import re
import sys

import tkinter as tk
from tkinter import ttk
from typing import Final

APP = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   'downpour_v29_titanium.py')

WANTED_FUNCS = ('_tab_bar_rows', '_hud_shade', '_tab_card_paint',
                '_tab_card_make', '_apply_hud_theme', '_hud_skin_widgets')
WANTED_CLASSES = ('ColorScheme', 'Colors')
WANTED_DICTS = ('_TAB_BAR_SPEC', '_HUD_THEME')


def _read_src(path=None):
    with open(path or APP, encoding='utf-8', errors='replace') as _f:
        return _f.read()


def load_gui_module(path=None):
    """Exec only the GUI pieces of the app and return their namespace."""
    src = _read_src(path)
    tree = ast.parse(src)
    ns = {'__name__': 'downpour_gui_preview', 'Any': object, 'os': os,
          'tk': tk, 'ttk': ttk, 're': re, 'Final': Final, 'sys': sys}
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name in WANTED_CLASSES:
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         '<gui>', 'exec'), ns)
        elif isinstance(node, ast.FunctionDef) and node.name in WANTED_FUNCS:
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         '<gui>', 'exec'), ns)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            _targets = (node.targets if isinstance(node, ast.Assign)
                        else [node.target])
            for _t in _targets:
                if isinstance(_t, ast.Name) and _t.id in WANTED_DICTS:
                    try:
                        ns[_t.id] = ast.literal_eval(node.value)
                    except Exception:
                        pass
    missing = [n for n in (WANTED_FUNCS + WANTED_CLASSES + WANTED_DICTS)
               if n not in ns]
    if missing:
        raise SystemExit(f'could not load {missing} from {path or APP}')
    return ns


def load_tab_labels(path=None):
    """Pull the real tab labels out of _TAB_DEFS (order preserved)."""
    labels = []
    for _attr, _raw in re.findall(r"\(\s*'(_tab_\w+)',\s*'((?:[^'\\]|\\.)*)'",
                                  _read_src(path)):
        try:
            labels.append(ast.literal_eval("'" + _raw + "'"))
        except Exception:
            labels.append(_raw)
    if not labels:
        raise SystemExit('no tab labels found - did _TAB_DEFS change shape?')
    return labels


def build_theme_showcase(parent, ns):
    """Exercise the HUD theme on the widget types the app uses everywhere."""
    C = ns['Colors']
    card = tk.Frame(parent, bg=C.GLASS_PANEL,
                    highlightbackground=C.GLASS_BORDER,
                    highlightcolor=C.GLASS_BORDER, highlightthickness=1)
    tk.Label(card, text='HUD THEME  -  tables / sub-tabs / inputs / buttons',
             font=('Consolas', 9, 'bold'), fg=C.GAUGE_TEAL, bg=C.GLASS_PANEL
             ).pack(anchor='w', padx=8, pady=(6, 4))

    tv = ttk.Treeview(card, style='Titan.Treeview', show='headings', height=6,
                      columns=('a', 'b', 'c'))
    for col, txt, w in (('a', 'PROCESS', 260), ('b', 'RISK', 120),
                        ('c', 'STATUS', 320)):
        tv.heading(col, text=txt)
        tv.column(col, width=w, anchor='w')
    for i, r in enumerate((('svchost.exe', 'LOW', 'signed / healthy'),
                           ('powershell.exe', 'MED', 'encoded command'),
                           ('rundll32.exe', 'HIGH', 'unsigned module'),
                           ('chrome.exe', 'LOW', 'network active'),
                           ('unknown_tmp.exe', 'CRIT', 'quarantined'))):
        tv.insert('', 'end', values=r)
    tv.selection_set(tv.get_children()[2])
    tv.pack(fill='x', padx=8, pady=(0, 8))

    nb = ttk.Notebook(card, style='Titan.TNotebook')
    for t in ('Hardening & NSA Checks', 'Vulnerability Scan', 'Compliance'):
        f = tk.Frame(nb, bg=C.BG_VOID)
        tk.Label(f, text='sub-tab content', font=('Consolas', 9),
                 fg=C.TEXT_DIM, bg=C.BG_VOID).pack(padx=10, pady=12)
        nb.add(f, text=t)
    nb.pack(fill='x', padx=8, pady=(0, 8))

    bar = tk.Frame(card, bg=C.GLASS_PANEL)
    bar.pack(fill='x', padx=8, pady=(0, 10))
    tk.Label(bar, text='HUNT:', font=('Consolas', 9, 'bold'), fg=C.GAUGE_RED,
             bg=C.GLASS_PANEL).pack(side='left', padx=(0, 6))
    e = tk.Entry(bar, font=('Consolas', 10), bg=C.GLASS_DARK,
                 fg=C.TEXT_LIGHT, insertbackground=C.GAUGE_TEAL, width=28)
    e.insert(0, 'search threats / hashes / ips')
    e.pack(side='left', padx=4)
    for txt, fg, bg in (('[SCAN]', C.BG_VOID, C.GAUGE_TEAL),
                        ('[QUARANTINE]', C.TEXT_BRIGHT, '#3a2a10'),
                        ('[PANIC]', C.TEXT_BRIGHT, '#5a1020')):
        tk.Button(bar, text=txt, font=('Consolas', 8, 'bold'), fg=fg, bg=bg,
                  relief='flat', bd=0, padx=8).pack(side='left', padx=4)
    ttk.Progressbar(card, style='Neon.TProgressbar', mode='determinate',
                    maximum=100, value=68).pack(fill='x', padx=8, pady=(0, 10))
    return card


def _enable_dpi_awareness():
    """Make Tk coords match physical screen pixels (Windows display scaling).

    Without this, winfo_rootx/y are logical pixels while ImageGrab works in
    physical pixels, so a screenshot lands on the wrong part of the screen.
    """
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)   # per-monitor
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def screenshot(root, path, delay=1600):
    """Grab this window once Tk has laid everything out, then quit."""
    def _shot():
        try:
            root.update_idletasks()
            root.lift()
            try:
                root.attributes('-topmost', True)
            except Exception:
                pass
            root.update()
            x, y = root.winfo_rootx(), root.winfo_rooty()
            w, h = root.winfo_width(), root.winfo_height()
            print(f'grab bbox=({x},{y}) size={w}x{h} '
                  f'screen={root.winfo_screenwidth()}x{root.winfo_screenheight()}')
            from PIL import ImageGrab
            img = ImageGrab.grab(bbox=(x, y, x + w, y + h), all_screens=True)
            img.save(path)
            print(f'WROTE {path}  {img.size[0]}x{img.size[1]}')
        except Exception as exc:                    # pragma: no cover
            print(f'SHOT FAILED: {type(exc).__name__}: {exc}')
        finally:
            try:
                root.destroy()
            except Exception:
                pass
    root.after(delay, _shot)
    root.mainloop()


def main(argv=None):
    ap = argparse.ArgumentParser(description='Downpour GUI preview (v29.109)')
    ap.add_argument('--mode', default='compare',
                    choices=('board', 'compare', 'theme', 'all'))
    ap.add_argument('--rows', type=int, default=None,
                    help='rows for --mode board (default: spec value)')
    ap.add_argument('--width', type=int, default=1440)
    ap.add_argument('--app', default=None,
                    help='path to downpour_v29_titanium.py')
    args = ap.parse_args(argv)

    global APP
    if args.app:
        APP = args.app

    ns = load_gui_module(APP)
    labels = load_tab_labels(APP)
    spec = ns['_TAB_BAR_SPEC']
    C = ns['Colors']

    _enable_dpi_awareness()
    root = tk.Tk()
    root.title(f'Downpour v29.109 GUI preview  |  mode={args.mode}')
    root.configure(bg=C.BG_VOID)
    try:
        root.tk_setPalette(background='#0a0a1a', foreground='#e0e0e0')
    except Exception:
        pass
    style = ttk.Style()
    style.theme_use('default')

    tk.Label(root,
             text=(f'Downpour v29.109 GUI preview   |   {len(labels)} tabs   |   '
                   f'active tab = #13, hovered card = #14'),
             font=('Consolas', 10, 'bold'), fg=C.GAUGE_TEAL, bg=C.BG_VOID
             ).pack(fill='x', padx=10, pady=(8, 6))

    if args.mode in ('compare', 'all'):
        for n in (2, 3, 4, 5):
            per_row = max(1, -(-len(labels) // n))
            tk.Label(root,
                     text=f'--- {n} ROWS  ({per_row} tabs per row) ---',
                     font=('Consolas', 9, 'bold'), fg=C.GAUGE_BLUE,
                     bg=C.BG_VOID).pack(fill='x', padx=10, pady=(2, 0))
            board, _cards = build_board(root, ns, labels, n, content_h=6,
                                        active_idx=12, hover_idx=13,
                                        tag=f'rows={n}  ')
            board.pack(fill='x', padx=10, pady=(2, 2))

    if args.mode == 'board':
        n = args.rows or spec['rows']
        board, _cards = build_board(root, ns, labels, n, content_h=140,
                                    active_idx=12, hover_idx=13)
        board.pack(fill='both', expand=True, padx=10, pady=(0, 10))

    if args.mode in ('theme', 'all'):
        tk.Label(root, text='--- HUD THEME ---', font=('Consolas', 9, 'bold'),
                 fg=C.GAUGE_BLUE, bg=C.BG_VOID).pack(fill='x', padx=10,
                                                     pady=(6, 0))
        # styles must exist before the widgets are created, exactly like the
        # app does it (theme first, then widgets)
        print('hud theme:', ns['_apply_hud_theme'](root, style))
        build_theme_showcase(root, ns).pack(fill='x', padx=10, pady=(2, 8))
        print('widget skin:', ns['_hud_skin_widgets'](root))

    root.update_idletasks()
    root.geometry(f'{args.width}x{root.winfo_reqheight()}+40+20')
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       f'preview_{args.mode}.png')
    screenshot(root, out)
    return 0


# the __main__ guard is at the very end of this file (after every helper)


def build_board(parent, ns, labels, rows, show_header=True, content_h=28,
                active_idx=12, hover_idx=13, tag=''):
    """Rebuild exactly what the app's _build_ui does for the tab board."""
    spec = ns['_TAB_BAR_SPEC']
    C = ns['Colors']
    frame = tk.Frame(parent, bg=C.BG_VOID, highlightbackground=C.GAUGE_CYAN,
                     highlightcolor=C.GAUGE_CYAN, highlightthickness=1)
    row0 = 1 if show_header else 0
    nb_row = row0 + rows
    frame.grid_rowconfigure(nb_row, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    row_frames = []
    for ri in range(rows):
        trf = tk.Frame(frame, bg=spec['bar_bg'])
        trf.grid(row=row0 + ri, column=0, sticky='ew', padx=6,
                 pady=(4 if ri == 0 else 1, 1))
        row_frames.append(trf)

    per_row = max(1, -(-len(labels) // rows))
    cards = []

    def _click(idx):
        for j, c in enumerate(cards):
            ns['_tab_card_paint'](c, 'active' if j == idx else 'idle')

    for i, label in enumerate(labels):
        rf = row_frames[min(i // per_row, rows - 1)]
        card = ns['_tab_card_make'](rf, label, i, _click)
        card.pack(side='left', fill='x', expand=True,
                  padx=spec['card_padx'], pady=spec['card_pady'])
        cards.append(card)

    content = tk.Frame(frame, bg=C.BG_VOID, height=content_h)
    content.grid(row=nb_row, column=0, sticky='nsew', padx=0, pady=(3, 0))
    content.grid_propagate(False)
    tk.Label(content, text=f'{tag}<tab content area - unchanged by this patch>',
             font=('Consolas', 9), fg=C.TEXT_INACTIVE, bg=C.BG_VOID
             ).pack(pady=3)

    ind = tk.Label(frame, text=f'  {labels[active_idx]}  '
                               f'({active_idx + 1}/{len(labels)})',
                   font=('Consolas', 8), fg=C.TEXT_DIM, bg=C.BG_VOID)
    ind.grid(row=nb_row + 1, column=0, sticky='ew', padx=6, pady=(0, 2))

    if show_header:
        hs = spec
        hdr = tk.Frame(frame, bg=hs['header_bg'])
        hdr.grid(row=row0 - 1, column=0, sticky='ew', padx=0, pady=0)
        bl = tk.Canvas(hdr, bg=hs['header_bg'], width=18, height=18,
                       highlightthickness=0, bd=0)
        bl.grid(row=0, column=0, padx=(6, 4), pady=2)
        bl.create_line(1, 16, 1, 3, 15, 3, fill=hs['corner'], width=2)
        bl.create_line(4, 7, 12, 7, fill=hs['corner'], width=1)
        br = tk.Canvas(hdr, bg=hs['header_bg'], width=18, height=18,
                       highlightthickness=0, bd=0)
        br.grid(row=0, column=3, padx=(4, 6), pady=2)
        br.create_line(2, 3, 16, 3, 16, 16, fill=hs['corner'], width=2)
        br.create_line(5, 7, 13, 7, fill=hs['corner'], width=1)
        tk.Label(hdr, text='TAB BOARD', font=hs['header_font'],
                 fg=hs['header_fg'], bg=hs['header_bg']
                 ).grid(row=0, column=1, padx=(2, 10), pady=2, sticky='w')
        hdr.grid_columnconfigure(2, weight=1)
        tk.Label(hdr, text=(f'{len(labels)} modules  |  {rows} rows  |  '
                            f'{per_row} per row  |  Ctrl+Tab cycles'),
                 font=hs['header_font'], fg=hs['header_dim'],
                 bg=hs['header_bg']
                 ).grid(row=0, column=2, padx=8, pady=2, sticky='e')

    # paint the active tab exactly like _highlight_active_tab_button does,
    # plus one hovered card so the hover state is visible in a screenshot
    _click(active_idx)
    if hover_idx is not None and 0 <= hover_idx < len(cards) and hover_idx != active_idx:
        ns['_tab_card_paint'](cards[hover_idx], 'hover')
    return frame, cards


if __name__ == '__main__':
    sys.exit(main())

