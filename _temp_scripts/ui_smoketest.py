"""Headless-ish UI smoke test: builds the real window without the UAC prompt.

The app's __main__ block calls restart_as_admin() -> "User Account Control"
dialog, which blocks unattended runs.  This harness imports the app module
(no __main__ guard), instantiates it and pumps the event loop long enough to
build every tab, then closes the window.

Watch downpour.log for the per-tab lines:
    _build_ui: tab [<name>] OK      /  EXCEPTION: ...

Usage: .venv\\Scripts\\python.exe _temp_scripts\\ui_smoketest.py [seconds]
"""
import os
import sys

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 100
sys.argv = ['downpour_v29_titanium.py']          # no --check-* flags
sys.path.insert(0, os.getcwd())

import downpour_v29_titanium as d                # noqa: E402

print('[smoketest] module imported, creating app...', flush=True)
app = d.downpour()
print('[smoketest] app object created, entering mainloop', flush=True)
app.after(SECONDS * 1000, app.destroy)
app.mainloop()
print('[smoketest] mainloop exited', flush=True)
