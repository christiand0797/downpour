Set-Location 'c:\Users\purpl\Desktop\downpour_consolidated'
Remove-Item -ErrorAction SilentlyContinue _kev_test.py, _check.txt, `
    _run.log, _pytest_z.txt
git add -A
git commit -m 'v29.69: Defense Suite +3 (27 total) - WMI subscription watcher (T1546.003, live SCM filter baselined), Defender exclusion watcher (T1562.001, MSFT_MpPreference via WMI - only viable non-elevated path), startup folder watcher (T1547.001, desktop.ini noise exempted). Wired into _init_defense_suite. All native APIs. 389 passed / 1 skipped.'
git push
