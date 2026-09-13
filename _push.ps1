Set-Location 'c:\Users\purpl\Desktop\downpour_consolidated'
Remove-Item -ErrorAction SilentlyContinue _check.txt, _run.log, _p.log, `
    _pytest_z.txt, _pytest_final.txt, _kev_test.py, _run_p.py
git add -A
git commit -m 'v29.65/66/67/68: firewall-rule watcher (new/changed inbound allows, OFF profiles), service-binary watcher (new/repointed ImagePaths), UAC-bypass IOC watcher (auto-elevate hijack slots), COM-hijack watcher (HKCU CLSID override + HKLM writable CLSIDs)'
git push
