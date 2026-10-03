mods = [
    ('psutil', 'psutil'),
    ('requests', 'requests'),
    ('cryptography', 'cryptography'),
    ('watchdog', 'watchdog'),
    ('colorama', 'colorama'),
    ('wmi', 'wmi'),
    ('sklearn', 'sklearn'),
    ('numpy', 'numpy'),
    ('scipy', 'scipy'),
    ('PIL', 'pillow'),  # pillow is imported as PIL
    ('dns', 'dnspython'),  # dnspython is imported as dns
    ('joblib', 'joblib'),
    ('tqdm', 'tqdm'),
    ('pyperclip', 'pyperclip'),
    ('pydantic', 'pydantic'),
    ('yaml', 'pyyaml'),  # pyyaml is imported as yaml
    ('aiohttp', 'aiohttp'),
    ('click', 'click'),
    ('rich', 'rich'),
    ('tenacity', 'tenacity'),
    ('schedule', 'schedule'),
]
failed = []
for mod_name, pkg_name in mods:
    try:
        __import__(mod_name)
        print(f'OK: {pkg_name} (imported as {mod_name})')
    except Exception as e:
        failed.append(f'{pkg_name} ({mod_name}): {e}')
        print(f'FAILED: {pkg_name} ({mod_name}): {e}')

if failed:
    print('\nFAILED:', failed)
else:
    print('\nALL CORE IMPORTS OK')