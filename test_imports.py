mods = ['psutil','requests','cryptography','watchdog','colorama','wmi','sklearn','numpy','scipy','pillow','dnspython','joblib','tqdm','pyperclip','pydantic','yaml','aiohttp','click','rich','tenacity','schedule']
failed = []
for m in mods:
    try:
        __import__(m.replace('-','_'))
    except Exception as e:
        failed.append(m)
        print(f"FAILED: {m} - {e}")

if failed:
    print('FAILED:', failed)
else:
    print('ALL CORE IMPORTS OK')