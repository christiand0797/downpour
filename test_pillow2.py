import sys
print(sys.executable)
print(sys.path)
try:
    import PIL
    print('PIL OK')
except Exception as e:
    print(f'PIL FAILED: {e}')

try:
    import PIL.Image
    print('PIL.Image OK')
except Exception as e:
    print(f'PIL.Image FAILED: {e}')

try:
    import dns
    print('dns OK')
except Exception as e:
    print(f'dns FAILED: {e}')

try:
    import dnspython
    print('dnspython OK')
except Exception as e:
    print(f'dnspython FAILED: {e}')