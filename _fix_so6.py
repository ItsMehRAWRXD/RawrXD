# -*- coding: utf-8 -*-
import io
p = r'F:\~dev\rawrxd\src\core\rawrxd_subsystem_api.cpp'
data = io.open(p, 'rb').read()
# Show context bytes around error location (search "filePath[0] == ")
idx = data.find(b'filePath[0] == ')
print(repr(data[idx:idx+30]))
good = b"filePath[0] == '\\x00'" if data[idx+len(b'filePath[0] == ')] in b"\x00'" else None
# Replace any of: NUL byte literal, empty quotes, chr(0)
data = data.replace(b"filePath[0] == \x00'", b"filePath[0] == '\\0'")
data = data.replace(b"filePath[0] == ''; ", b"filePath[0] == '\\0';")
data = data.replace(b"filePath[0] == chr(0)", b"filePath[0] == '\\0'")
data = data.replace(b"filePath[0] == ''", b"filePath[0] == '\\0'")
io.open(p, 'wb').write(data)
idx2 = data.find(b'filePath[0] == ')
print(repr(data[idx2:idx2+30]))
print('DONE')
