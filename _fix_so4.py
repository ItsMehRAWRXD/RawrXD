# -*- coding: utf-8 -*-
import io
p = r'F:\~dev\rawrxd\src\core\rawrxd_subsystem_api.cpp'
c = io.open(p, encoding='utf-8', errors='replace').read().replace('\r\n','\n')
c = c.replace("filePath[0] == ''", "filePath[0] == chr(0)")
io.open(p, 'w', encoding='utf-8', newline='\n').write(c)
print('OK')
