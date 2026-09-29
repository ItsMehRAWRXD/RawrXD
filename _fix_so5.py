# -*- coding: utf-8 -*-
import io
p = r'F:\~dev\rawrxd\src\core\rawrxd_subsystem_api.cpp'
c = io.open(p, encoding='utf-8', errors='replace').read().replace('\r\n','\n')
bad = "filePath[0] == chr(0)"
good = "filePath[0] == " + chr(39) + "\\0" + chr(39)
c = c.replace(bad, good)
io.open(p, 'w', encoding='utf-8', newline='\n').write(c)
print('OK')
