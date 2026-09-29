# -*- coding: utf-8 -*-
import io
p = r'F:\~dev\rawrxd\src\core\rawrxd_subsystem_api.cpp'
c = io.open(p, encoding='utf-8', errors='replace').read().replace('\r\n','\n')
pairs = [
 ("    SO_CreateThreadPool(static_cast<int>(threads));\n    SO_StartDEFLATEThreads(static_cast<int>(threads));\n    SO_InitializePrefetchQueue(64);",
  "    (void)SO_CreateThreadPool();\n    SO_StartDEFLATEThreads(static_cast<uint32_t>(threads));\n    (void)SO_InitializePrefetchQueue();"),
 ('#include "rawrxd_subsystem_api.hpp"',
  '#include "rawrxd_subsystem_api.hpp"\n#include <atomic>\n#include <cstring>\n#include <new>'),
]
n = 0
for old_s, new_s in pairs:
    if old_s in c:
        c = c.replace(old_s, new_s); n += 1
    else:
        print('MISS:', old_s[:60])
io.open(p, 'w', encoding='utf-8', newline='\n').write(c)
print('APPLIED2', n)
