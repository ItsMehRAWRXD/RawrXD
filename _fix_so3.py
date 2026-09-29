# -*- coding: utf-8 -*-
import io
p = r'F:\~dev\rawrxd\src\core\rawrxd_subsystem_api.cpp'
c = io.open(p, encoding='utf-8', errors='replace').read().replace('\r\n','\n')
c = c.replace("const bool pipelines = SO_CreateComputePipelines();",
              "const bool pipelines = (SO_CreateComputePipelines(nullptr, 4) != nullptr);")
io.open(p, 'w', encoding='utf-8', newline='\n').write(c)
print('OK')
