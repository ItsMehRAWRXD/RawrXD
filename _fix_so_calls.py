# -*- coding: utf-8 -*-
import io
p = r'F:\~dev\rawrxd\src\core\rawrxd_subsystem_api.cpp'
c = io.open(p, encoding='utf-8', errors='replace').read().replace('\r\n','\n')
pairs = [
 ("const bool loaded = SO_LoadExecFile(execFile);",
  "const int loaded = SO_LoadExecFile(execFile);"),
 ("const bool streamInit = SO_InitializeStreaming();",
  "const bool streamInit = SO_InitializeStreaming();"),
 ("    (void)SO_CreateThreadPool(static_cast<int>(threads));\n    SO_StartDEFLATEThreads(static_cast<int>(threads));\n    SO_InitializePrefetchQueue(64);",
  "    (void)SO_CreateThreadPool();\n    SO_StartDEFLATEThreads(static_cast<uint32_t>(threads));\n    (void)SO_InitializePrefetchQueue();"),
 ("    void* arena = nullptr;\n    const bool arenaOk = SO_CreateMemoryArena(static_cast<size_t>(arenaSize), &arena);",
  "    void* arena = SO_CreateMemoryArena(arenaSize);"),
 ("    if (arenaOk && arena) {", "    if (arena) {"),
 ("    void* arena = nullptr;\n    (void)SO_CreateMemoryArena(512ULL * 1024 * 1024, &arena);",
  "    void* arena = SO_CreateMemoryArena(512ULL * 1024 * 1024);"),
]
n = 0
for old_s, new_s in pairs:
    if old_s in c:
        c = c.replace(old_s, new_s)
        n += 1
    else:
        print('MISS:', old_s[:60])
io.open(p, 'w', encoding='utf-8', newline='\n').write(c)
print('APPLIED', n)
