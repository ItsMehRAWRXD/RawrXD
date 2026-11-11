#!/usr/bin/env python3
# RAWRXD_FIX_METASKIP_001 -- remove the spurious 4-byte skip after the GGUF
# metadata valueType. valueType is a uint32 with NO padding; the value begins
# immediately. The extra `ptr += 4` shifts the parser by 4 bytes per KV
# (45 KV -> 180 bytes) and corrupts the tensor-directory offset, failing init.
# (Original "GGUF metadata switch fix #1"; the concurrent rewrite re-added it.)
import io, sys, datetime, shutil

SRC = r"F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp"
with io.open(SRC, "r", encoding="utf-8") as f:
    text = f.read()

old = r'''            ptr += 4; // skip value type and padding?'''
new = r'''            // GGUF: valueType is uint32 with NO padding; ptr already advanced.
            // The value itself begins here and is decoded by the switch below.'''

cnt = text.count(old)
if cnt != 1:
    sys.stderr.write("ABORT: metaskip anchor matched %d times (file changed?)\n" % cnt)
    sys.exit(1)
text = text.replace(old, new, 1)

backup = SRC + ".metaskipfix_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".bak"
shutil.copy2(SRC, backup)
with io.open(SRC, "w", encoding="utf-8") as f:
    f.write(text)
sys.stdout.write("[OK] removed spurious valueType skip\n")
sys.stdout.write("METASKIP_FIX=PASS\nBACKUP=%s\n" % backup)
