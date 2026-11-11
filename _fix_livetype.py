#!/usr/bin/env python3
# RAWRXD_FIX_LIVETYPEMAP_001 — restore file-scope liveTypeMap_ (free function
# DequantizeTensor + ModelExportRuntime both need it). Removes the duplicate
# member declarations that the concurrent rewrite re-introduced. Atomic.
import io, sys, datetime, shutil

SRC = r"F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp"
with io.open(SRC, "r", encoding="utf-8") as f:
    text = f.read()

edits = []

# 1) Add a file-scope static declaration just before the free function that uses it.
edits.append(("insert_static",
r'''void DequantizeTensor(const TensorView& tv, std::vector<float>& out)
''',
r'''// Live GGUF tensor type map. File-scope because DequantizeTensor() is a free
// function and ModelExportRuntime methods both read/write this table. Do not
// redeclare as a class member (causes C2086 redefinition).
static std::unordered_map<std::string, ModelGenie::GGMLType> liveTypeMap_;

void DequantizeTensor(const TensorView& tv, std::vector<float>& out)
'''))

# 2) Remove the duplicate member declaration in the public section (939-940).
edits.append(("remove_member_pub",
r'''    // Live GGUF tensor type map (for dequant type correction)
    std::unordered_map<std::string, ModelGenie::GGMLType> liveTypeMap_;

    // Execution tracking for RAWRXD_MODELGENIE_TOKEN0_EXECUTION_001
''',
r'''    // Execution tracking for RAWRXD_MODELGENIE_TOKEN0_EXECUTION_001
'''))

# 3) Remove the duplicate member declaration in the private section (1387-1388).
edits.append(("remove_member_priv",
r'''    GGUFROM rom_;
    std::unordered_map<std::string, ModelGenie::GGMLType> liveTypeMap_;
''',
r'''    GGUFROM rom_;
'''))

for name, old, new in edits:
    cnt = text.count(old)
    if cnt != 1:
        sys.stderr.write("ABORT: anchor %s matched %d times\n" % (name, cnt))
        sys.exit(1)
    text = text.replace(old, new, 1)
    sys.stdout.write("[OK] %s\n" % name)

backup = SRC + ".livetypefix_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".bak"
shutil.copy2(SRC, backup)
with io.open(SRC, "w", encoding="utf-8") as f:
    f.write(text)
sys.stdout.write("LIVETYPE_FIX=PASS\nBACKUP=%s\n" % backup)
