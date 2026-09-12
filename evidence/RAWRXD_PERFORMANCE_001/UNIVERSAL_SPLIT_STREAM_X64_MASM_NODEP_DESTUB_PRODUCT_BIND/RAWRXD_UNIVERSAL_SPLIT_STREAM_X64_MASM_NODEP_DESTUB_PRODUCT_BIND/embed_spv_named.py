from pathlib import Path
import sys
name = sys.argv[1]
spv = Path(name + ".spv").read_bytes()
words = ["0x%08Xu" % int.from_bytes(spv[i : i + 4], "little") for i in range(0, len(spv), 4)]
Path(name + "_spv.h").write_text(
    "/* embedded %s.spv */\n#include <stdint.h>\n"
    "static const uint32_t %s_spv[] = {\n" % (name, name)
    + ",\n".join(words)
    + "\n};\n"
    "static const uint32_t %s_spv_words = sizeof(%s_spv)/4;\n" % (name, name)
)
print(name, len(spv), len(words))
