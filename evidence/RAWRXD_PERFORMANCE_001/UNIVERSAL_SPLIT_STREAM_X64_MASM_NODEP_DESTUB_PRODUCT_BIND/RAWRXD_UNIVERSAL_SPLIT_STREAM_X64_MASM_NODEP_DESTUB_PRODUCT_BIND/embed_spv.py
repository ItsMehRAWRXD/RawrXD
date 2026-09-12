# embed_spv.py — one-shot SPIR-V → C header
from pathlib import Path
p = Path("ss_vk_consume.spv").read_bytes()
words = ["0x%08Xu" % int.from_bytes(p[i : i + 4], "little") for i in range(0, len(p), 4)]
Path("ss_vk_spv.h").write_text(
    "/* embedded ss_vk_consume.spv */\n#include <stdint.h>\n"
    "static const uint32_t ss_vk_consume_spv[] = {\n"
    + ",\n".join(words)
    + "\n};\n"
    "static const uint32_t ss_vk_consume_spv_words = "
    "sizeof(ss_vk_consume_spv)/4;\n"
)
print(len(p), len(words))
