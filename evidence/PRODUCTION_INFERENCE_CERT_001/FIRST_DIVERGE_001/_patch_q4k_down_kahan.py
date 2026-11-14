import subprocess
import pathlib

raw = subprocess.check_output(["git", "show", "HEAD:src/backend/gemv_q4k.comp"])
text = raw.decode("utf-8")
old_init = (
    "  uint rowOff = row * nblk * 144u;\r\n"
    "  // precise: disable FMA/reassoc (match gemv_q6k; GATE/UP 0-ULP vs llama)\r\n"
    "  precise float sumf = 0.0;\r\n"
    "  precise float sums[8];\r\n"
    "  for (uint i = 0u; i < 8u; ++i) sums[i] = 0.0;"
)
new_init = (
    "  uint rowOff = row * nblk * 144u;\r\n"
    "  // GATE/UP stock; FFN_DOWN (rows<cols) Kahan only (PROMOTE=0)\r\n"
    "  const bool downShape = pc.rows < pc.cols;\r\n"
    "  precise float sumf = 0.0;\r\n"
    "  precise float sumc = 0.0;\r\n"
    "  precise float sums[8];\r\n"
    "  precise float sumsc[8];\r\n"
    "  for (uint i = 0u; i < 8u; ++i) { sums[i] = 0.0; sumsc[i] = 0.0; }"
)
old_acc = (
    "    precise float dw = d * xd;\r\n"
    "    for (uint l = 0u; l < 8u; ++l)\r\n"
    "      sums[l] = sums[l] + dw * float(aux32[l]);\r\n"
    "    precise float dm = dmin * xd;\r\n"
    "    sumf = sumf - dm * float(sumi);\r\n"
    "  }\r\n"
    "  for (uint l = 0u; l < 8u; ++l) sumf = sumf + sums[l];\r\n"
    "  y[row] = sumf;\r\n"
    "}"
)
new_acc = (
    "    precise float dw = d * xd;\r\n"
    "    precise float dm = dmin * xd;\r\n"
    "    if (downShape) {\r\n"
    "      for (uint l = 0u; l < 8u; ++l) {\r\n"
    "        precise float yv = dw * float(aux32[l]) - sumsc[l];\r\n"
    "        precise float t = sums[l] + yv;\r\n"
    "        sumsc[l] = (t - sums[l]) - yv;\r\n"
    "        sums[l] = t;\r\n"
    "      }\r\n"
    "      precise float yv = -(dm * float(sumi)) - sumc;\r\n"
    "      precise float t = sumf + yv;\r\n"
    "      sumc = (t - sumf) - yv;\r\n"
    "      sumf = t;\r\n"
    "    } else {\r\n"
    "      for (uint l = 0u; l < 8u; ++l)\r\n"
    "        sums[l] = sums[l] + dw * float(aux32[l]);\r\n"
    "      sumf = sumf - dm * float(sumi);\r\n"
    "    }\r\n"
    "  }\r\n"
    "  if (downShape) {\r\n"
    "    for (uint l = 0u; l < 8u; ++l) {\r\n"
    "      precise float yv = sums[l] - sumc;\r\n"
    "      precise float t = sumf + yv;\r\n"
    "      sumc = (t - sumf) - yv;\r\n"
    "      sumf = t;\r\n"
    "    }\r\n"
    "  } else {\r\n"
    "    for (uint l = 0u; l < 8u; ++l) sumf = sumf + sums[l];\r\n"
    "  }\r\n"
    "  y[row] = sumf;\r\n"
    "}"
)
if old_init not in text:
    raise SystemExit("init missing")
if old_acc not in text:
    raise SystemExit("acc missing")
text = text.replace(old_init, new_init).replace(old_acc, new_acc)
pathlib.Path("src/backend/gemv_q4k.comp").write_bytes(text.encode("utf-8"))
print("ok", len(text))
