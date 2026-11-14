# Clean Deep2Engine = 77f5043af7 + GemvAvxWqNext + R91 ATTN_OUT ULP hold.
# PROMOTE=0 TIP_CLIMB=HOLD
import subprocess
from pathlib import Path

cwd = r"G:\~dev\rawrxd"
base = subprocess.check_output(
    ["git", "show", "77f5043af7:src/deep2/Deep2Engine.cpp"], cwd=cwd
)
text = base.decode("utf-8")
old = (
    "         wt.type == (int)GGMLType::GGML_TYPE_Q6_K)) {\r\n"
    "        const bool ok = vc->DispatchGEMVQuant("
)
new = (
    "         wt.type == (int)GGMLType::GGML_TYPE_Q6_K)) {\r\n"
    "        /* R89: llama-AVX Q4 square pipe for attn_q.weight only (not wo). */\r\n"
    "        if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K &&\r\n"
    '            wt.name.find("attn_q.weight") != std::string::npos)\r\n'
    "            vc->GemvAvxWqNext();\r\n"
    "        const bool ok = vc->DispatchGEMVQuant("
)
if old not in text:
    old = old.replace("\r\n", "\n")
    new = new.replace("\r\n", "\n")
    if old not in text:
        i = text.find("GGML_TYPE_Q6_K)) {")
        raise SystemExit("patch site missing: " + repr(text[i : i + 200]))
    print("patched LF")
else:
    print("patched CRLF")
text = text.replace(old, new, 1)

hold_old = (
    "        B3_StageDigest(key, tokPos, output, hiddenDim); "
    "// pre-residual attn (llama attn_out)\n"
    "    }\n\n"
    "    // 3. Residual connection"
)
hold_new = (
    "        B3_StageDigest(key, tokPos, output, hiddenDim); "
    "// pre-residual attn (llama attn_out)\n"
    "    }\n"
    "    /* R91: ATTN_OUT ULP hold — 3 mantissa LSBs; breaks FFN_NORM Q8 qs. */\n"
    "    {\n"
    '        const char* hold = std::getenv("RAWRXD_ATTN_OUT_ULP_HOLD");\n'
    "        if (hold && hold[0] == '1') {\n"
    "            for (size_t hi = 0; hi < hiddenDim; ++hi) {\n"
    "                std::uint32_t u = 0;\n"
    "                std::memcpy(&u, output + hi, sizeof(u));\n"
    "                u &= ~std::uint32_t(7);\n"
    "                std::memcpy(output + hi, &u, sizeof(u));\n"
    "            }\n"
    "        }\n"
    "    }\n\n"
    "    // 3. Residual connection"
)
if hold_old not in text:
    hold_old = hold_old.replace("\n", "\r\n")
    hold_new = hold_new.replace("\n", "\r\n")
if hold_old not in text:
    raise SystemExit("R91 ULP hold site missing")
text = text.replace(hold_old, hold_new, 1)
print("patched R91 ATTN_OUT_ULP_HOLD")

out = Path(cwd) / "src" / "deep2" / "_Deep2Engine_r89_wq_clean.cpp"
out.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))
print("wrote", out, "bytes", out.stat().st_size)
print("GemvAvxWqNext", text.count("GemvAvxWqNext"))
print("ULP_HOLD", text.count("RAWRXD_ATTN_OUT_ULP_HOLD"))
