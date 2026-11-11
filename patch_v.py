import io, os
P = r"F:\rawrxd\src\deep2\Deep2Engine.cpp"
with io.open(P, "r", encoding="utf-8", newline=None) as f:
    s = f.read()
old = """            if (kBase)
                memcpy(kBase, kProj, kvBytes);
            if (vBase)
                memcpy(vBase, vProj, kvBytes);
"""
new = """            // Fail closed before storing: a non-finite K/V vector would
            // poison every later decode step even if this token's logits
            // happen to remain finite.
            Deep2ValidateVector("ATTN_V_PRE_KV", layer, vProj, kvDim);
            if (kBase)
                memcpy(kBase, kProj, kvBytes);
            if (vBase)
                memcpy(vBase, vProj, kvBytes);
"""
if s.count(old) != 1:
    raise SystemExit("KV memcpy block not found exactly once")
s = s.replace(old, new, 1)
with io.open(P, "w", encoding="utf-8", newline="\r\n") as f:
    f.write(s)
print("patched V finite validation; bytes", os.path.getsize(P))