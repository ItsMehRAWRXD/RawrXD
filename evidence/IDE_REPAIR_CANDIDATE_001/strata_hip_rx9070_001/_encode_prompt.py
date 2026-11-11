import sys
sys.path.insert(0, r"F:\rawrxd\external\strata\terminal\0.1.59\tools")
from strata_tokenizer import Tokenizer
gguf = r"F:\rawrxd\external\strata\models\models\qwen36-UD-Q4_K_XL\Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf"
t = Tokenizer.from_gguf(gguf)
ids = t.encode("Say hi in one word.")
print(",".join(str(i) for i in ids))
print("N=", len(ids))
