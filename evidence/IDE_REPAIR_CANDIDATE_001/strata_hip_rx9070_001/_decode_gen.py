import sys
sys.path.insert(0, r"F:\rawrxd\external\strata\terminal\0.1.59\tools")
from strata_tokenizer import Tokenizer
gguf = r"F:\rawrxd\external\strata\models\models\qwen36-UD-Q4_K_XL\Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf"
t = Tokenizer.from_gguf(gguf)
ids = [271, 248068, 198, 8160, 579, 264, 7047, 1817]
print(repr(t.decode(ids)))
