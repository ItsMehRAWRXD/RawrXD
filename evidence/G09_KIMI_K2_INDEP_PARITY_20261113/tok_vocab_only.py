import sys
from pathlib import Path
from llama_cpp import Llama

model = sys.argv[1]
prompt = Path(sys.argv[2]).read_text(encoding="utf-8")
# vocab_only should avoid weight load
llm = Llama(model_path=model, vocab_only=True, verbose=True)
# no BOS to match Deep2 special tokens already in fixture
ids = llm.tokenize(prompt.encode("utf-8"), add_bos=False, special=True)
print("PROMPT_BYTES", len(prompt.encode("utf-8")))
print("PROMPT_TOKEN_COUNT", len(ids))
print("PROMPT_TOKEN_IDS", ",".join(str(i) for i in ids))
