"""Split control tokens then ByteLevel BPE — approximate; AUTHORITY only if matches llama.cpp."""
import sys, re, hashlib
from pathlib import Path
from gguf import GGUFReader
from tokenizers import Tokenizer
from tokenizers.models import BPE
from tokenizers.pre_tokenizers import ByteLevel, Sequence, Split
from tokenizers.decoders import ByteLevel as ByteLevelDecoder

model_path, prompt_path = sys.argv[1], sys.argv[2]
prompt = Path(prompt_path).read_text(encoding='utf-8')
reader = GGUFReader(model_path)
tokens = [str(x) for x in reader.fields['tokenizer.ggml.tokens'].data]
merges = [str(x) for x in reader.fields['tokenizer.ggml.merges'].data]
# control-like tokens
ctrl = [t for t in tokens if t.startswith('<|') and t.endswith('|>')]
ctrl += [t for t in tokens if t.startswith('[') and t.endswith(']') and t in ('[BOS]','[EOS]','[EOT]','[PAD]')]
ctrl = sorted(set(ctrl), key=len, reverse=True)
vocab = {t:i for i,t in enumerate(tokens)}
merge_list=[]
for m in merges:
    a=m.split(' ',1)
    if len(a)==2: merge_list.append((a[0],a[1]))
tok = Tokenizer(BPE(vocab=vocab, merges=merge_list))
# Split on known specials first
# Build regex of escaped specials
esc = '|'.join(re.escape(c) for c in ctrl if c)
# Use tokenizers Split keep
from tokenizers import Regex
tok.pre_tokenizer = Sequence([
    Split(Regex(esc), behavior='isolated') if esc else ByteLevel(add_prefix_space=False),
    ByteLevel(add_prefix_space=False),
])
tok.decoder = ByteLevelDecoder()
# Also mark specials
specials = []
for c in ctrl:
    if c in vocab:
        specials.append(c)
# encode
ids = tok.encode(prompt, add_special_tokens=False).ids
print('PROMPT_BYTES', len(prompt.encode()))
print('PROMPT_TOKEN_COUNT', len(ids))
print('PROMPT_TOKEN_IDS', ','.join(map(str,ids)))
print('CTRL_COUNT', len(ctrl))
# piece debug
enc = tok.encode(prompt, add_special_tokens=False)
print('TOKENS', enc.tokens[:50])
