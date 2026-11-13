import sys, re, hashlib
from pathlib import Path
from gguf import GGUFReader
from tokenizers import Tokenizer, Regex
from tokenizers.models import BPE
from tokenizers.pre_tokenizers import ByteLevel, Sequence, Split
from tokenizers.decoders import ByteLevel as ByteLevelDecoder

model_path, prompt_path, tmpl_out = sys.argv[1:4]
prompt = Path(prompt_path).read_text(encoding='utf-8')
r = GGUFReader(model_path)
arch = r.fields['general.architecture'].contents()
pre = r.fields['tokenizer.ggml.pre'].contents()
tmpl = r.fields['tokenizer.chat_template'].contents()
tokens = r.fields['tokenizer.ggml.tokens'].contents()
merges = r.fields['tokenizer.ggml.merges'].contents()
bos = int(r.fields['tokenizer.ggml.bos_token_id'].contents())
eos = int(r.fields['tokenizer.ggml.eos_token_id'].contents())
Path(tmpl_out).write_text(tmpl, encoding='utf-8')
print(f'ARCH={arch}')
print(f'TOKENIZER_PRE={pre}')
print(f'VOCAB={len(tokens)} MERGES={len(merges)} BOS={bos} EOS={eos}')
print(f'CHAT_TEMPLATE_BYTES={len(tmpl.encode())}')
print(f'CHAT_TEMPLATE_SHA256={hashlib.sha256(tmpl.encode()).hexdigest().upper()}')
print(f'TOKEN_SAMPLE_0={tokens[0]!r} 163584={tokens[163584]!r} 163586={tokens[163586]!r}')
ctrl = [t for t in tokens if isinstance(t,str) and ((t.startswith('<|') and t.endswith('|>')) or t in ('[BOS]','[EOS]','[EOT]','[PAD]','[INST]'))]
ctrl = sorted(set(ctrl), key=len, reverse=True)
print(f'CTRL_COUNT={len(ctrl)} CTRL_HEAD={ctrl[:8]}')
vocab = {t:i for i,t in enumerate(tokens)}
merge_list=[]
for m in merges:
    a=m.split(' ',1)
    if len(a)==2: merge_list.append((a[0],a[1]))
tok = Tokenizer(BPE(vocab=vocab, merges=merge_list))
esc='|'.join(re.escape(c) for c in ctrl)
tok.pre_tokenizer = Sequence([
    Split(Regex(esc), behavior='isolated'),
    ByteLevel(add_prefix_space=False),
])
tok.decoder = ByteLevelDecoder()
enc = tok.encode(prompt, add_special_tokens=False)
ids = enc.ids
print(f'PROMPT_BYTES={len(prompt.encode())}')
print(f'PROMPT_TOKEN_COUNT={len(ids)}')
print('PROMPT_TOKEN_IDS=' + ','.join(map(str,ids)))
print('PROMPT_TOKEN_PIECES=' + '|'.join(enc.tokens))
# also no-special-split baseline
tok2 = Tokenizer(BPE(vocab=vocab, merges=merge_list))
tok2.pre_tokenizer = ByteLevel(add_prefix_space=False)
enc2 = tok2.encode(prompt, add_special_tokens=False)
print('NOSPLIT_COUNT=' + str(len(enc2.ids)))
print('NOSPLIT_IDS=' + ','.join(map(str,enc2.ids)))
