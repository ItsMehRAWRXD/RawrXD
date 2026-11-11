from gguf import GGUFReader
from tokenizers import Tokenizer
from tokenizers.models import BPE
from tokenizers.pre_tokenizers import ByteLevel
from tokenizers.decoders import ByteLevel as ByteLevelDecoder

MODEL = r"F:\OllamaModels\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf"
reader = GGUFReader(MODEL)
tokens = reader.fields["tokenizer.ggml.tokens"].contents()
merges = reader.fields["tokenizer.ggml.merges"].contents()
vocab = {str(token): i for i, token in enumerate(tokens)}
tok = Tokenizer(BPE(vocab=vocab, merges=[tuple(m.split(" ", 1)) for m in merges], unk_token=None))
tok.pre_tokenizer = ByteLevel(add_prefix_space=False)
tok.decoder = ByteLevelDecoder()
for text in ["Hello", ",\n\n", "made", " ancest"]:
    enc = tok.encode(text)
    print(repr(text), enc.ids, [repr(t) for t in enc.tokens], repr(tok.decode(enc.ids)))
