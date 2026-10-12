#include <filesystem>
#include <cstdio>
#include <cstring>
#include <vector>

#include "Deep2InferenceAdapter.h"

int main()
{
    setvbuf(stderr, nullptr, _IONBF, 0);
    const char* path = "F:/rawrxd/DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    Deep2Model* model = Deep2_LoadModel(path);
    const int vocab = Deep2_GetVocabSize(model);
    fprintf(stderr, "vocab=%d\n", vocab);

    const char* probe = "User: Hello, world!\n\nAssistant:";
    fprintf(stderr, "A: tokenize (query)\n");
    int qcap = Deep2_Tokenize(model, probe, nullptr, 0);
    fprintf(stderr, "  needed=%d\n", qcap);
    fprintf(stderr, "B: tokenize (write)\n");
    std::vector<int> ids(qcap > 0 ? qcap : 1);
    int n = Deep2_Tokenize(model, probe, ids.data(), (int) ids.size());
    fprintf(stderr, "  got=%d:", n);
    for (int i = 0; i < n && i < 12; ++i) fprintf(stderr, " %d", ids[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "C: detokenize\n");
    char rt[512] = {};
    int rl = Deep2_Detokenize(model, ids.data(), n, rt, sizeof(rt));
    fprintf(stderr, "  len=%d text=[%s]\n", rl, rt);

    fprintf(stderr, "D: create ctx\n");
    Deep2Context* ctx = Deep2_CreateContext(model, 256);
    fprintf(stderr, "  ctx=%p\n", (void*) ctx);

    fprintf(stderr, "E: prefill\n");
    std::vector<uint32_t> prompt(ids.begin(), ids.begin() + n);
    std::vector<float> logits(vocab, 0.0f);
    int consumed = Deep2_Prefill(ctx, prompt.data(), prompt.size(), logits.data());
    fprintf(stderr, "  consumed=%d logits[0..3]=%.4f %.4f %.4f %.4f\n",
            consumed, logits[0], logits[1], logits[2], logits[3]);

    fprintf(stderr, "F: decode\n");
    std::vector<float> step(vocab, 0.0f);
    int tok = Deep2_Decode(ctx, step.data(), nullptr);
    fprintf(stderr, "  tok=%d step[0..3]=%.4f %.4f %.4f %.4f\n",
            tok, step[0], step[1], step[2], step[3]);

    fprintf(stderr, "G: position/mem\n");
    size_t kv = 0, mb = 0, pk = 0;
    Deep2_GetMemoryInfo(ctx, &kv, &mb, &pk);
    fprintf(stderr, "  kv=%zu model=%zu peak=%zu\n", kv, mb, pk);
    Deep2_ResetKVCache(ctx);
    fprintf(stderr, "H: reset ok\n");
    Deep2_FreeContext(ctx);
    Deep2_FreeModel(model);
    fprintf(stderr, "ALL DONE\n");
    return 0;
}
