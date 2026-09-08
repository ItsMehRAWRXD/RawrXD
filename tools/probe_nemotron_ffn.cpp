// One-shot: print blk.1 FFN dims from Nemotron Q8 GGUF.
#include "GGUFLoader.hpp"
#include <cstdio>
int main(int argc, char** argv) {
    const char* p = argc > 1 ? argv[1]
        : "F:/OllamaModels/NVIDIA-Nemotron-3-Nano-4B-GGUF/NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf";
    auto r = Deep2::GGUFLoader::Load(p);
    if (!r.ok) { fprintf(stderr, "load fail: %s\n", r.error.c_str()); return 1; }
    for (const auto& t : r.tensors) {
        if (t.name.find("blk.1.") == 0 || t.name.find("blk.12.attn_q") == 0) {
            size_t d0 = t.dimensions.size() > 0 ? t.dimensions[0] : 0;
            size_t d1 = t.dimensions.size() > 1 ? t.dimensions[1] : 0;
            printf("%s type=%d dims=%zux%zu size=%zu data=%p\n",
                   t.name.c_str(), (int)t.type, d0, d1, t.size, t.data);
        }
    }
    return 0;
}
