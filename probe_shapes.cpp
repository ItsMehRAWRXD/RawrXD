#include "src/deep2/K2GlobalTensorIndex.hpp"
#include "src/deep2/KimiK2Config.hpp"
#include <cstdio>
#include <filesystem>

int main(int argc, char** argv) {
    std::filesystem::path dir = (argc > 1) ? argv[1] : std::filesystem::current_path();
    Deep2::GlobalTensorIndex index;
    std::string err;
    Deep2::KimiK2Config cfg;
    cfg.hiddenDim = 7168; cfg.numLayers = 61;
    if (!index.BuildFromShardDirectory(dir, cfg, err)) {
        printf("Build failed: %s\n", err.c_str());
        return 1;
    }
    const char* names[] = {
        "blk.0.attn_q_a.weight", "blk.0.attn_q_b.weight",
        "blk.0.attn_kv_a_mqa.weight", "blk.0.attn_k_b.weight",
        "blk.0.attn_v_b.weight", "blk.0.attn_output.weight",
        "blk.0.attn_norm.weight", "blk.0.attn_q_a_norm.weight",
        "blk.0.attn_kv_a_norm.weight"
    };
    for (const char* n : names) {
        auto ref = index.Find(n);
        if (ref) {
            printf("%s: dims=[", n);
            for (size_t i = 0; i < ref->shape.size(); ++i) {
                printf("%llu%s", (unsigned long long)ref->shape[i], (i+1 < ref->shape.size()) ? ", " : "");
            }
            printf("] ggmlType=%u byteSize=%llu\n", ref->ggmlType, (unsigned long long)ref->byteSize);
        } else {
            printf("%s: NOT FOUND\n", n);
        }
    }
    return 0;
}
