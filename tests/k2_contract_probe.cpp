#include <string>
#include <unordered_map>

#include "../src/deep2/KimiK2Config.hpp"

int main() {
    std::unordered_map<std::string, std::string> meta = {
        {"general.architecture", "kimi_k2"},
        {"llama.attention.head_count", "128"},
        {"llama.attention.head_count_kv", "8"},
        {"llama.embedding_length", "7168"},
        {"llama.block_count", "61"},
        {"llama.feed_forward_length", "2048"},
        {"llama.vocab_size", "163840"},
        {"llama.context_length", "262144"},
        {"llama.expert_count", "384"},
        {"llama.expert_used_count", "8"},
        {"llama.kv_lora_rank", "512"},
        {"llama.qk_rope_head_dim", "64"},
        {"llama.qk_nope_head_dim", "128"},
        {"llama.v_head_dim", "128"},
    };

    Deep2::KimiK2Config cfg = Deep2::ParseKimiK2ConfigFromGGUF(meta);
    std::string err;
    if (!Deep2::ValidateKimiK2Config(cfg, err)) {
        return 2;
    }
    return cfg.numLayers == 61 ? 0 : 1;
}
