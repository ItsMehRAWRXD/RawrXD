#include <cstdio>
#include "universal_gguf.hpp"
using namespace RawrXD::Deep2::Universal;
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    const IngestReport& r = Ingest(argv[1], false);
    std::printf("spec: kv_lora_rank=%llu key_length=%llu value_length=%llu\n",
        (unsigned long long)r.spec.kv_lora_rank,
        (unsigned long long)r.spec.key_length,
        (unsigned long long)r.spec.value_length);
    std::printf("heads=%llu heads_kv=%llu embd=%llu\n",
        (unsigned long long)r.spec.heads,
        (unsigned long long)r.spec.heads_kv,
        (unsigned long long)r.spec.embd);
    for (const auto& t : r.tensors) {
        if (t.block == 0 && (t.name.find("kv_a") != std::string::npos ||
                             t.name.find("kv_b") != std::string::npos ||
                             t.name.find("attn_q") != std::string::npos ||
                             t.name.find("attn_output") != std::string::npos ||
                             t.name.find("ffn_gate") != std::string::npos)) {
            std::printf("  %-34s dims=[", t.name.c_str());
            for (auto d : t.dims) std::printf("%llu ", (unsigned long long)d);
            std::printf("] type=%u bytes=%zu\n", (unsigned)t.gguf_type, t.bytes);
        }
    }
    return 0;
}
