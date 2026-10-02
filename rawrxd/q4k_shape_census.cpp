// q4k_shape_census.cpp
// Answers the limitation attached to RAWRXD_Q4K_GEMV_PARITY_001: can a set of
// all-square tensors discriminate row-major from its transpose? And which
// dimension convention does each real tensor actually satisfy?
#include "gguf_loader.hpp"
#include <cstdio>
#include <map>
#include <string>
using namespace rawrxd;

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) { std::printf("LOAD=FAIL\n"); return 2; }
    const GGUFModel* m = loader.GetModel();

    size_t sq = 0, nsq = 0, convShape0 = 0, convShape1 = 0, neither = 0;
    std::map<std::string, size_t> shapes;
    for (const auto& t : m->tensors) {
        if (t.ggml_type != GGMLType::Q4_K || t.shape.size() != 2) continue;
        const size_t a = (size_t)t.shape[0], b = (size_t)t.shape[1];
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%zux%zu", a, b);
        shapes[buf]++;
        if (a == b) ++sq; else ++nsq;
        // cols=a convention: a contiguous, b rows
        const bool okA = (a % 256 == 0) && (b * (a / 256) * 144 == t.byte_size);
        const bool okB = (b % 256 == 0) && (a * (b / 256) * 144 == t.byte_size);
        if (okA) ++convShape0;
        if (okB) ++convShape1;
        if (!okA && !okB) ++neither;
    }
    std::printf("Q4K_TOTAL=%zu  SQUARE=%zu  NONSQUARE=%zu\n", sq + nsq, sq, nsq);
    std::printf("CONVENTION_cols=shape0=%zu   cols=shape1=%zu   neither=%zu\n",
                convShape0, convShape1, neither);
    std::printf("\n; distinct Q4_K shapes present ---\n");
    for (const auto& kv : shapes) std::printf("  %-20s x%zu\n", kv.first.c_str(), kv.second);
    return 0;
}