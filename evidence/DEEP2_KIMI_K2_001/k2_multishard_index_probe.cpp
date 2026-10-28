// Standalone probe: 13/13 shards + tensor index + 0 duplicates + bounds.
#include "K2GlobalTensorIndex.hpp"
#include "KimiK2Config.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    const char* dir =
        (argc > 1) ? argv[1]
                   : "F:/OllamaModels/Kimi-K2-Instruct-0905-GGUF/Q4_K_M";
    const size_t expectTensors =
        (argc > 2) ? static_cast<size_t>(std::strtoull(argv[2], nullptr, 10))
                   : 1096ull;

    Deep2::KimiK2Config cfg{};
    cfg.valid = true;
    Deep2::GlobalTensorIndex idx;
    std::string err;
    if (!idx.BuildFromShardDirectory(dir, cfg, err)) {
        std::fprintf(stderr, "BUILD_FAIL=%s\n", err.c_str());
        std::fprintf(stderr, "DISPOSITION=FAIL\nPROMOTE=0\n");
        return 1;
    }
    std::string verr;
    if (!idx.Validate(verr)) {
        std::fprintf(stderr, "VALIDATE_FAIL=%s\n", verr.c_str());
        std::fprintf(stderr, "DISPOSITION=FAIL\nPROMOTE=0\n");
        return 2;
    }

    const size_t shards = idx.TotalShards();
    const size_t tensors = idx.TotalTensors();
    const bool shardsOk = (shards == 13);
    const bool tensorsOk = (tensors == expectTensors);
    std::fprintf(stderr,
                 "SHARDS=%zu/13 TENSORS=%zu/%zu BOUNDS=PASS DUPLICATES=0\n"
                 "TOTAL_BYTES=%llu\n",
                 shards, tensors, expectTensors,
                 (unsigned long long)idx.TotalBytes());
    const bool pass = shardsOk && tensorsOk;
    std::fprintf(stderr, "DISPOSITION=%s\nPROMOTE=0\n",
                 pass ? "PASS" : "FAIL");
    return pass ? 0 : 3;
}
