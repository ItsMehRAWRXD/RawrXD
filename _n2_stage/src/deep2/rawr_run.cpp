// rawr_run.cpp
// CLI entry point for: rawr run <model> [--tokens N] [--vulkan] <prompt...>
//
// Usage:
//   rawrxd_cli.exe run <model> <prompt>
//   rawrxd_cli.exe run qwen2.5-coder "audit this codebase for stubs"
//   rawrxd_cli.exe run F:\models\Qwen2.5-Coder-32B-Q4_K_M.gguf "hello"
//   rawrxd_cli.exe run --tokens 256 --vulkan <model> <prompt>
#include "rawr_run.h"
#include "rawrxd_run_modelname_001.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int rawr_run_main(int argc, char** argv) {
    // argv[0] is "run" (already consumed by caller)
    // Expected: [--tokens N] [--vulkan] <model> <prompt words...>

    if (argc < 2) {
        std::fprintf(stderr,
            "Usage: rawr run [--tokens N] [--vulkan] <model> <prompt>\n"
            "\n"
            "  <model>   GGUF path or model name (searched in RAWRXD_MODEL_DIR)\n"
            "  <prompt>  Text prompt (remaining args joined with spaces)\n"
            "\n"
            "Examples:\n"
            "  rawr run qwen2.5-coder \"audit this codebase for stubs\"\n"
            "  rawr run F:\\models\\Qwen2.5-Coder-32B-Q4_K_M.gguf \"hello world\"\n"
            "  rawr run --tokens 512 --vulkan qwen2.5-coder \"explain RoPE\"\n");
        return 1;
    }

    uint32_t maxTokens   = 512;
    bool     vulkan      = false;
    int      argIdx      = 0;

    // Parse flags
    while (argIdx < argc) {
        if (std::strcmp(argv[argIdx], "--tokens") == 0 && argIdx + 1 < argc) {
            maxTokens = static_cast<uint32_t>(std::atoi(argv[argIdx + 1]));
            argIdx += 2;
        } else if (std::strcmp(argv[argIdx], "--vulkan") == 0) {
            vulkan = true;
            ++argIdx;
        } else if (std::strcmp(argv[argIdx], "--no-vulkan") == 0) {
            vulkan = false;
            ++argIdx;
        } else {
            break;
        }
    }

    if (argIdx >= argc) {
        std::fprintf(stderr, "[rawr run] ERROR: no model specified after flags\n");
        return 1;
    }

    const std::string model = argv[argIdx++];

    if (argIdx >= argc) {
        std::fprintf(stderr, "[rawr run] ERROR: no prompt specified\n");
        return 1;
    }

    // Join remaining args as prompt
    std::string prompt;
    for (int i = argIdx; i < argc; ++i) {
        if (i > argIdx) prompt += ' ';
        prompt += argv[i];
    }

    return rawrxd_run_modelname_001(model.c_str(), prompt.c_str(),
                                     maxTokens, vulkan);
}

// Standalone executable entry point
int main(int argc, char** argv) {
    // argv[0] is the executable name; shift so argv[0] is treated as "run"
    if (argc < 2) {
        std::fprintf(stderr,
            "Usage: rawr <model> <prompt>\n"
            "  or:  rawr --tokens N [--vulkan] <model> <prompt>\n");
        return 1;
    }
    // If first arg is literally "run", consume it (for compatibility)
    int offset = 0;
    if (std::strcmp(argv[1], "run") == 0) {
        offset = 1;
    }
    int subArgc = argc - 1 - offset;
    char** subArgv = argv + 1 + offset;
    return rawr_run_main(subArgc, subArgv);
}
