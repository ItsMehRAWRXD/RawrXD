// nemotron_nano_poem_smoke.cpp — real Deep2 generateStream poem + wall TPS
#include "../src/deep2/RawrRunSession.hpp"
#include "../src/deep2/SemanticSafe.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <direct.h>
#endif

using namespace Deep2;
using namespace Deep2::rawr_run;

static const char* kModel =
    "F:\\OllamaModels\\NVIDIA-Nemotron-3-Nano-4B-GGUF\\"
    "NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf";
static const char* kPrompt =
    "Write a short poem titled Budget Formulation Wall. "
    "Theme: token generation fold — where budget meets live token "
    "throughput. Exactly 8-12 lines. No preamble, poem only.";
static const char* kEvid =
    "G:\\~dev\\rawrxd\\evidence\\NEMOTRON_NANO_POEM_001";

int main() {
#ifdef _WIN32
    // Force Nemotron — do not inherit K2 shard hijack.
    SetEnvironmentVariableA("DEEP2_K2_SHARD_DIR", nullptr);
    SetEnvironmentVariableA("DEEP2_REAL_K2_GENERATE", "0");
    _putenv_s("DEEP2_REAL_K2_GENERATE", "0");
    _putenv_s("RAWRXD_NO_TP", "1");
    _putenv_s("RAWRXD_GREEDY", "1");
    _putenv_s("TPS_LIMIT", "NONE");
    _putenv_s("FULL_MODEL_RESIDENCY_REQUIRED", "0");
    _putenv_s("DEEP2_TPS_DISPLAY_SCALE", "1");
    // Nemotron-H hybrid: approximate SSM layers (scaffolding, not MLA-CERT).
    SetEnvironmentVariableA("RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM", "1");
    _putenv_s("RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM", "1");
    _mkdir("G:\\~dev\\rawrxd\\evidence");
    _mkdir(kEvid);
#endif
    SemanticSafeApply();

    Deep2Engine e;
    RunWitness w{};
    if (!OpenSession(e, kModel, w)) {
        std::fprintf(stderr, "LOAD_FAIL path=%s\n", kModel);
        return 1;
    }
    std::fprintf(stderr, "MODEL=%s\nPATH=%s\nARCH_PATH=REAL_DEEP2\n",
                 w.modelName.c_str(), w.modelPath.c_str());

    GenerationOptions opts{};
    opts.maxTokens = 160;
    opts.temperature = 0.7f;
    opts.topK = 40;
    opts.seed = 7;
    e.clearCancel();
    const std::string formatted = FormatChatPrompt(e, kPrompt, &w);
    std::string text;
    uint32_t n = 0;
    const auto t0 = std::chrono::steady_clock::now();
    auto gr = e.generateStream(formatted, opts,
                               [&](int32_t, const std::string& piece) -> bool {
                                   text += piece;
                                   ++n;
                                   return true;
                               });
    const auto t1 = std::chrono::steady_clock::now();
    const double wallMs =
        std::chrono::duration<double, std::milli>(t1 - t0).count();
    const double wallTps =
        (n > 0 && wallMs > 0.0) ? (1000.0 * (double)n / wallMs) : 0.0;

    FILE* f = std::fopen((std::string(kEvid) + "\\POEM.txt").c_str(), "w");
    if (f) {
        std::fprintf(f, "%s\n", text.c_str());
        std::fclose(f);
    }
    FILE* g = std::fopen((std::string(kEvid) + "\\SUMMARY.txt").c_str(), "w");
    if (g) {
        std::fprintf(g, "MODEL=NVIDIA-Nemotron-3-Nano-4B-Q8_0\n");
        std::fprintf(g, "PATH=%s\n", w.modelPath.c_str());
        std::fprintf(g, "REAL_GENERATE_STREAM=%d\n", n > 0 ? 1 : 0);
        std::fprintf(g, "GENERATED_TOKENS=%u\n", n);
        std::fprintf(g, "WALL_MS=%.3f\n", wallMs);
        std::fprintf(g, "WALL_TPS=%.3f\n", wallTps);
        std::fprintf(g, "COMPLETED=%d\n", gr.completed ? 1 : 0);
        std::fprintf(g, "K2_HIJACK=0\n");
        std::fprintf(g, "--- POEM ---\n%s\n--- END ---\n", text.c_str());
        std::fclose(g);
    }
    std::printf("WALL_TPS=%.3f TOKENS=%u\n--- POEM ---\n%s\n--- END ---\n",
                wallTps, n, text.c_str());
    e.unloadModel();
    return n > 0 ? 0 : 1;
}
