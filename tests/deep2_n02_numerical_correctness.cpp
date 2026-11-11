// N02 numerical correctness — tip Deep2Engine, real GGUF only.
#include "Deep2Engine.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    const char* gguf = (argc > 1 && argv[1] && argv[1][0])
                           ? argv[1]
                           : "F:\\ollamamodels\\n4-tiny-oracle.gguf";
    const char* prompt = (argc > 2 && argv[2] && argv[2][0]) ? argv[2] : "Hi";
    const size_t maxTok = (argc > 3) ? (size_t)std::atoi(argv[3]) : 8;

    Deep2::Deep2Engine eng;
    Deep2::EngineConfig cfg{};
    if (!eng.initialize(cfg)) {
        std::printf("INIT_FAIL=1\n");
        return 2;
    }
    if (!eng.loadModel(gguf)) {
        std::printf("LOAD_FAIL=1 MODEL=%s\n", gguf);
        return 3;
    }
    std::printf("MODEL=%s\n%s\n", gguf, eng.kvGeometryReceipt().c_str());

    auto ids = eng.tokenize(prompt);
    if (ids.empty()) {
        std::printf("TOKENIZE_FAIL=1\n");
        return 4;
    }
    const double div =
        eng.prefillParityReport(ids.data(), ids.size(), /*chunk*/ 4, stdout);
    std::printf("PREFILL_PARITY_MAX_REL=%g\n", div);
    if (!(div >= 0.0) || !std::isfinite(div) || div > 1e-3) {
        std::printf("PREFILL_PARITY_FAIL=1\nCERTIFIED=0\nPROMOTE=0\n");
        return 5;
    }

    auto greedy = [&](std::vector<int32_t>& out) -> bool {
        eng.resetInferenceState();
        Deep2::GenerationOptions opts;
        opts.maxTokens = maxTok;
        opts.temperature = 0.0f;
        opts.topP = 1.0f;
        opts.topK = 1;
        eng.configureGeneration(opts);
        out.clear();
        auto gr = eng.generateStream(prompt, opts,
                                     [&](int32_t tid, const std::string&) {
                                         out.push_back(tid);
                                         return true;
                                     });
        return gr.generatedTokens > 0 && out.size() == gr.generatedTokens;
    };

    std::vector<int32_t> a, b;
    if (!greedy(a) || !greedy(b)) {
        std::printf("GREEDY_FAIL=1\nCERTIFIED=0\nPROMOTE=0\n");
        return 6;
    }
    std::printf("TOKEN_IDS_A=");
    for (size_t i = 0; i < a.size(); ++i)
        std::printf("%s%d", i ? "," : "", (int)a[i]);
    std::printf("\nTOKEN_IDS_B=");
    for (size_t i = 0; i < b.size(); ++i)
        std::printf("%s%d", i ? "," : "", (int)b[i]);
    std::printf("\n");
    const int match = (a == b) ? 1 : 0;
    std::printf("TOKEN_ID_MATCH=%d GENERATED=%zu PREFILL_PARITY_OK=1\n", match,
                a.size());
    std::printf("CERTIFIED=0\nPROMOTE=0\nTIP_CLIMB=HOLD\n");
    return match ? 0 : 7;
}
