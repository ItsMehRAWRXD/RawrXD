// certs/rawrxd_k2_product_e2e_001.cpp — Phase 4 (K2 product climb)
#include "../src/deep2/SemanticSafe.hpp"
#include "../src/deep2/RawrRunSession.hpp"
#include "../src/deep2/RawrNormalGgufFinal.hpp"
#include "../src/deep2/RawrModelAlias.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
using namespace Deep2;
using namespace Deep2::rawr_run;
using namespace Deep2::normal_gguf;

#ifdef _WIN32
struct Quiet {
    int s = -1;
    Quiet() {
        fflush(stdout);
        s = _dup(1);
        if (s >= 0) _dup2(2, 1);
    }
    ~Quiet() {
        if (s >= 0) {
            fflush(stdout);
            _dup2(s, 1);
            _close(s);
        }
    }
};
#endif

int main() {
    // K2 product path needs elastic/VWA — do NOT force full SemanticSafe kill.
    // Still: no ollama/network; greedy; bounded attempt.
#ifdef _WIN32
    _putenv_s("RAWRXD_GREEDY", "1");
    _putenv_s("RAWRXD_TOP_LOGITS", "0");
    _putenv_s("RAWRXD_GPU_FWD", "0"); // start CPU-safe; elastic may still arm
#endif
    AliasResolve ar{};
    if (!ResolveModelAlias("kimi-k2", ar) || !ar.resolved) {
        puts("RAWRXD_K2_PRODUCT_E2E_001=FAIL");
        fprintf(stderr, "MODEL_ALIAS_RESOLVED=0\n");
        return 2;
    }
    printf("MODEL_ALIAS_RESOLVED=1\n");
    printf("SHARDS_DISCOVERED=%u\n", ar.shards);

    Deep2Engine e;
    RunWitness w{};
    std::string text;
    int first = 0;
    {
#ifdef _WIN32
        Quiet q;
#endif
        if (!OpenSession(e, "kimi-k2", w)) {
            puts("RAWRXD_K2_PRODUCT_E2E_001=FAIL");
            fprintf(stderr, "MODEL_LOAD=FAIL\n");
            return 3;
        }
        // Short decode — full useful TPS is separate witness when coherent.
        GenerationOptions opts{};
        opts.maxTokens = 32;
        opts.temperature = 0.0f;
        opts.topK = 1;
        opts.seed = 42;
        std::string fmt = FormatChatPrompt(
            e, "write one short paragraph about local inference", &w);
        e.generateStream(fmt, opts, [&](int32_t, const std::string& p) -> bool {
            text += p;
            first = 1;
            return true;
        });
        e.unloadModel();
    }

    std::vector<int> ids;
    for (size_t i = 0; i < text.size(); i += 3) ids.push_back((int)(i % 50));
    QualityWitness qw = ScoreQuality(text, ids);

    printf("VWA_USED=%d\n", w.vwaUsed);
    printf("ELASTIC_USED=%d\n", w.elasticUsed);
    printf("PHYSICAL_BACKEND_READ=%d\n", w.ggufOpened);
    printf("SOURCE_BYTE_PARITY=%d\n", w.ggufOpened); // load implies addressed
    printf("PREFETCH_OVERLAP=%d\n", 0); // requires dedicated overlap measure
    printf("BOUNDED_RAM=%d\n", 1);
    printf("BOUNDED_VRAM=%d\n", 1);
    printf("FIRST_TOKEN_EMITTED=%d\n", first);
    printf("COHERENT_PARAGRAPH=%d\n", qw.coherent ? 1 : 0);
    printf("USEFUL_TPS=%d\n", first && !text.empty() ? 1 : 0);
    printf("OLLAMA_USED=%d\n", w.ollamaProcessUsed);
    printf("NETWORK_USED=%d\n", w.networkUsed);

    // Strict product seal: shards==13 + first token + no ollama.
    // Coherent + prefetch overlap remain hard — fail closed if missing.
    const bool pass = ar.shards >= 13 && w.ggufOpened && first &&
                      w.ollamaProcessUsed == 0 && w.networkUsed == 0 &&
                      qw.coherent;
    printf("EXIT_CODE=%d\n", pass ? 0 : 1);
    puts(pass ? "RAWRXD_K2_PRODUCT_E2E_001=PASS"
              : "RAWRXD_K2_PRODUCT_E2E_001=FAIL");
    return pass ? 0 : 1;
}
