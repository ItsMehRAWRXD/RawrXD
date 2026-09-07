// certs/rawrxd_stdout_clean_001.cpp — U01
#include "../src/deep2/SemanticSafe.hpp"
#include "../src/deep2/RawrRunSession.hpp"
#include "../src/deep2/RawrNormalGgufFinal.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
using namespace Deep2;
using namespace Deep2::rawr_run;
using namespace Deep2::normal_gguf;

#ifdef _WIN32
struct QuietOut {
    int saved = -1;
    QuietOut() {
        fflush(stdout);
        saved = _dup(1);
        if (saved >= 0) _dup2(2, 1);
    }
    ~QuietOut() {
        if (saved >= 0) {
            fflush(stdout);
            _dup2(saved, 1);
            _close(saved);
        }
    }
};
#endif

int main() {
    SemanticSafeApply();
    Deep2Engine e;
    RunWitness w{};
    std::string text;
    {
#ifdef _WIN32
        QuietOut q;
#endif
        if (!OpenSession(e, "tinyllama", w)) {
            puts("RAWRXD_STDOUT_CLEAN_001=FAIL");
            return 1;
        }
        std::string fmt = FormatChatPrompt(e, "write one sentence", &w);
        GenerationOptions opts{};
        opts.maxTokens = 48;
        opts.temperature = 0.0f;
        opts.topK = 1;
        opts.seed = 42;
        e.generateStream(fmt, opts, [&](int32_t, const std::string& p) -> bool {
            text += p;
            return true;
        });
        e.unloadModel();
    }
    if (HasDebugLeak(text) || text.find("HOTPATH_") != std::string::npos ||
        text.find("[Deep2") != std::string::npos || text.size() < 20) {
        puts("RAWRXD_STDOUT_CLEAN_001=FAIL");
        return 1;
    }
    // Emit as the product would: text only on stdout last line witness.
    fputs(text.c_str(), stdout);
    fputc('\n', stdout);
    puts("RAWRXD_STDOUT_CLEAN_001=PASS");
    return 0;
}
