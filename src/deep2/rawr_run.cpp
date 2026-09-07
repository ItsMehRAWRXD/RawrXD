// rawr_run.cpp — legacy single-command entry (disabled when agentic CLI linked)
#if defined(RAWR_AGENTIC_CLI)
int rawr_run_legacy_main_disabled = 0;
#else
#include "RawrRunSession.hpp"
#include "SemanticSafe.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
using namespace Deep2;
using namespace Deep2::rawr_run;

static void Usage() {
    fprintf(stderr, "Usage: rawr run <modelname> [prompt]\n");
}

#ifdef _WIN32
struct StdoutToStderr {
    int saved = -1;
    StdoutToStderr() {
        fflush(stdout);
        saved = _dup(1);
        if (saved >= 0) _dup2(2, 1);
    }
    ~StdoutToStderr() {
        if (saved >= 0) {
            fflush(stdout);
            _dup2(saved, 1);
            _close(saved);
            saved = -1;
        }
    }
};
#endif

int main(int argc, char** argv) {
    if (argc < 3 || std::strcmp(argv[1], "run") != 0) {
        Usage();
        return 1;
    }
    SemanticSafeApply();

    const char* alias = argv[2];
    std::string prompt = "Hello";
    if (argc > 3) {
        prompt.clear();
        for (int i = 3; i < argc; ++i) {
            if (i > 3) prompt.push_back(' ');
            prompt += argv[i];
        }
    }

    std::string acc;
    {
#ifdef _WIN32
        StdoutToStderr quiet;
#endif
        Deep2Engine engine;
        RunWitness w{};
        if (!OpenSession(engine, alias, w)) {
            fprintf(stderr, "rawr: failed to resolve/load '%s'\n", alias);
            return 2;
        }
        fprintf(stderr, "MODEL=%s\nPATH=%s\nOLLAMA_USED=0\nNETWORK_USED=0\n",
                w.modelName.c_str(), w.modelPath.c_str());
        const std::string formatted = FormatChatPrompt(engine, prompt, &w);
        GenerationOptions opts{};
        opts.maxTokens = 256;
        opts.temperature = 0.0f;
        opts.topK = 1;
        opts.seed = 42;
        engine.clearCancel();
        engine.generateStream(formatted, opts,
                              [&](int32_t, const std::string& piece) -> bool {
                                  acc += piece;
                                  return true;
                              });
        engine.unloadModel();
    } // engine dtor + quiet restore

    fputs(acc.c_str(), stdout);
    fputc('\n', stdout);
    fflush(stdout);
    return 0;
}
#endif // RAWR_AGENTIC_CLI
