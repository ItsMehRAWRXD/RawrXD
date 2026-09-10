// rawr_run.cpp — product generate via ProductRunDecode
#if defined(RAWR_AGENTIC_CLI)
int rawr_run_legacy_main_disabled = 0;
#else
#include "lavapath/ProductRun.hpp"
#include "lavapath/ProductStreamerPrep.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static void Usage() {
    fprintf(stderr, "Usage: rawr run <modelname> [prompt]\n");
}

int main(int argc, char** argv) {
    if (argc < 3 || std::strcmp(argv[1], "run") != 0) {
        Usage();
        return 1;
    }
    if (!Deep2::ProductStreamerPrep()) return 1;
    const char* alias = argv[2];
    std::string prompt = "Hello";
    if (argc > 3) {
        prompt.clear();
        for (int i = 3; i < argc; ++i) {
            if (i > 3) prompt.push_back(' ');
            prompt += argv[i];
        }
    }
    uint32_t maxTok = 8u;
    if (const char* e = std::getenv("RAWR_MAX_TOKENS")) {
        const int n = std::atoi(e);
        if (n > 0) maxTok = (uint32_t)n;
    }
    rawr::product_run::Request req{};
    req.modelAlias = alias;
    req.prompt = prompt.c_str();
    req.maxTokens = maxTok;
    auto pr = rawr::product_run::ProductRun(req);
    fputs(pr.text.c_str(), stdout);
    fputc('\n', stdout);
    fflush(stdout);
    return (pr.firstToken && pr.generatedTokens > 0) ? 0 : 3;
}
#endif
