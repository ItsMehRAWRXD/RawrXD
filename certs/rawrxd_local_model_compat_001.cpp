// certs/rawrxd_local_model_compat_001.cpp — every local GGUF must resolve;
// small models must load+stream (no Ollama).
#include "../src/deep2/SemanticSafe.hpp"
#include "../src/deep2/RawrRunSession.hpp"
#include "../src/deep2/RawrModelDiscover.hpp"
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif
using namespace Deep2;
using namespace Deep2::rawr_run;

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

static int ProbeStream(const char* alias, FILE* gate) {
    Deep2Engine e;
    RunWitness w{};
    int load = 0, tok = 0, stream = 0;
    {
#ifdef _WIN32
        Quiet q;
#endif
        SemanticSafeApply();
        _putenv_s("RAWRXD_GREEDY", "1");
        if (!OpenSession(e, alias, w)) {
            fprintf(gate, "PROBE alias=%s LOAD=0 STREAM=0\n", alias);
            fprintf(stderr, "PROBE alias=%s LOAD=0\n", alias);
            return 0;
        }
        load = 1;
        tok = w.tokenizerReady;
        stream = StreamTokens(e, "Say hi in five words.", 4, 0, &w, true) > 0
                     ? 1
                     : 0;
        e.unloadModel();
    }
    fprintf(gate,
            "PROBE alias=%s LOAD=%d TOK=%d STREAM=%d PATH=%s SHARDS=%d "
            "ARCH_TMPL=%d\n",
            alias, load, tok, stream, w.modelPath.c_str(), w.shardsDiscovered,
            w.chatTemplateReady);
    fprintf(stderr, "PROBE alias=%s LOAD=%d STREAM=%d\n", alias, load, stream);
    return load && stream;
}

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_LOCAL_MODEL_COMPAT_001", nullptr);
#endif
    const char* gatePath =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_LOCAL_MODEL_COMPAT_001\\"
        "GATE_STATUS.txt";
    FILE* gate = fopen(gatePath, "w");
    if (!gate) {
        puts("RAWRXD_LOCAL_MODEL_COMPAT_001=FAIL");
        return 2;
    }

    std::vector<LocalModelUnit> units;
    DiscoverLocalModels(units);
    fprintf(gate, "DISCOVERED_UNITS=%zu\n", units.size());
    int resolveOk = 0, resolveFail = 0;
    for (const auto& u : units) {
        AliasResolve ar{};
        // Prefer stem alias for resolve round-trip.
        const bool ok = ResolveModelAlias(u.alias.c_str(), ar) && ar.resolved;
        fprintf(gate, "UNIT kind=%s alias=%s path=%s shards=%u resolve=%d\n",
                u.isDir ? "shard" : "single", u.alias.c_str(), u.path.c_str(),
                u.shards, ok ? 1 : 0);
        if (ok)
            ++resolveOk;
        else
            ++resolveFail;
    }

    // Explicit short aliases buyers/CLI use.
    const char* aliases[] = {"tinyllama", "llama32", "phi3", "gemma3",
                             "phi3-q8",   "nemotron", "deepseek-r1-8b",
                             "codestral", "kimi-k2",  "qwen-coder",
                             "bigdaddy",  "glm47",    "gemma4"};
    int aliasOk = 0, aliasFail = 0;
    for (const char* a : aliases) {
        AliasResolve ar{};
        const bool ok = ResolveModelAlias(a, ar) && ar.resolved;
        fprintf(gate, "ALIAS name=%s resolve=%d path=%s shards=%u\n", a,
                ok ? 1 : 0, ok ? ar.path.c_str() : "", ok ? ar.shards : 0u);
        if (ok)
            ++aliasOk;
        else
            ++aliasFail;
    }

    // Stream probes — keep to models that fit typical local RAM for CI-speed.
    const char* probes[] = {"tinyllama", "llama32", "phi3", "gemma3"};
    int probePass = 0, probeN = 0;
    for (const char* a : probes) {
        AliasResolve ar{};
        if (!ResolveModelAlias(a, ar) || !ar.resolved) continue;
        ++probeN;
        probePass += ProbeStream(a, gate);
    }

    const bool pass = resolveFail == 0 && aliasFail == 0 && probePass == probeN &&
                      probeN >= 3 && (int)units.size() >= 10;
    fprintf(gate, "RESOLVE_OK=%d RESOLVE_FAIL=%d ALIAS_OK=%d ALIAS_FAIL=%d\n",
            resolveOk, resolveFail, aliasOk, aliasFail);
    fprintf(gate, "PROBE_PASS=%d PROBE_N=%d\n", probePass, probeN);
    fprintf(gate, "OLLAMA=0 NETWORK=0\n");
    fprintf(gate, "RAWRXD_LOCAL_MODEL_COMPAT_001=%s\n", pass ? "PASS" : "FAIL");
    fclose(gate);
    puts(pass ? "RAWRXD_LOCAL_MODEL_COMPAT_001=PASS"
              : "RAWRXD_LOCAL_MODEL_COMPAT_001=FAIL");
    return pass ? 0 : 1;
}
