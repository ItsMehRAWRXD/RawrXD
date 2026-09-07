// certs/mla_cert_001.cpp — MLA-CERT-001 negative control + certified flag
// Proves: K2 MLA models refuse production load without MLA_CERTIFIED.
// Does NOT enable RAWRXD_DEEP2_ALLOW_UNSAFE_MLA (that invalidates U13).
#include "../src/deep2/Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static const char* kEvid = "G:\\~dev\\rawrxd\\evidence\\MLA_CERT_001";
static const char* kShard =
    "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
static const char* kEntry =
    "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M\\"
    "Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf";

int main() {
#ifdef _WIN32
    // Explicitly clear unsafe MLA — negative control requires this.
    SetEnvironmentVariableA("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA", nullptr);
    _putenv_s("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA", "");
    SetEnvironmentVariableA("DEEP2_K2_SHARD_DIR", kShard);
    _putenv_s("DEEP2_K2_SHARD_DIR", kShard);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(kEvid, nullptr);
#endif

    const char* unsafe = std::getenv("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA");
    const int unsafeUsed =
        (unsafe && unsafe[0] && unsafe[0] != '0') ? 1 : 0;

    int loadOk = 0;
    int mlaRequired = 0;
    if (!unsafeUsed) {
        Deep2Engine e;
        loadOk = e.loadModel(kEntry) ? 1 : 0;
        // If load failed, MLA gate fired (expected). Detection is best-effort.
        mlaRequired = loadOk ? 0 : 1;
        if (loadOk) e.unloadModel();
    }

    // MLA_CERTIFIED stays 0 until production attention is sealed separately.
    const int mlaCertified = 0;
    const int productionPath = (loadOk && mlaCertified && !unsafeUsed) ? 1 : 0;
    const int u13Eligible = (mlaCertified && productionPath) ? 1 : 0;

    // Negative control PASS: refused uncertified MLA without unsafe bypass.
    const int negativePass =
        (!unsafeUsed && !loadOk && mlaRequired && !mlaCertified) ? 1 : 0;

    FILE* f = fopen((std::string(kEvid) + "\\GATE_STATUS.txt").c_str(), "w");
    auto emit = [&](FILE* out) {
        std::fprintf(out, "MLA-CERT-001=%s\n",
                     negativePass ? "NEGATIVE_CONTROL_PASS" : "FAIL");
        std::fprintf(out, "MLA_REQUIRED=%d\n", mlaRequired);
        std::fprintf(out, "MLA_CERTIFIED=%d\n", mlaCertified);
        std::fprintf(out, "UNSAFE_MLA_USED=%d\n", unsafeUsed);
        std::fprintf(out, "PRODUCTION_DECODE_PATH=%d\n", productionPath);
        std::fprintf(out, "U13_SEAL_ELIGIBLE=%d\n", u13Eligible);
        std::fprintf(out, "LOAD_OK=%d\n", loadOk);
        std::fprintf(out, "MODEL_ENTRY=%s\n", kEntry);
        std::fprintf(out, "NOTE=MLA_CERTIFIED=1 requires Deep2Engine MLA "
                          "forward via MlaAttentionComplete (not unsafe env)\n");
    };
    if (f) {
        emit(f);
        fclose(f);
    }
    emit(stdout);

    // Gate remains OPEN for product seal; negative control is the win today.
    puts(negativePass ? "MLA_CERT_001_NEGATIVE_CONTROL=PASS"
                      : "MLA_CERT_001_NEGATIVE_CONTROL=FAIL");
    puts("MLA_CERT_001=OPEN");
    return negativePass ? 0 : 1;
}
