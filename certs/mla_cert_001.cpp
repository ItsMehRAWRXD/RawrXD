// certs/mla_cert_001.cpp — MLA-CERT-001 production computeAttention seal
#include "../src/deep2/Deep2Engine.h"
#include "../src/deep2/MlaCertAuthority.hpp"
#include "../src/deep2/RawrRunSession.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
using namespace Deep2::rawr_run;

static const char* kEvid = "G:\\~dev\\rawrxd\\evidence\\MLA_CERT_001";

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA", nullptr);
    _putenv_s("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA", "");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(kEvid, nullptr);
#endif
    const char* unsafe = std::getenv("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA");
    const int unsafeEnv = (unsafe && unsafe[0] && unsafe[0] != '0') ? 1 : 0;
    MlaCertAuthority::Reset();
    Deep2Engine e;
    RunWitness w{};
    int loadOk = 0, genOk = 0;
    if (!unsafeEnv && OpenSession(e, "kimi-k2", w)) {
        loadOk = 1;
        auto ids = e.tokenize("hello");
        if (ids.empty()) ids.push_back(1);
        std::vector<int> out(1, 0);
        InferenceStats st{};
        genOk = e.generate(ids.data(), ids.size(), out.data(), 1, &st, nullptr) > 0
                    ? 1
                    : 0;
    }
    if (unsafeEnv) MlaCertAuthority::NoteUnsafeEnv();
    auto& a = MlaCertAuthority::W();
    const int pass = (!unsafeEnv && loadOk && genOk &&
                      MlaCertAuthority::ProductSealPass())
                         ? 1
                         : 0;
    FILE* f = fopen((std::string(kEvid) + "\\GATE_STATUS.txt").c_str(), "w");
    auto emit = [&](FILE* o) {
        std::fprintf(o, "MLA_CERT_001=%s\n", pass ? "PASS" : "FAIL");
        std::fprintf(o, "MLA-CERT-001=%s\n", pass ? "PASS" : "FAIL");
        std::fprintf(o, "MLA_REQUIRED=%d\n", a.mlaRequired.load());
        std::fprintf(o, "MLA_CERTIFIED=%d\n", a.mlaCertified.load());
        std::fprintf(o, "MLA_FORWARD_ENTERED=%d\n", a.mlaForwardEntered.load());
        std::fprintf(o, "MLA_ATTENTION_COMPLETE_USED=%d\n",
                     a.mlaAttentionCompleteUsed.load());
        std::fprintf(o, "UNSAFE_MLA_USED=%d\n", a.unsafeMlaUsed.load());
        std::fprintf(o, "FALLBACK_ATTENTION_USED=%d\n",
                     a.fallbackAttentionUsed.load());
        std::fprintf(o, "STUB_ATTENTION_USED=%d\n", a.stubAttentionUsed.load());
        std::fprintf(o, "OUTPUT_FINITE=%d\n", a.outputFinite.load());
        std::fprintf(o, "OUTPUT_SHAPE_VALID=%d\n", a.outputShapeValid.load());
        std::fprintf(o, "PRODUCTION_DECODE_PATH=%d\n",
                     a.productionDecodePath.load());
        std::fprintf(o, "LOAD_OK=%d GEN_OK=%d SHARDS=%d USE_MLA=%d\n", loadOk,
                     genOk, w.shardsDiscovered, e.getConfig().useMLA ? 1 : 0);
    };
    if (f) {
        emit(f);
        fclose(f);
    }
    emit(stdout);
    return pass ? 0 : 1;
}
