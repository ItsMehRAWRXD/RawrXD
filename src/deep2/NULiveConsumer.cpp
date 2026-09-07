// NULiveConsumer.cpp — DEEP2_LIVE_NU + parity auth → NU_GemvGpu
#include "NULiveConsumer.hpp"
#include "NUGemv.hpp"
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

namespace Deep2 {
namespace {
NULiveStats g_st;

static bool EnvIs1(const char* k) {
    const char* e = std::getenv(k);
    return e && e[0] == '1' && e[1] == '\0';
}

static bool ParityWitnessOk() {
    const char* path =
        "G:\\~dev\\rawrxd\\evidence\\NU_GEMV_PARITY_001\\GATE_STATUS.txt";
    std::ifstream in(path);
    if (!in) return false;
    std::string all((std::istreambuf_iterator<char>(in)),
                    std::istreambuf_iterator<char>());
    const bool pass = all.find("NU_GEMV_PARITY_001=PASS") != std::string::npos;
    const bool auth =
        all.find("LIVE_NU_CONSUME_AUTHORIZED=1") != std::string::npos;
    return pass && auth;
}
} // namespace

void NU_LiveStatsReset() { g_st = {}; }
const NULiveStats& NU_LiveStatsGet() { return g_st; }

bool NU_LiveWanted() { return EnvIs1("DEEP2_LIVE_NU"); }

bool NU_LiveAuthorized() {
    const char* e = std::getenv("DEEP2_LIVE_NU_AUTH");
    if (e && e[0] == '0' && e[1] == '\0') return false; // explicit deny
    if (e && e[0] == '1' && e[1] == '\0') return true;
    return ParityWitnessOk();
}

bool NU_LiveActive() { return NU_LiveWanted() && NU_LiveAuthorized(); }

bool NU_LiveConsumeGemv(CPUInference::VulkanCompute& vc,
                        const uint8_t* nu, size_t nuBytes,
                        const float* x, float* y,
                        uint32_t rows, uint32_t cols,
                        uint64_t cacheKey) {
    if (!NU_LiveWanted()) { ++g_st.rejectOff; return false; }
    if (!NU_LiveAuthorized()) { ++g_st.rejectNoAuth; return false; }
    if (!NU_GemvGpu(vc, nu, nuBytes, x, y, rows, cols, cacheKey)) {
        ++g_st.fail;
        return false;
    }
    ++g_st.ops;
    g_st.bytes += nuBytes;
    return true;
}

void NU_LiveEmit(FILE* f) {
    if (!f) return;
    fprintf(f, "LIVE_NU_WANTED=%u\n", NU_LiveWanted() ? 1u : 0u);
    fprintf(f, "LIVE_NU_AUTHORIZED=%u\n", NU_LiveAuthorized() ? 1u : 0u);
    fprintf(f, "LIVE_NU_ACTIVE=%u\n", NU_LiveActive() ? 1u : 0u);
    fprintf(f, "LIVE_NU_CONSUME_OPS=%llu\n", (unsigned long long)g_st.ops);
    fprintf(f, "LIVE_NU_CONSUME_BYTES=%llu\n", (unsigned long long)g_st.bytes);
    fprintf(f, "LIVE_NU_REJECT_OFF=%llu\n", (unsigned long long)g_st.rejectOff);
    fprintf(f, "LIVE_NU_REJECT_NO_AUTH=%llu\n",
            (unsigned long long)g_st.rejectNoAuth);
    fprintf(f, "LIVE_NU_FAIL=%llu\n", (unsigned long long)g_st.fail);
}

} // namespace Deep2
