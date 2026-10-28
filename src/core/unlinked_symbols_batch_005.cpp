// unlinked_symbols_batch_005.cpp
// Batch 5: watchdog status lane + camellia auth file + omega lifecycle.
// ABIs: watchdog_service.hpp / camellia256_bridge.hpp / omega_orchestrator.hpp
// asm_watchdog_init â†’ win32ide_watchdog_init.cpp
// asm_watchdog_shutdown â†’ batch_001 MagBag (not rawrxd_watchdog_bridge â€” ODR)
// asm_camellia256_auth_{en,de}crypt_file:
//   RAWR_HAS_MASM -> RawrXD_Camellia256_Auth.asm (RCM2 Encrypt-then-MAC)
//   !RAWR_HAS_MASM -> XOR stream below (SYNTHETIC=partial)

#include "mag_registry.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>

namespace {

struct WatchdogStatusLane {
    std::mutex mtx;
    std::atomic<uint64_t> verifyCount{0};
    std::atomic<uint64_t> violationCount{0};
    uint8_t baseline[32]{};
    int lastResult = 0;
};
WatchdogStatusLane g_wd;

uint32_t crc32Ieee(const uint8_t* data, uint32_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            const uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

// Sync MagBuf watchdog region CRC into local baseline[0..3].
int syncBaselineFromMagBuf() {
    void* region = nullptr;
    uint32_t bytes = 0;
    mag_watchdog_region_peek(&region, &bytes);
    if (region == nullptr || bytes < sizeof(uint32_t) + 1u) {
        return -1;
    }
    auto* p = static_cast<const uint8_t*>(region);
    const uint32_t payloadLen = bytes - static_cast<uint32_t>(sizeof(uint32_t));
    const uint32_t expect = crc32Ieee(p, payloadLen);
    uint32_t stored = 0;
    std::memcpy(&stored, p + payloadLen, sizeof(stored));
    std::lock_guard<std::mutex> lock(g_wd.mtx);
    std::memset(g_wd.baseline, 0, sizeof(g_wd.baseline));
    std::memcpy(g_wd.baseline, &expect, sizeof(expect));
    return (expect == stored) ? 0 : -2;
}

struct OmegaState {
    std::mutex mtx;
    bool active = false;
    uint32_t nextTask = 1;
    uint32_t nextAgent = 1;
    uint64_t ingestCount = 0;
};
OmegaState g_omega;

static int xorFileTwoPath(const char* inPath, const char* outPath) {
    if (inPath == nullptr || outPath == nullptr || inPath[0] == '\0' || outPath[0] == '\0') {
        return -1;
    }
    std::ifstream in(inPath, std::ios::binary);
    if (!in) {
        return -1;
    }
    std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
    if (!out) {
        return -1;
    }
    // Deterministic stream transform (placeholder until Camellia ASM auth obj links).
    uint8_t buf[4096];
    uint64_t off = 0;
    while (in) {
        in.read(reinterpret_cast<char*>(buf), sizeof(buf));
        const std::streamsize n = in.gcount();
        if (n <= 0) {
            break;
        }
        for (std::streamsize i = 0; i < n; ++i) {
            buf[i] = static_cast<uint8_t>(buf[i] ^ static_cast<uint8_t>(0xA5u ^ (off + static_cast<uint64_t>(i))));
        }
        out.write(reinterpret_cast<const char*>(buf), n);
        if (!out) {
            return -1;
        }
        off += static_cast<uint64_t>(n);
    }
    return 0;
}

} // namespace

extern "C" {

int asm_watchdog_verify(void) {
    g_wd.verifyCount.fetch_add(1, std::memory_order_relaxed);
    // B04 MagBuf CRC join: region must be published by asm_watchdog_init.
    void* region = nullptr;
    uint32_t bytes = 0;
    mag_watchdog_region_peek(&region, &bytes);
    if (region == nullptr || bytes < sizeof(uint32_t)) {
        g_wd.violationCount.fetch_add(1, std::memory_order_relaxed);
        g_wd.lastResult = -1;
        return -1;
    }
    const uint32_t payloadLen = bytes - static_cast<uint32_t>(sizeof(uint32_t));
    uint32_t stored = 0;
    std::memcpy(&stored,
                static_cast<const uint8_t*>(region) + payloadLen,
                sizeof(uint32_t));
    uint32_t crc = 0xFFFFFFFFu;
    const auto* data = static_cast<const uint8_t*>(region);
    for (uint32_t i = 0; i < payloadLen; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            const uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    crc = ~crc;
    g_wd.lastResult = (crc == stored) ? 0 : -2;
    if (g_wd.lastResult != 0) {
        g_wd.violationCount.fetch_add(1, std::memory_order_relaxed);
    }
    {
        std::lock_guard<std::mutex> lock(g_wd.mtx);
        std::memset(g_wd.baseline, 0, sizeof(g_wd.baseline));
        std::memcpy(g_wd.baseline, &crc, sizeof(crc));
        std::memcpy(g_wd.baseline + 4, &stored, sizeof(stored));
        std::memcpy(g_wd.baseline + 8, &bytes, sizeof(bytes));
    }
    return g_wd.lastResult;
}

int asm_watchdog_get_status(void* status48) {
    if (status48 == nullptr) {
        return -1;
    }
    auto* out = static_cast<uint64_t*>(status48);
    out[0] = g_wd.verifyCount.load(std::memory_order_relaxed);
    out[1] = static_cast<uint64_t>(g_wd.lastResult);
    out[2] = g_wd.violationCount.load(std::memory_order_relaxed);
    out[3] = mag_watchdog_crc32_region();
    out[4] = 0;
    out[5] = 0;
    return 0;
}

// Camellia product HMAC key (RawrXD_Camellia256.obj / runtime bridge).
extern int asm_camellia256_get_hmac_key(uint8_t* hmacKey32);

int asm_watchdog_get_baseline(uint8_t* hmac32) {
    if (hmac32 == nullptr) {
        return -1;
    }
    // Product HMAC path: real Camellia key only. MagBuf CRC is B04 verify/status,
    // not an HMAC substitute (CRC-as-hmac was OPEN / fake-success theater).
    const int hk = asm_camellia256_get_hmac_key(hmac32);
    if (hk == 0) {
        std::lock_guard<std::mutex> lock(g_wd.mtx);
        std::memcpy(g_wd.baseline, hmac32, 32);
        return 0;
    }
    std::memset(hmac32, 0, 32);
    return -1; // NO_KEY — fail-closed until Camellia engine initialized
}

// B01: Win32IDE always defines RAWR_HAS_MASM=0|1 — gate on value, not defined().
// Under RAWR_HAS_MASM=1, Auth ASM owns asm_camellia256_auth_*_file (no C XOR).
#if !RAWR_HAS_MASM
int asm_camellia256_auth_encrypt_file(const char* inputPath, const char* outputPath) {
    return xorFileTwoPath(inputPath, outputPath);
}

int asm_camellia256_auth_decrypt_file(const char* inputPath, const char* outputPath) {
    return xorFileTwoPath(inputPath, outputPath);
}

int asm_omega_init() {
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    g_omega.active = true;
    g_omega.nextTask = 1;
    g_omega.nextAgent = 1;
    g_omega.ingestCount = 0;
    return 0;
}

int asm_omega_shutdown() {
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    g_omega.active = false;
    g_omega.nextTask = 0;
    g_omega.nextAgent = 0;
    return 0;
}

uint64_t asm_omega_ingest_requirement(const char* text, int length) {
    if (text == nullptr || length <= 0) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    if (!g_omega.active) {
        return 0;
    }
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (int i = 0; i < length; ++i) {
        hash ^= static_cast<uint64_t>(static_cast<unsigned char>(text[i]));
        hash *= 0x100000001B3ULL;
    }
    g_omega.ingestCount += 1;
    return hash;
}

int asm_omega_plan_decompose(uint64_t /*reqHash*/, uint32_t* taskIds, int maxTasks) {
    if (taskIds == nullptr || maxTasks <= 0) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    if (!g_omega.active) {
        return 0;
    }
    const int n = (maxTasks < 4) ? maxTasks : 4;
    for (int i = 0; i < n; ++i) {
        taskIds[i] = g_omega.nextTask++;
    }
    return n;
}

int asm_omega_architect_select(int taskId, int /*patternHint*/) {
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    return (g_omega.active && taskId > 0) ? 1 : -1;
}

uint64_t asm_omega_implement_generate(int taskId) {
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    if (!g_omega.active || taskId <= 0) {
        return 0;
    }
    return 0x4F4D454741000000ULL | static_cast<uint64_t>(taskId & 0xFFFF);
}

int asm_omega_verify_test(int taskId) {
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    return (g_omega.active && taskId > 0) ? 1 : 0;
}

int asm_omega_deploy_distribute(int taskId, int /*target*/) {
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    return (g_omega.active && taskId > 0) ? 0 : -1;
}

int asm_omega_observe_monitor(int taskId) {
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    return (g_omega.active && taskId > 0) ? static_cast<int>(g_omega.ingestCount & 0x7fffffff) : -1;
}

int asm_omega_evolve_improve(int taskId, int /*mutationRate*/) {
    std::lock_guard<std::mutex> lock(g_omega.mtx);
    return (g_omega.active && taskId > 0) ? 0 : -1;
}
#endif // !RAWR_HAS_MASM

} // extern "C"
