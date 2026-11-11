#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <vector>

static constexpr uint64_t kEntityCount = 256;
static constexpr uint64_t kTickCount = 10000;

static uint64_t gEntityX[kEntityCount];
static uint64_t gEntityY[kEntityCount];
static uint64_t gEntityVX[kEntityCount];
static uint64_t gEntityVY[kEntityCount];
static uint64_t gEntityFlags[kEntityCount];

using CRC64_InitTable_t = void (*)();
using CRC64_HashState_t = uint64_t (*)(const void*, uint64_t);
using DesyncRecovery_Configure_t = int (*)(uint64_t, uint64_t*, uint64_t*, uint64_t*, uint64_t*, uint64_t*);
using SaveState_t = int (*)();
using RestoreState_t = int (*)();

struct TickStateHash {
    uint64_t tick;
    uint64_t entityCount;
    uint64_t x0;
    uint64_t y0;
    uint64_t vx0;
    uint64_t vy0;
    uint64_t flags0;
    uint64_t x31;
    uint64_t y31;
    uint64_t checksum;
};

static uint64_t XorShift64(uint64_t& s) {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

static void ResetEntities(uint64_t seed) {
    uint64_t s = seed;
    for (uint64_t i = 0; i < kEntityCount; ++i) {
        gEntityX[i] = XorShift64(s);
        gEntityY[i] = XorShift64(s);
        gEntityVX[i] = (XorShift64(s) & 0x3FFu) + 1;
        gEntityVY[i] = (XorShift64(s) & 0x3FFu) + 1;
        gEntityFlags[i] = XorShift64(s) & 0xFFu;
    }
}

static void SimTickDeterministic(uint64_t tick, uint64_t& rng) {
    for (uint64_t i = 0; i < kEntityCount; ++i) {
        const uint64_t r = XorShift64(rng);
        const uint64_t accel = (r & 0xFu) + 1;

        gEntityVX[i] = (gEntityVX[i] + accel) & 0xFFFFu;
        gEntityVY[i] = (gEntityVY[i] + ((r >> 4) & 0xFu) + 1) & 0xFFFFu;

        gEntityX[i] = (gEntityX[i] + gEntityVX[i]) & 0xFFFFFFFFu;
        gEntityY[i] = (gEntityY[i] + gEntityVY[i]) & 0xFFFFFFFFu;

        gEntityFlags[i] ^= ((tick + i) & 1u) ? 0x1u : 0x2u;
    }
}

static uint64_t BuildChecksum() {
    uint64_t c = 1469598103934665603ull;
    for (uint64_t i = 0; i < kEntityCount; ++i) {
        c ^= gEntityX[i] + 0x9E3779B97F4A7C15ull;
        c *= 1099511628211ull;
        c ^= gEntityY[i];
        c *= 1099511628211ull;
    }
    return c;
}

static bool RunPass(
    uint64_t seed,
    CRC64_HashState_t hashFn,
    SaveState_t saveState,
    std::vector<uint64_t>& outHistory,
    uint64_t& outFinalChecksum) {

    outHistory.assign(kTickCount, 0);
    ResetEntities(seed);

    uint64_t rng = seed ^ 0xA5A5A5A55A5A5A5Aull;

    for (uint64_t tick = 0; tick < kTickCount; ++tick) {
        if (!saveState()) {
            std::printf("[Determinism] SaveState failed at tick %llu\n", static_cast<unsigned long long>(tick));
            return false;
        }

        SimTickDeterministic(tick, rng);

        TickStateHash state{};
        state.tick = tick;
        state.entityCount = kEntityCount;
        state.x0 = gEntityX[0];
        state.y0 = gEntityY[0];
        state.vx0 = gEntityVX[0];
        state.vy0 = gEntityVY[0];
        state.flags0 = gEntityFlags[0];
        state.x31 = gEntityX[31];
        state.y31 = gEntityY[31];
        state.checksum = BuildChecksum();

        outHistory[tick] = hashFn(&state, sizeof(state));
    }

    outFinalChecksum = BuildChecksum();
    return true;
}

int main() {
    HMODULE sdk = LoadLibraryA("d:\\rawrxd-ci-bootstrap\\Sovereign_SDK.dll");
    if (!sdk) {
        std::printf("[Determinism] Failed to load Sovereign_SDK.dll (err=%lu)\n", GetLastError());
        return 1;
    }

    auto crcInit = reinterpret_cast<CRC64_InitTable_t>(GetProcAddress(sdk, "CRC64_InitTable"));
    auto crcHash = reinterpret_cast<CRC64_HashState_t>(GetProcAddress(sdk, "CRC64_HashState"));
    auto cfg = reinterpret_cast<DesyncRecovery_Configure_t>(GetProcAddress(sdk, "DesyncRecovery_Configure"));
    auto saveState = reinterpret_cast<SaveState_t>(GetProcAddress(sdk, "SaveState"));
    auto restoreState = reinterpret_cast<RestoreState_t>(GetProcAddress(sdk, "RestoreState"));

    if (!crcInit || !crcHash || !cfg || !saveState || !restoreState) {
        std::printf("[Determinism] Missing required exports\n");
        FreeLibrary(sdk);
        return 2;
    }

    crcInit();

    if (!cfg(kEntityCount, gEntityX, gEntityY, gEntityVX, gEntityVY, gEntityFlags)) {
        std::printf("[Determinism] DesyncRecovery_Configure failed\n");
        FreeLibrary(sdk);
        return 3;
    }

    std::vector<uint64_t> a;
    std::vector<uint64_t> b;
    uint64_t chkA = 0;
    uint64_t chkB = 0;

    const uint64_t seed = 0x123456789ABCDEF0ull;

    if (!RunPass(seed, crcHash, saveState, a, chkA)) {
        FreeLibrary(sdk);
        return 4;
    }

    if (!restoreState()) {
        std::printf("[Determinism] RestoreState failed after pass A\n");
        FreeLibrary(sdk);
        return 5;
    }

    if (!RunPass(seed, crcHash, saveState, b, chkB)) {
        FreeLibrary(sdk);
        return 6;
    }

    uint64_t mismatchTick = UINT64_MAX;
    for (uint64_t i = 0; i < kTickCount; ++i) {
        if (a[i] != b[i]) {
            mismatchTick = i;
            break;
        }
    }

    if (mismatchTick == UINT64_MAX && chkA == chkB) {
        std::printf("[Determinism] PASS: %llu ticks matched. finalChecksum=%016llX\n",
            static_cast<unsigned long long>(kTickCount),
            static_cast<unsigned long long>(chkA));
        FreeLibrary(sdk);
        return 0;
    }

    if (mismatchTick != UINT64_MAX) {
        std::printf("[Determinism] FAIL: first mismatch tick=%llu A=%016llX B=%016llX\n",
            static_cast<unsigned long long>(mismatchTick),
            static_cast<unsigned long long>(a[mismatchTick]),
            static_cast<unsigned long long>(b[mismatchTick]));
    }

    std::printf("[Determinism] Final checksums A=%016llX B=%016llX\n",
        static_cast<unsigned long long>(chkA),
        static_cast<unsigned long long>(chkB));

    FreeLibrary(sdk);
    return 7;
}
