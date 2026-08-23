// ============================================================================
// test_val_051_7_tensor_residency.cpp
// Gate 6: Tensor Residency Fixture — Standalone deterministic test
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <map>
#include <algorithm>

// Minimal deterministic "GGUF" tensor fixture
struct FixtureTensor {
    std::string name;
    std::vector<uint8_t> bytes;
    size_t offset = 0;  // within "file"
};

// Fake residency manager for fixture testing
class FixtureResidencyManager {
public:
    struct ResidentEntry {
        std::string name;
        const uint8_t* data = nullptr;
        size_t bytes = 0;
        uint64_t generation = 0;
        size_t leaseCount = 0;
        bool resident = false;
    };

    size_t capacityBytes = 1024 * 1024;  // 1 MB default
    size_t currentBytes = 0;
    uint64_t totalAcquires = 0;
    uint64_t totalReleases = 0;
    uint64_t totalEvictions = 0;
    uint64_t totalRemaps = 0;

    std::map<std::string, ResidentEntry> residents;
    std::map<std::string, FixtureTensor> source;

    void RegisterSource(const FixtureTensor& ft) {
        source[ft.name] = ft;
    }

    bool Acquire(const std::string& name, const uint8_t*& outData, size_t& outBytes) {
        auto it = source.find(name);
        if (it == source.end()) {
            printf("[FIXTURE_FAIL] Acquire: unknown tensor '%s'\n", name.c_str());
            return false;
        }

        const size_t needBytes = it->second.bytes.size();

        // Already resident?
        auto rit = residents.find(name);
        if (rit != residents.end() && rit->second.resident) {
            rit->second.leaseCount++;
            outData = rit->second.data;
            outBytes = rit->second.bytes;
            totalAcquires++;
            printf("[FIXTURE] Acquire '%s' (existing resident, lease=%zu)\n",
                   name.c_str(), rit->second.leaseCount);
            return true;
        }

        // Need to map — check capacity
        if (currentBytes + needBytes > capacityBytes) {
            // Evict oldest
            if (!EvictOldest(needBytes)) {
                printf("[FIXTURE_FAIL] Acquire: cannot make room for '%s' (%zu bytes)\n",
                       name.c_str(), needBytes);
                return false;
            }
        }

        // Map
        ResidentEntry entry;
        entry.name = name;
        entry.bytes = needBytes;
        entry.generation = totalRemaps;
        entry.leaseCount = 1;
        entry.resident = true;

        // Allocate copy (simulating mapped view)
        uint8_t* copy = new uint8_t[needBytes];
        memcpy(copy, it->second.bytes.data(), needBytes);
        entry.data = copy;

        residents[name] = entry;
        currentBytes += needBytes;
        totalAcquires++;
        totalRemaps++;

        printf("[FIXTURE] Acquire '%s' (mapped, gen=%llu, bytes=%zu)\n",
               name.c_str(), (unsigned long long)entry.generation, needBytes);

        outData = entry.data;
        outBytes = entry.bytes;
        return true;
    }

    bool Release(const std::string& name) {
        auto rit = residents.find(name);
        if (rit == residents.end() || !rit->second.resident) {
            printf("[FIXTURE_FAIL] Release: '%s' not resident\n", name.c_str());
            return false;
        }
        if (rit->second.leaseCount == 0) {
            printf("[FIXTURE_FAIL] Release: '%s' lease count already 0\n", name.c_str());
            return false;
        }
        rit->second.leaseCount--;
        totalReleases++;
        printf("[FIXTURE] Release '%s' (lease=%zu)\n", name.c_str(), rit->second.leaseCount);
        return true;
    }

    bool EvictOldest(size_t needBytes) {
        // Simple LRU: find resident with leaseCount==0, evict oldest by generation
        std::string victim;
        uint64_t oldestGen = UINT64_MAX;
        for (auto& kv : residents) {
            if (kv.second.resident && kv.second.leaseCount == 0 && kv.second.generation < oldestGen) {
                oldestGen = kv.second.generation;
                victim = kv.first;
            }
        }
        if (victim.empty()) {
            printf("[FIXTURE_FAIL] EvictOldest: no evictable tensor found\n");
            return false;
        }
        auto& entry = residents[victim];
        printf("[FIXTURE] Evict '%s' (gen=%llu, bytes=%zu)\n",
               victim.c_str(), (unsigned long long)entry.generation, entry.bytes);
        delete[] entry.data;
        entry.data = nullptr;
        entry.resident = false;
        currentBytes -= entry.bytes;
        totalEvictions++;
        return true;
    }

    bool Validate(const std::string& name, const uint8_t* data, size_t bytes) {
        auto it = source.find(name);
        if (it == source.end()) return false;
        if (bytes != it->second.bytes.size()) return false;
        return memcmp(data, it->second.bytes.data(), bytes) == 0;
    }

    void Reset() {
        for (auto& kv : residents) {
            if (kv.second.data) delete[] kv.second.data;
        }
        residents.clear();
        currentBytes = 0;
        totalAcquires = 0;
        totalReleases = 0;
        totalEvictions = 0;
        totalRemaps = 0;
    }

    ~FixtureResidencyManager() { Reset(); }
};

// ============================================================================
// Test Helpers
// ============================================================================
static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_testsPassed++; printf("[PASS] %s\n", msg); } \
    else { g_testsFailed++; printf("[FAIL] %s\n", msg); } \
} while(0)

// ============================================================================
// Gate 6: Tensor Residency Fixture Tests
// ============================================================================
int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("VAL-051.7 Gate 6: Tensor Residency Fixture\n");
    printf("=================================================================\n");

    // Create deterministic tensors
    FixtureTensor tensorA;
    tensorA.name = "tensor.A";
    tensorA.bytes.resize(1024);
    for (size_t i = 0; i < 1024; ++i) tensorA.bytes[i] = static_cast<uint8_t>(i & 0xFF);

    FixtureTensor tensorB;
    tensorB.name = "tensor.B";
    tensorB.bytes.resize(2048);
    for (size_t i = 0; i < 2048; ++i) tensorB.bytes[i] = static_cast<uint8_t>((i * 3 + 7) & 0xFF);

    FixtureTensor tensorC;
    tensorC.name = "tensor.C";
    tensorC.bytes.resize(512);
    for (size_t i = 0; i < 512; ++i) tensorC.bytes[i] = static_cast<uint8_t>((i * 5 + 11) & 0xFF);

    // ── Test 1: Acquire A, validate, release ────────────────────────
    {
        FixtureResidencyManager mgr;
        mgr.RegisterSource(tensorA);

        const uint8_t* data = nullptr;
        size_t bytes = 0;
        CHECK(mgr.Acquire("tensor.A", data, bytes), "Acquire A");
        CHECK(bytes == 1024, "A bytes correct");
        CHECK(mgr.Validate("tensor.A", data, bytes), "A validate against source");
        CHECK(mgr.Release("tensor.A"), "Release A");
        CHECK(mgr.currentBytes == 1024, "A still resident after release");
    }

    // ── Test 2: Reacquire A after release ────────────────────────────
    {
        FixtureResidencyManager mgr;
        mgr.RegisterSource(tensorA);

        const uint8_t* data1 = nullptr;
        size_t bytes1 = 0;
        mgr.Acquire("tensor.A", data1, bytes1);
        mgr.Release("tensor.A");

        const uint8_t* data2 = nullptr;
        size_t bytes2 = 0;
        CHECK(mgr.Acquire("tensor.A", data2, bytes2), "Reacquire A");
        CHECK(bytes2 == 1024, "A reacquire bytes correct");
        CHECK(mgr.Validate("tensor.A", data2, bytes2), "A reacquire validate");
        CHECK(data1 == data2, "A reacquire same pointer (no eviction)");
        mgr.Release("tensor.A");
    }

    // ── Test 3: A → B → C → A with forced eviction ──────────────────
    {
        FixtureResidencyManager mgr;
        mgr.capacityBytes = 2500;  // Less than A+B+C = 3584
        mgr.RegisterSource(tensorA);
        mgr.RegisterSource(tensorB);
        mgr.RegisterSource(tensorC);

        const uint8_t* a1 = nullptr; size_t a1b = 0;
        const uint8_t* b1 = nullptr; size_t b1b = 0;
        const uint8_t* c1 = nullptr; size_t c1b = 0;

        CHECK(mgr.Acquire("tensor.A", a1, a1b), "Sequence: Acquire A");
        CHECK(mgr.Acquire("tensor.B", b1, b1b), "Sequence: Acquire B");
        CHECK(mgr.Acquire("tensor.C", c1, c1b), "Sequence: Acquire C (forces eviction)");

        // Release A and B so C can fit
        mgr.Release("tensor.A");
        mgr.Release("tensor.B");

        // Now reacquire A — should trigger remap
        const uint8_t* a2 = nullptr; size_t a2b = 0;
        CHECK(mgr.Acquire("tensor.A", a2, a2b), "Sequence: Reacquire A after eviction");
        CHECK(mgr.Validate("tensor.A", a2, a2b), "Sequence: A validate after remap");
        CHECK(mgr.totalEvictions > 0, "Sequence: at least one eviction occurred");
        CHECK(mgr.totalRemaps >= 2, "Sequence: at least two remaps");

        mgr.Release("tensor.A");
        mgr.Release("tensor.C");
    }

    // ── Test 4: Double release detection ─────────────────────────────
    {
        FixtureResidencyManager mgr;
        mgr.RegisterSource(tensorA);
        const uint8_t* data = nullptr; size_t bytes = 0;
        mgr.Acquire("tensor.A", data, bytes);
        mgr.Release("tensor.A");
        CHECK(!mgr.Release("tensor.A"), "Double release detected");
    }

    // ── Test 5: Active lease prevents eviction ──────────────────────
    {
        FixtureResidencyManager mgr;
        mgr.capacityBytes = 1500;  // A=1024, B=2048
        mgr.RegisterSource(tensorA);
        mgr.RegisterSource(tensorB);

        const uint8_t* a1 = nullptr; size_t a1b = 0;
        CHECK(mgr.Acquire("tensor.A", a1, a1b), "Evict guard: Acquire A");
        // Try to acquire B — should fail because A is active and cannot be evicted
        const uint8_t* b1 = nullptr; size_t b1b = 0;
        CHECK(!mgr.Acquire("tensor.B", b1, b1b), "Evict guard: B blocked by active A");
        mgr.Release("tensor.A");
    }

    // ── Summary ──────────────────────────────────────────────────────
    printf("\n============================================================\n");
    printf("Gate 6 Results: %d passed, %d failed\n", g_testsPassed, g_testsFailed);
    printf("============================================================\n");

    return g_testsFailed > 0 ? 1 : 0;
}
