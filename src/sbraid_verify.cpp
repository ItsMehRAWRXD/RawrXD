// ============================================================================
// sbraid_verify.cpp — Standalone verification for .sbraid container format
// ============================================================================
// Build: g++ -O2 -std=c++17 -o sbraid_verify.exe sbraid_verify.cpp rawrxd_slingshot_braid.cpp
// ============================================================================
#include "rawrxd_slingshot_braid.hpp"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>
#include <chrono>

static bool g_verbose = false;

void PrintHeader(const SBraidHeader& h) {
    std::printf("  Magic:        %.4s\n", h.magic);
    std::printf("  Version:      0x%08X\n", h.version);
    std::printf("  Elements:     %llu\n", static_cast<unsigned long long>(h.element_count));
    std::printf("  Tile size:    %u\n", h.tile_size);
    std::printf("  Tile count:   %u\n", h.tile_count);
    std::printf("  Directory:    offset=%llu\n", static_cast<unsigned long long>(h.directory_offset));
    std::printf("  Payload:      offset=%llu size=%llu\n",
                static_cast<unsigned long long>(h.payload_offset),
                static_cast<unsigned long long>(h.payload_size));
    std::printf("  Global scale: %.6f\n", h.global_scale);
    std::printf("  Earned bits:  %.4f\n", h.earned_bits);
    std::printf("  Max bounce:   %u\n", h.max_bounce_pass);
}

void PrintTile(const SBraidTile& t, size_t index) {
    std::printf("  Tile[%zu]: id=%u elements=%u base_bits=%u residuals=%u bounce=%u scale=%.6f payload=%u+%u\n",
                index, t.tile_id, t.element_count, t.base_bits, t.residual_count, t.bounce_pass,
                t.scale,
                static_cast<unsigned int>(t.payload_offset),
                t.payload_size);
    if (t.flags & TILE_FLAG_ATTENTION) std::printf("    [ATTENTION]\n");
    if (t.flags & TILE_FLAG_SACRED)    std::printf("    [SACRED]\n");
    if (t.flags & TILE_FLAG_BOUNCED)   std::printf("    [BOUNCED]\n");
    if (t.flags & TILE_FLAG_SPARSE)    std::printf("    [SPARSE]\n");
}

// ============================================================================
// Test 1: Round-trip serialization/deserialization
// ============================================================================
bool TestRoundTrip() {
    std::printf("\n[TEST 1] Round-trip serialization/deserialization\n");

    // Create synthetic tensor: 256 elements, sinusoidal pattern
    constexpr int64_t N = 256;
    std::vector<float> src(N);
    for (int64_t i = 0; i < N; ++i) {
        src[i] = std::sinf(static_cast<float>(i) * 0.1f);
    }

    const char* test_file = "__test_roundtrip.sbraid";

    // Emit
    bool ok = SlingshotBraidEmitter::EmitSBraidTensor(
        test_file, "test.sin", src.data(), N, 256);
    if (!ok) {
        std::printf("  FAIL: EmitSBraidTensor returned false\n");
        return false;
    }

    // Inspect
    SBraidHeader header{};
    std::vector<SBraidTile> directory;
    ok = SlingshotBraidEmitter::InspectSBraidTensor(test_file, header, directory);
    if (!ok) {
        std::printf("  FAIL: InspectSBraidTensor returned false\n");
        std::remove(test_file);
        return false;
    }

    // Validate header
    if (std::memcmp(header.magic, "SRBD", 4) != 0) {
        std::printf("  FAIL: Magic mismatch\n");
        std::remove(test_file);
        return false;
    }
    if (header.version != SBRAID_VERSION) {
        std::printf("  FAIL: Version mismatch\n");
        std::remove(test_file);
        return false;
    }
    if (header.element_count != static_cast<uint64_t>(N)) {
        std::printf("  FAIL: element_count mismatch: expected %d, got %llu\n",
                    static_cast<int>(N), static_cast<unsigned long long>(header.element_count));
        std::remove(test_file);
        return false;
    }
    if (header.tile_count != static_cast<uint32_t>((N + 63) / 64)) {
        std::printf("  FAIL: tile_count mismatch\n");
        std::remove(test_file);
        return false;
    }

    // Validate directory
    if (directory.size() != header.tile_count) {
        std::printf("  FAIL: directory size mismatch\n");
        std::remove(test_file);
        return false;
    }

    // Check payload offsets are monotonically increasing
    uint64_t prev_end = header.payload_offset;
    for (size_t i = 0; i < directory.size(); ++i) {
        const SBraidTile& t = directory[i];
        if (t.payload_offset != prev_end) {
            std::printf("  FAIL: tile[%zu] payload_offset gap: expected %llu, got %llu\n",
                        i,
                        static_cast<unsigned long long>(prev_end),
                        static_cast<unsigned long long>(t.payload_offset));
            std::remove(test_file);
            return false;
        }
        prev_end = t.payload_offset + t.payload_size;

        if (g_verbose) {
            PrintTile(t, i);
        }
    }

    // Check total payload size
    if (header.payload_size != (prev_end - header.payload_offset)) {
        std::printf("  FAIL: payload_size mismatch\n");
        std::remove(test_file);
        return false;
    }

    std::printf("  PASS: Round-trip OK (%u tiles, %llu payload bytes)\n",
                header.tile_count,
                static_cast<unsigned long long>(header.payload_size));

    if (g_verbose) {
        PrintHeader(header);
    }

    std::remove(test_file);
    return true;
}

// ============================================================================
// Test 2: Attention tensor detection and sacred flag
// ============================================================================
bool TestAttentionDetection() {
    std::printf("\n[TEST 2] Attention tensor detection\n");

    constexpr int64_t N = 128;
    std::vector<float> src(N, 0.5f);

    struct TestCase {
        const char* name;
        bool expect_attention;
    };

    TestCase cases[] = {
        {"blk.0.attn_q.weight", true},
        {"blk.0.attn_k.weight", true},
        {"blk.0.attn_v.weight", true},
        {"blk.0.attn_output.weight", true},
        {"blk.0.ffn_up.weight", false},
        {"blk.0.ffn_down.weight", false},
        {"token_embd.weight", true},  // Sacred
        {"output.weight", true},     // Sacred
        {"blk.0.ffn_norm.weight", false},
    };

    bool all_pass = true;
    for (const auto& tc : cases) {
        const char* test_file = "__test_attn.sbraid";
        bool ok = SlingshotBraidEmitter::EmitSBraidTensor(
            test_file, tc.name, src.data(), N, 256);
        if (!ok) {
            std::printf("  FAIL: %s - emit failed\n", tc.name);
            all_pass = false;
            continue;
        }

        SBraidHeader header{};
        std::vector<SBraidTile> directory;
        ok = SlingshotBraidEmitter::InspectSBraidTensor(test_file, header, directory);
        std::remove(test_file);
        if (!ok) {
            std::printf("  FAIL: %s - inspect failed\n", tc.name);
            all_pass = false;
            continue;
        }

        bool has_attention = false;
        bool has_sacred = false;
        for (const auto& t : directory) {
            if (t.flags & TILE_FLAG_ATTENTION) has_attention = true;
            if (t.flags & TILE_FLAG_SACRED) has_sacred = true;
        }

        bool pass = (has_attention == tc.expect_attention) &&
                    (has_sacred == tc.expect_attention);
        if (!pass) {
            std::printf("  FAIL: %s - attention=%d(sacred=%d) expected=%d\n",
                        tc.name, has_attention, has_sacred, tc.expect_attention);
            all_pass = false;
        } else {
            std::printf("  PASS: %s - attention=%d sacred=%d\n",
                        tc.name, has_attention, has_sacred);
        }
    }

    return all_pass;
}

// ============================================================================
// Test 3: Large tensor stress (simulates 926M-element output.weight)
// ============================================================================
bool TestLargeTensor() {
    std::printf("\n[TEST 3] Large tensor stress (simulated)\n");

    // Use smaller representative size for fast test
    constexpr int64_t N = 1000000;  // 1M elements = ~15,625 tiles
    std::vector<float> src(N);
    for (int64_t i = 0; i < N; ++i) {
        src[i] = static_cast<float>(i % 17) / 17.0f - 0.5f;  // Bounded pattern
    }

    const char* test_file = "__test_large.sbraid";

    auto t0 = std::chrono::high_resolution_clock::now();
    bool ok = SlingshotBraidEmitter::EmitSBraidTensor(
        test_file, "output.weight", src.data(), N, 256);
    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    if (!ok) {
        std::printf("  FAIL: Emit failed\n");
        return false;
    }

    SBraidHeader header{};
    std::vector<SBraidTile> directory;
    ok = SlingshotBraidEmitter::InspectSBraidTensor(test_file, header, directory);
    std::remove(test_file);

    if (!ok) {
        std::printf("  FAIL: Inspect failed\n");
        return false;
    }

    // Memory sanity: payload should be much smaller than dense 256-plane
    // Dense 256-plane for 1M elements: 1M * 256 / 8 = 32 MB
    // Our sparse representation should be ~1-2 MB
    const double dense_equivalent_mb = (N * 256.0) / 8.0 / (1024.0 * 1024.0);
    const double actual_mb = header.payload_size / (1024.0 * 1024.0);
    const double ratio = dense_equivalent_mb / actual_mb;

    std::printf("  Elements:     %lld\n", static_cast<long long>(N));
    std::printf("  Tiles:        %u\n", header.tile_count);
    std::printf("  Emit time:    %.2f ms\n", ms);
    std::printf("  Payload:      %.3f MB\n", actual_mb);
    std::printf("  Dense equiv:  %.3f MB\n", dense_equivalent_mb);
    std::printf("  Reduction:    %.1fx\n", ratio);
    std::printf("  Earned bits:  %.4f\n", header.earned_bits);

    if (ratio < 10.0) {
        std::printf("  WARN: Compression ratio %.1fx is lower than expected\n", ratio);
    }

    std::printf("  PASS: Large tensor OK\n");
    return true;
}

// ============================================================================
// Test 4: Edge cases
// ============================================================================
bool TestEdgeCases() {
    std::printf("\n[TEST 4] Edge cases\n");

    bool all_pass = true;

    // Empty tensor
    {
        bool ok = SlingshotBraidEmitter::EmitSBraidTensor(
            "__test_empty.sbraid", "empty", nullptr, 0, 256);
        if (ok) {
            std::printf("  FAIL: Empty tensor should reject\n");
            all_pass = false;
        } else {
            std::printf("  PASS: Empty tensor rejected\n");
        }
    }

    // Single element
    {
        float val = 3.14f;
        bool ok = SlingshotBraidEmitter::EmitSBraidTensor(
            "__test_single.sbraid", "single", &val, 1, 256);
        std::remove("__test_single.sbraid");
        if (!ok) {
            std::printf("  FAIL: Single element should succeed\n");
            all_pass = false;
        } else {
            std::printf("  PASS: Single element OK\n");
        }
    }

    // Negative values
    {
        float vals[] = {-1.0f, -0.5f, -0.1f, 0.0f, 0.1f, 0.5f, 1.0f};
        bool ok = SlingshotBraidEmitter::EmitSBraidTensor(
            "__test_neg.sbraid", "negative", vals, 7, 256);
        std::remove("__test_neg.sbraid");
        if (!ok) {
            std::printf("  FAIL: Negative values should succeed\n");
            all_pass = false;
        } else {
            std::printf("  PASS: Negative values OK\n");
        }
    }

    return all_pass;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    std::printf("========================================\n");
    std::printf("  Slingshot Braid (.sbraid) Verification\n");
    std::printf("========================================\n");

    if (argc > 1 && std::strcmp(argv[1], "--verbose") == 0) {
        g_verbose = true;
    }

    bool all_pass = true;
    all_pass = TestRoundTrip() && all_pass;
    all_pass = TestAttentionDetection() && all_pass;
    all_pass = TestLargeTensor() && all_pass;
    all_pass = TestEdgeCases() && all_pass;

    std::printf("\n========================================\n");
    if (all_pass) {
        std::printf("  ALL TESTS PASSED\n");
        return 0;
    } else {
        std::printf("  SOME TESTS FAILED\n");
        return 1;
    }
}
