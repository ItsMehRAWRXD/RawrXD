// RAWRXD_STREAMING_INTEGRITY_001
//
// Block carry across window boundaries, and three independent bounds
// (FILE RANGE / TENSOR RANGE / ENCODED BLOCK RANGE). Runs against an in-memory
// source so the algorithmic half is provable independently of the Win32 mapping
// path, which is currently blocked on an unresolved MapViewOfFile error.
//
// The failure this exists to catch: a window that is not a multiple of 144 bytes
// leaves a partial Q4_K block at the end. Rounding down silently drops weights;
// restarting at byte 0 on the next window corrupts alignment. Both are silent.
//
// Q4_K: 144 bytes -> 256 elements. That is the block layout under test.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static const std::uint64_t QK_B = 144;
static const std::uint64_t QK_E = 256;

struct Receipt {
    std::uint64_t requested_offset = 0, requested_bytes = 0;
    std::uint64_t mapped_offset = 0, mapped_bytes = 0;
    std::uint64_t source_bytes_consumed = 0;
    std::uint64_t elements_produced = 0;
    std::uint64_t complete_blocks = 0;
    std::uint32_t carry_in = 0, carry_out = 0;
    bool eof = false, tensor_complete = false, success = false;
    std::string failure;
};

// Deterministic pseudo-random source so a hash proves byte-exactness.
static std::uint8_t srcByte(std::uint64_t i) {
    std::uint64_t x = i * 6364136223846793005ull + 1442695040888963407ull;
    x ^= x >> 33; x *= 0xff51afd7ed558ccdull; x ^= x >> 33;
    return std::uint8_t(x >> 24);
}

// A windowed reader over [tensorOff, tensorOff+tensorBytes) inside a file of
// fileBytes. Yields whole 144-byte blocks via carry. FAILS CLOSED.
struct Reader {
    std::uint64_t fileBytes = 0, tensorOff = 0, tensorBytes = 0;
    std::uint8_t carry[QK_B];
    std::size_t  carryLen = 0;
    std::uint64_t next = 0;          // absolute cursor within the tensor
    std::uint64_t blocksDone = 0, bytesConsumed = 0;
    bool done = false;

    void reset(std::uint64_t fB, std::uint64_t tOff, std::uint64_t tBytes) {
        fileBytes = fB; tensorOff = tOff; tensorBytes = tBytes;
        carryLen = 0; next = 0; blocksDone = 0; bytesConsumed = 0; done = false;
    }

    // One window of at most `window` file bytes, starting at the cursor.
    Receipt step(std::uint64_t window) {
        Receipt r;
        r.carry_in = std::uint32_t(carryLen);
        r.requested_offset = tensorOff + next;
        r.requested_bytes  = window;

        // --- BOUND 1: file range ---
        if (tensorOff + tensorBytes > fileBytes) {
            r.failure = "RANGE_OOB_TENSOR_PAST_FILE"; return r;
        }
        // --- BOUND 2: tensor range ---
        std::uint64_t remain = tensorBytes - next;
        if (remain == 0) {
            if (carryLen) { r.failure = "BLOCK_SPLIT_LOST_AT_TENSOR_END"; return r; }
            r.eof = true; r.tensor_complete = true; r.success = true; done = true; return r;
        }
        // --- BOUND 3: window payload, clamped by all of the above ---
        std::uint64_t take = (window < remain) ? window : remain;
        if (tensorOff + next + take > fileBytes) { r.failure = "RANGE_OOB_WINDOW"; return r; }
        if (take == 0 && carryLen == 0) {
            // zero progress with work outstanding is a hard failure, never a retry
            r.failure = "ZERO_PROGRESS"; return r;
        }

        // append new bytes to carry, emit whole blocks
        std::size_t fill = std::size_t(carryLen) + std::size_t(take);
        if (fill > sizeof(carry)) { r.failure = "CARRY_OVERFLOW"; return r; }
        for (std::uint64_t i = 0; i < take; ++i)
            carry[carryLen + i] = srcByte(tensorOff + next + i);

        std::size_t whole = (fill / std::size_t(QK_B)) * std::size_t(QK_B);
        // verify each complete block against the source, then emit
        for (std::size_t b = 0; b < whole; b += std::size_t(QK_B)) {
            const std::uint64_t absStart = tensorOff + next - carryLen + b;
            for (std::uint64_t k = 0; k < QK_B; ++k) {
                if (carry[b + k] != srcByte(absStart + k)) {
                    r.failure = "BYTE_MISMATCH_IN_BLOCK"; return r;
                }
            }
            r.complete_blocks++;
            r.elements_produced += QK_E;
        }
        r.source_bytes_consumed = take;

        std::memmove(carry, carry + whole, fill - whole);
        carryLen = fill - whole;
        r.carry_out = std::uint32_t(carryLen);

        next += take;
        bytesConsumed += take;
        if (next == tensorBytes) {
            if (carryLen) { r.failure = "BLOCK_SPLIT_LOST_AT_TENSOR_END"; return r; }
            r.tensor_complete = true; r.eof = true; done = true;
        }
        r.success = true;
        return r;
    }
};

static int g_fail = 0;
static void expect(bool ok, const char* name, const char* detail) {
    std::printf("  %-6s %-46s %s\n", ok ? "PASS" : "FAIL", name, detail);
    if (!ok) ++g_fail;
}

int main() {
    std::printf("RAWRXD_STREAMING_INTEGRITY_001   Q4_K 144B block / 256 elem\n\n");

    const std::uint64_t FB = 12ull << 30;          // 12 GB "file"
    const std::uint64_t TO = 4ull << 30;           // tensor at 4 GB (>4GB offset test)
    const std::uint64_t TB = 11264ull * QK_B;      // 1 expert = 1.55 MB

    // ---------- 1. boundary-size matrix ----------
    std::printf("1. WINDOW SIZE MATRIX (tensor 1.55 MB at offset 4 GB)\n");
    const std::uint64_t sizes[] = {1, 2, 143, 144, 145, 255, 256, 257,
                                  4095, 4096, 405504, 405505, 1ull << 20};
    for (std::uint64_t w : sizes) {
        Reader rd; rd.reset(FB, TO, TB);
        std::uint64_t blocks = 0, bytes = 0, windows = 0;
        bool ok = true; std::string why;
        std::uint32_t maxCarry = 0;
        for (;;) {
            Receipt r = rd.step(w);
            if (!r.success) { ok = false; why = r.failure; break; }
            blocks += r.complete_blocks;
            bytes += r.source_bytes_consumed;
            if (r.carry_out > maxCarry) maxCarry = r.carry_out;
            ++windows;
            if (r.tensor_complete) break;
            if (windows > TB + 16) { ok = false; why = "NO_PROGRESS_LOOP"; break; }
        }
        const std::uint64_t wantBlocks = TB / QK_B;
        const bool good = ok && blocks == wantBlocks && bytes == TB && maxCarry < QK_B;
        char det[128];
        std::snprintf(det, sizeof det, "%llu blocks, %llu bytes, maxcarry=%u%s%s",
                      (unsigned long long)blocks, (unsigned long long)bytes,
                      maxCarry, why.empty() ? "" : " FAIL=", why.c_str());
        char nm[64];
        std::snprintf(nm, sizeof nm, "window=%llu B", (unsigned long long)w);
        expect(good, nm, det);
    }

    // ---------- 2. carry continuity: carry_out[i] == carry_in[i+1] ----------
    std::printf("\n2. CARRY CONTINUITY (window=405505, odd size)\n");
    {
        Reader rd; rd.reset(FB, TO, TB);
        std::uint32_t prev = 0; bool contig = true;
        std::uint64_t n = 0;
        for (;;) {
            Receipt r = rd.step(405505);
            if (!r.success) { contig = false; break; }
            if (n > 0 && r.carry_in != prev) contig = false;
            prev = r.carry_out;
            ++n;
            if (r.tensor_complete) break;
        }
        expect(contig, "carry_out feeds carry_in", "no dropped or duplicated bytes");
    }

    // ---------- 3. every block byte verified against source ----------
    std::printf("\n3. BLOCK ASSEMBLY (window=143, worst case: never a full block in one window)\n");
    {
        Reader rd; rd.reset(FB, TO, TB);
        std::uint64_t blocks = 0; bool ok = true;
        for (;;) {
            Receipt r = rd.step(143);
            if (!r.success) { ok = false; break; }
            blocks += r.complete_blocks;
            if (r.tensor_complete) break;
        }
        expect(ok && blocks == TB / QK_B, "143 B windows still yield every block",
               "each emitted block was byte-verified against the source");
    }

    // ---------- 4. tensor boundary is not the window boundary ----------
    std::printf("\n4. BOUND SEPARATION\n");
    {
        // window larger than the tensor -> clamped, not over-read
        Reader rd; rd.reset(FB, TO, TB);
        Receipt r = rd.step(TB * 4);
        expect(r.success && r.tensor_complete && r.source_bytes_consumed == TB,
               "window >> tensor is clamped", "did not read into the next tensor");
        // tensor past EOF -> rejected
        Reader bad; bad.reset(FB, FB - 16, 64);
        Receipt r2 = bad.step(64);
        expect(!r2.success && r2.failure == "RANGE_OOB_TENSOR_PAST_FILE",
               "tensor past EOF is rejected", r2.failure.c_str());
    }

    // ---------- 5. zero-progress is an error, not a retry ----------
    std::printf("\n5. FAIL-CLOSED BEHAVIOUR\n");
    {
        Reader rd; rd.reset(FB, TO, TB);
        for (;;) { Receipt r = rd.step(4096); if (r.tensor_complete) break; }
        Receipt z = rd.step(4096);
        expect(!z.success && z.failure == "ZERO_PROGRESS",
               "post-completion read fails ZERO_PROGRESS", z.failure.c_str());
    }

    // ---------- 6. ragged tensor length is caught, not ignored ----------
    std::printf("\n6. RAGGED TENSOR END\n");
    {
        const std::uint64_t ragged = TB - 71;     // not a multiple of 144
        Reader rd; rd.reset(FB, TO, ragged);
        bool ok = true; std::string why;
        for (;;) {
            Receipt r = rd.step(405504);
            if (!r.success) { ok = false; why = r.failure; break; }
            if (r.tensor_complete) break;
        }
        expect(!ok && why == "BLOCK_SPLIT_LOST_AT_TENSOR_END",
               "trailing partial block is a hard failure", why.c_str());
    }

    std::printf("\nSTREAMING_INTEGRITY=%s  FAILURES=%d\n",
                g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
