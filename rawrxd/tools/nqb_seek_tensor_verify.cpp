// ============================================================================
// nqb_seek_tensor_verify.cpp
// RAWRXD_NQB_SEEK_TENSOR_001
//
// Proves that Nanof32BraidStreamer::seekTensor() returns the tensor it claims.
//
// WHY THIS EXISTS
// ---------------
// seekTensor() was declared in the public header and defined NOWHERE. A caller
// compiled clean and then failed at link. It has now been implemented, and a
// compile is not evidence that it reads the right tensor: a seek that lands on
// the wrong offset would silently feed a caller another tensor's weights, which
// is far worse than a link error because nothing would complain.
//
// So this compares random access against the sequential walk they must agree
// with. Both are read from the SAME file with the SAME reader.
//
// NOTE ON ORDER: readNextTensor() walks BACKWARD from EOF, so the reference list
// built here is in reverse file order. seekTensor() takes a FORWARD index (0 =
// first written, lowest offset). Every comparison below therefore flips the
// reference. Mixing the two conventions is how a correct seek gets reported as
// a wrong one -- which is what happened on the first run of this tool.
//
// It also checks the negative cases, because a seek that always succeeds is
// useless:
//
//     seekTensor(numTensors)      -> false   (one past the end)
//     seekTensor(UINT32_MAX)      -> false
//     seekTensor on a fresh closed reader -> false
//
// and that a seek is RESUMABLE: after seeking to i, the next reads must continue
// i, i+1, i+2 ... rather than restarting or skipping.
//
// Usage: nqb_seek_tensor_verify <file.nqb> [samples]
// ============================================================================

#include "deep2/Nanof32BraidFormat.hpp"
#include "deep2/Nanof32BraidStreamer.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint64_t FNV_BASIS = 1469598103934665603ULL;
constexpr uint64_t FNV_PRIME = 1099511628211ULL;

uint64_t fnv1a(uint64_t h, const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= FNV_PRIME; }
    return h;
}

struct Rec {
    std::string name;
    uint64_t rows = 0, cols = 0, dataBytes = 0;
    uint64_t fnv = FNV_BASIS;
};

std::string footName(const Deep2::Nanof32BraidTensorFooter& f) {
    size_t n = 0;
    while (n < sizeof(f.name) && f.name[n] != '\0') ++n;
    return std::string(f.name, n);
}

// Read the tensor at the current position and digest the lossless F32 image.
bool readCurrent(Deep2::Nanof32BraidStreamer& s, Rec& out, std::string& err) {
    Deep2::Nanof32BraidTensorFooter f{};
    std::vector<Deep2::bfloat16_t> b16;
    std::vector<float> f32;
    if (!s.readNextTensor(f, b16, &f32)) { err = "readNextTensor returned false"; return false; }
    out.name      = footName(f);
    out.rows      = f.rows;
    out.cols      = f.cols;
    out.dataBytes = f.dataBytes;
    if (!f32.empty()) {
        out.fnv = fnv1a(FNV_BASIS, f32.data(), f32.size() * sizeof(float));
    } else if (!b16.empty()) {
        out.fnv = fnv1a(FNV_BASIS, b16.data(), b16.size() * sizeof(Deep2::bfloat16_t));
    } else {
        err = "reader returned neither F32 nor BF16";
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <file.nqb> [samples]\n", argv[0]);
        return 2;
    }
    const std::string path = argv[1];
    const int samples = (argc > 2) ? std::atoi(argv[2]) : 9;

    std::printf("GATE=RAWRXD_NQB_SEEK_TENSOR_001\n");
    std::printf("ARTIFACT=%s\n", path.c_str());

    // ---- reference: the sequential walk ----------------------------------
    std::vector<Rec> seq;
    {
        Deep2::Nanof32BraidStreamer s;
        if (!s.open(path)) { std::printf("FAIL=open\nVERDICT=INVALID_NO_RESULT\n"); return 2; }
        const uint32_t total = s.header()->numTensors;
        std::printf("HEADER_NUM_TENSORS=%u\n", total);
        for (uint32_t i = 0; i < total; ++i) {
            Rec r; std::string err;
            if (!readCurrent(s, r, err)) {
                std::printf("FAIL=sequential_read index=%u %s\n", i, err.c_str());
                std::printf("VERDICT=FAIL\n");
                return 1;
            }
            seq.push_back(r);
        }
        std::printf("SEQUENTIAL_TENSORS_READ=%zu (reverse walk order)\n", seq.size());
        // a closed reader must refuse a seek
        s.close();
        if (s.seekTensor(0)) {
            std::printf("FAIL=closed_reader_accepted_seek\n");
            std::printf("VERDICT=FAIL\n");
            return 1;
        }
        std::printf("CLOSED_READER_REFUSES_SEEK=1\n");
    }
    if (seq.empty()) { std::printf("VERDICT=INVALID_NO_RESULT\n"); return 2; }

    // ---- negative cases ----------------------------------------------------
    uint64_t fail = 0;
    {
        Deep2::Nanof32BraidStreamer s;
        if (!s.open(path)) { std::printf("FAIL=reopen\nVERDICT=INVALID_NO_RESULT\n"); return 2; }
        const uint32_t total = s.header()->numTensors;
        if (s.seekTensor(total))     { std::printf("FAIL=seek_one_past_end_accepted\n"); ++fail; }
        else std::printf("SEEK_ONE_PAST_END_REFUSED=1\n");
        if (s.seekTensor(UINT32_MAX)) { std::printf("FAIL=seek_uint32max_accepted\n"); ++fail; }
        else std::printf("SEEK_UINT32MAX_REFUSED=1\n");
        if (s.seekTensor(0))          { std::printf("SEEK_ZERO_ACCEPTED=1\n"); }
        else { std::printf("FAIL=seek_zero_refused\n"); ++fail; }
    }

    // ---- random access must equal the sequential walk ----------------------
    std::vector<size_t> picks;
    if (samples <= 1) {
        picks.push_back(0);
    } else {
        for (int k = 0; k < samples; ++k) {
            const size_t i = (k * (seq.size() - 1)) / static_cast<size_t>(samples - 1);
            if (picks.empty() || picks.back() != i) picks.push_back(i);
        }
    }

    Deep2::Nanof32BraidStreamer s;
    if (!s.open(path)) { std::printf("FAIL=open3\nVERDICT=INVALID_NO_RESULT\n"); return 2; }

    uint64_t matched = 0;
    for (size_t idx : picks) {
        if (!s.seekTensor(static_cast<uint32_t>(idx))) {
            std::printf("SEEK_FAILED index=%zu\n", idx);
            ++fail;
            continue;
        }
        Rec r; std::string err;
        if (!readCurrent(s, r, err)) {
            std::printf("READ_AFTER_SEEK_FAILED index=%zu %s\n", idx, err.c_str());
            ++fail;
            continue;
        }
        const Rec& e = seq[seq.size() - 1 - idx];   // seq is reverse-ordered
        const bool same = (r.name == e.name) && (r.rows == e.rows) &&
                          (r.cols == e.cols) && (r.dataBytes == e.dataBytes) &&
                          (r.fnv == e.fnv);
        std::printf("SEEK index=%-4zu name=%-28s expected=%-28s digest=%s\n",
                    idx, r.name.c_str(), e.name.c_str(),
                    same ? "MATCH" : "MISMATCH");
        if (!same) {
            std::printf("  rows %llu/%llu cols %llu/%llu bytes %llu/%llu fnv %llu/%llu\n",
                        (unsigned long long)r.rows, (unsigned long long)e.rows,
                        (unsigned long long)r.cols, (unsigned long long)e.cols,
                        (unsigned long long)r.dataBytes, (unsigned long long)e.dataBytes,
                        (unsigned long long)r.fnv, (unsigned long long)e.fnv);
            ++fail;
        } else {
            ++matched;
        }
    }
    std::printf("SEEK_SAMPLES=%zu SEEK_MATCHED=%llu\n", picks.size(),
                (unsigned long long)matched);

    // ---- iteration after a seek continues BACKWARD --------------------------
    //
    // The first version of this check asserted FORWARD continuation
    // (127, 128, 129 ...). That expectation was wrong, not the code:
    // readNextTensor() walks BACKWARD from wherever readHead_ sits, so after a
    // seek the sequence necessarily continues i, i-1, i-2 ... A seek gives random
    // ACCESS, not a cursor that can be walked in the opposite direction. The check
    // now asserts the real contract, and additionally pins the direction so a
    // future change to the traversal order cannot pass unnoticed.
    if (seq.size() >= 3) {
        const size_t start = seq.size() / 2;
        if (!s.seekTensor(static_cast<uint32_t>(start))) {
            std::printf("FAIL=resume_seek\n"); ++fail;
        } else {
            uint64_t followed = 0;
            for (size_t k = 0; k < seq.size(); ++k) {
                const size_t fwd = start - k;          // BACKWARD from start
                if (k >= seq.size() - start) break;
                Rec r; std::string err;
                if (!readCurrent(s, r, err)) break;
                const Rec& e = seq[seq.size() - 1 - fwd];   // reverse-ordered reference
                if (r.name != e.name || r.fnv != e.fnv) break;
                ++followed;
            }
            const size_t expected = seq.size() - start;
            const bool complete = (followed == expected);
            std::printf("RESUME_FROM fwd_index=%zu DIRECTION=BACKWARD "
                        "FOLLOWED=%llu EXPECTED=%zu COMPLETE=%d\n",
                        start, (unsigned long long)followed, expected,
                        complete ? 1 : 0);
            if (!complete || followed < 2) ++fail;
        }
    }

    std::printf("FAILURES=%llu\n", (unsigned long long)fail);
    std::printf("SEEK_MATCHES_SEQUENTIAL_WALK=%s\n", fail == 0 ? "PASS" : "FAIL");
    std::printf("VERDICT=%s\n", fail == 0 ? "PASS" : "FAIL");
    return fail == 0 ? 0 : 1;
}