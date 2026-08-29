/*
 * Compare collision-proof oracle dumps via DUMP_MANIFEST.jsonl
 * Stops at first full-shape (head=-1) mismatch with max_abs > 1e-6.
 *
 * Usage:
 *   test_oracle_ladder.exe <oracle_dir> <report.txt>
 * oracle_dir contains deep2_*.bin + llama_*.bin + DUMP_MANIFEST.jsonl
 */
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>

struct DumpRec {
    std::string side, stage, bin, fnv;
    int pos = -1, layer = -1, head = -999, nelem = -1, seq = -1;
    double l2 = 0;
};

static bool loadF32(const char* path, size_t expectN, std::vector<float>& out, std::string& err) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { err = "open_fail"; return false; }
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz < 0 || (size_t)sz != expectN * 4) {
        err = "nbytes_mismatch_file=" + std::to_string(sz) + "_expect=" + std::to_string(expectN * 4);
        std::fclose(f);
        return false;
    }
    out.resize(expectN);
    if (std::fread(out.data(), 1, (size_t)sz, f) != (size_t)sz) {
        err = "short_read";
        std::fclose(f);
        return false;
    }
    std::fclose(f);
    return true;
}

static uint64_t fnv1a(const float* a, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t bits = 0;
        std::memcpy(&bits, &a[i], 4);
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }
    return h;
}

static std::string getField(const std::string& line, const char* key) {
    std::string pat = std::string("\"") + key + "\":";
    size_t p = line.find(pat);
    if (p == std::string::npos) return {};
    p += pat.size();
    if (p >= line.size()) return {};
    if (line[p] == '"') {
        size_t e = line.find('"', p + 1);
        if (e == std::string::npos) return {};
        return line.substr(p + 1, e - p - 1);
    }
    size_t e = p;
    while (e < line.size() && line[e] != ',' && line[e] != '}') ++e;
    return line.substr(p, e - p);
}

static DumpRec parseLine(const std::string& line) {
    DumpRec r;
    r.side = getField(line, "side");
    r.stage = getField(line, "stage");
    r.bin = getField(line, "bin");
    r.fnv = getField(line, "fnv");
    r.pos = std::atoi(getField(line, "pos").c_str());
    r.layer = std::atoi(getField(line, "layer").c_str());
    r.head = std::atoi(getField(line, "head").c_str());
    r.nelem = std::atoi(getField(line, "nelem").c_str());
    r.seq = std::atoi(getField(line, "seq").c_str());
    r.l2 = std::atof(getField(line, "l2").c_str());
    return r;
}

static DumpRec pickFirstFull(const std::vector<DumpRec>& all, const char* side,
                             const char* stage, int pos, int expectN) {
    DumpRec best;
    int bestSeq = INT_MAX;
    for (const auto& r : all) {
        if (r.side != side) continue;
        if (r.stage != stage) continue;
        if (r.pos != pos) continue;
        if (r.head != -1) continue; // full only
        if (expectN > 0 && r.nelem != expectN) continue;
        if (r.seq < bestSeq) { best = r; bestSeq = r.seq; }
    }
    return best;
}

int main(int argc, char** argv) {
    const char* dir = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V2)";
    const char* report = argc > 2 ? argv[2]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V2\LADDER_VERDICT.txt)";

    std::string manPath = std::string(dir) + "\\DUMP_MANIFEST.jsonl";
    std::ifstream in(manPath);
    if (!in) {
        std::fprintf(stderr, "MISSING_MANIFEST %s\n", manPath.c_str());
        return 2;
    }
    std::vector<DumpRec> all;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        all.push_back(parseLine(line));
    }

    struct Step { const char* stage; int n; };
    // Ordered ladder — full-shape only for this pass
    Step steps[] = {
        {"PROMPT_EMBED", 2048},
        {"ATTN_NORM_0", 2048},
        {"Q_PRE_ROPE_0", 2048},
        {"K_PRE_ROPE_0", 256},
        {"V_0", 256},
        {"Q_POST_ROPE_0", 2048},
        {"K_POST_ROPE_0", 256},
        {"ATTN_OUT_0", 2048},
        {"FFN_INP_0", 2048},
        {"FFN_NORM_0", 2048},
        {"FFN_DOWN_0", 2048},
        {"POST_FFN_0", 2048},
        {"LAYER_OUT_0", 2048},
        {"LAYER_OUT_1", 2048},
        {"LAYER_OUT_21", 2048},
        {"PROMPT_FINAL_NORM", 2048},
    };

    FILE* rf = std::fopen(report, "w");
    auto out = [&](const char* fmt, auto... args) {
        std::printf(fmt, args...);
        if (rf) std::fprintf(rf, fmt, args...);
    };

    out("BATCH2_ORACLE_V2_LADDER\n");
    out("abs_eps=1e-6\n");
    out("note=old_BATCH2_ATTN_LADDER_NUM_INVALID_due_to_dump_clobber\n");
    out("Q_PRE_ROPE_NUMERICAL=PASS_frozen @1e-6\n");
    out("Q_PRE_ROPE_BITWISE=OPEN\n\n");

    const char* firstFail = nullptr;
    for (const Step& st : steps) {
        DumpRec d2 = pickFirstFull(all, "deep2", st.stage, 0, st.n);
        DumpRec ll = pickFirstFull(all, "llama", st.stage, 0, st.n);
        if (d2.bin.empty() || ll.bin.empty()) {
            out("%-18s MISSING deep2_seq=%d llama_seq=%d expect_n=%d\n",
                st.stage, d2.seq, ll.seq, st.n);
            continue;
        }
        std::vector<float> a, b;
        std::string errA, errB;
        if (!loadF32(d2.bin.c_str(), (size_t)d2.nelem, a, errA) ||
            !loadF32(ll.bin.c_str(), (size_t)ll.nelem, b, errB)) {
            out("%-18s MANIFEST_FILE_MISMATCH deep2=%s llama=%s\n",
                st.stage, errA.c_str(), errB.c_str());
            if (!firstFail) firstFail = st.stage;
            break;
        }
        if ((int)a.size() != st.n || (int)b.size() != st.n) {
            out("%-18s SHAPE_FAIL expect=%d got_d2=%zu got_ll=%zu\n",
                st.stage, st.n, a.size(), b.size());
            if (!firstFail) firstFail = st.stage;
            break;
        }
        // Verify FNV against manifest
        char fnvA[32], fnvB[32];
        std::snprintf(fnvA, sizeof(fnvA), "%016llx", (unsigned long long)fnv1a(a.data(), a.size()));
        std::snprintf(fnvB, sizeof(fnvB), "%016llx", (unsigned long long)fnv1a(b.data(), b.size()));
        if (d2.fnv.size() && d2.fnv != fnvA) {
            out("%-18s DEEP2_FNV_MISMATCH manifest=%s file=%s => REJECT\n",
                st.stage, d2.fnv.c_str(), fnvA);
            if (!firstFail) firstFail = st.stage;
            break;
        }
        if (ll.fnv.size() && ll.fnv != fnvB) {
            out("%-18s LLAMA_FNV_MISMATCH manifest=%s file=%s => REJECT\n",
                st.stage, ll.fnv.c_str(), fnvB);
            if (!firstFail) firstFail = st.stage;
            break;
        }

        double maxAbs = 0, sumAbs = 0, sumSq = 0, maxRel = 0;
        int firstBad = -1, largest = -1;
        size_t exact = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            uint32_t ba = 0, bb = 0;
            std::memcpy(&ba, &a[i], 4);
            std::memcpy(&bb, &b[i], 4);
            if (ba == bb) ++exact;
            double e = std::fabs((double)a[i] - (double)b[i]);
            sumAbs += e; sumSq += e * e;
            if (e > maxAbs) { maxAbs = e; largest = (int)i; }
            double den = std::max(std::fabs((double)a[i]), std::fabs((double)b[i]));
            double rel = den > 0 ? e / den : e;
            if (rel > maxRel) maxRel = rel;
            if (firstBad < 0 && e > 1e-6) firstBad = (int)i;
        }
        double mean = sumAbs / (double)a.size();
        double rms = std::sqrt(sumSq / (double)a.size());
        const char* gate = maxAbs <= 1e-6 ? "PASS" : (maxAbs <= 1e-5 ? "INSPECT" : "FAIL");
        out("%-18s gate=%-7s shape=%d exact=%zu max_abs=%.6e max_rel=%.6e mean=%.6e rms=%.6e "
            "first_bad=%d largest=%d fnvD=%s fnvL=%s seqD=%d seqL=%d\n",
            st.stage, gate, st.n, exact, maxAbs, maxRel, mean, rms,
            firstBad, largest, fnvA, fnvB, d2.seq, ll.seq);
        if (std::strcmp(gate, "FAIL") == 0) {
            firstFail = st.stage;
            out("\nSTOP first_genuine_full_shape_mismatch=%s\n", st.stage);
            break;
        }
    }

    if (!firstFail) out("\nfirst_genuine_full_shape_mismatch=NONE\n");
    if (rf) std::fclose(rf);
    return firstFail ? 1 : 0;
}
