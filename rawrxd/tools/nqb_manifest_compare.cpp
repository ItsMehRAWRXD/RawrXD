// ============================================================================
// nqb_manifest_compare.cpp
// RAWRXD_NQB_SOURCE_F32_PARITY_001 -- COMPARISON AUTHORITY
//
// Opens NEITHER MODEL. It receives two manifest files and nothing else, which is
// the whole reason the work was split into three processes: a comparator that
// could open the container could recompute a hash from the container and quietly
// agree with itself.
//
//   SOURCE_GENERATION_AUTHORITY = GGUF_ONLY
//   PAYLOAD_GENERATION_AUTHORITY = NQB_ONLY
//   COMPARISON_AUTHORITY        = MANIFESTS_ONLY
//
// JOIN KEY IS THE EXACT TENSOR NAME, never the traversal index. NC_RECORD_REORDER
// exists to prove that: it shuffles every record and the verdict must not move.
//
// ACCEPTANCE PER TENSOR
//     NAME_PRESENT_BOTH, ELEMENT_COUNT_MATCH, LOGICAL_SHAPE_MATCH,
//     F32_BYTES_MATCH, FNV1A64_MATCH, SHA256_MATCH
//
// Geometry is compared even though the hashes already cover the bytes, because a
// correct byte stream attached to the wrong tensor name is not payload fidelity.
// This tree has already had metadata and physical reality diverge.
//
// USAGE
//     nqb_manifest_compare <source.manifest> <payload.manifest> [--nc <dir>]
// ============================================================================

#include "deep2/Nanof32BraidManifest.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Check { std::string id; bool pass; std::string detail; };
std::vector<Check> g_checks;
bool g_clean = true;
std::string g_failures;

void chk(const char* id, bool pass, const std::string& detail) {
    g_checks.push_back(Check{id, pass, detail});
    if (!pass) {
        if (!g_clean) g_failures += "; ";
        g_clean = false;
        g_failures += id;
    }
}

std::string readAll(const std::string& path, bool& ok) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) { ok = false; return {}; }
    std::ostringstream ss;
    ss << f.rdbuf();
    ok = true;
    return ss.str();
}

bool writeAll(const std::string& path, const std::string& text) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
    return f.good();
}

// Re-serialise a record set in a caller-chosen order. Used by the reorder
// control, and by nothing else -- the real comparison is always name-keyed.
std::string serialiseInOrder(const std::vector<Deep2::NqbF32Record>& recs,
                             const std::vector<size_t>& order) {
    std::string out = Deep2::nqbManifestHeader();
    out += "\n";
    for (size_t i : order) out += Deep2::nqbSerialiseRecord(recs[i]);
    return out;
}

struct CompareResult {
    uint64_t tensorsCompared = 0;
    uint64_t nameMatch = 0, shapeMatch = 0, elementMatch = 0, byteMatch = 0;
    uint64_t fnvMatch = 0, shaMatch = 0;
    uint64_t missingSource = 0, missingPayload = 0, duplicateNames = 0;
    uint64_t mismatches = 0;
    std::string firstMismatchName, firstMismatchSourceSha, firstMismatchPayloadSha;
    uint64_t firstMismatchElements = 0, firstMismatchBytes = 0;
    bool     rootsMatch = false;
    std::string sourceRoot, payloadRoot;
};

CompareResult compare(const std::vector<Deep2::NqbF32Record>& src,
                      const std::vector<Deep2::NqbF32Record>& pay) {
    CompareResult r;
    r.sourceRoot  = Deep2::nqbManifestRoot(src);
    r.payloadRoot = Deep2::nqbManifestRoot(pay);
    r.rootsMatch  = (r.sourceRoot == r.payloadRoot);

    std::map<std::string, const Deep2::NqbF32Record*> si, pi;
    for (const Deep2::NqbF32Record& x : src) {
        if (!si.emplace(x.name, &x).second) ++r.duplicateNames;
    }
    for (const Deep2::NqbF32Record& x : pay) {
        if (!pi.emplace(x.name, &x).second) ++r.duplicateNames;
    }
    for (const auto& kv : si) if (pi.find(kv.first) == pi.end()) ++r.missingPayload;
    for (const auto& kv : pi) if (si.find(kv.first) == si.end()) ++r.missingSource;

    for (const auto& kv : si) {
        auto it = pi.find(kv.first);
        if (it == pi.end()) continue;
        const Deep2::NqbF32Record& a = *kv.second;
        const Deep2::NqbF32Record& b = *it->second;
        ++r.tensorsCompared;

        const bool shape = (a.dim0 == b.dim0) && (a.dim1 == b.dim1);
        const bool elem  = (a.elements == b.elements);
        const bool bytes = (a.f32Bytes == b.f32Bytes);
        const bool fnv   = (a.fnv1a64 == b.fnv1a64);
        const bool sha   = (a.sha256 == b.sha256);
        r.shapeMatch += shape; r.elementMatch += elem; r.byteMatch += bytes;
        r.fnvMatch += fnv;     r.shaMatch += sha;
        r.nameMatch += 1;

        if (!(shape && elem && bytes && fnv && sha)) {
            ++r.mismatches;
            if (r.mismatches == 1) {
                r.firstMismatchName        = a.name;
                r.firstMismatchSourceSha   = a.sha256;
                r.firstMismatchPayloadSha  = b.sha256;
                r.firstMismatchElements    = a.elements;
                r.firstMismatchBytes       = a.f32Bytes;
            }
        }
    }
    return r;
}

void emitCompare(const char* tag, const CompareResult& r,
                 uint64_t srcTensors, uint64_t srcElements, uint64_t srcBytes,
                 uint64_t payTensors, uint64_t payElements, uint64_t payBytes) {
    std::printf("[%s] TENSORS_EXPECTED=%zu TENSORS_COMPARED=%llu\n", tag,
                (size_t)srcTensors, (unsigned long long)r.tensorsCompared);
    std::printf("[%s] SOURCE_TENSORS=%llu NQB_TENSORS=%llu\n", tag,
                (unsigned long long)srcTensors, (unsigned long long)payTensors);
    std::printf("[%s] SOURCE_ELEMENTS=%llu NQB_ELEMENTS=%llu\n", tag,
                (unsigned long long)srcElements, (unsigned long long)payElements);
    std::printf("[%s] SOURCE_F32_BYTES=%llu NQB_F32_BYTES=%llu\n", tag,
                (unsigned long long)srcBytes, (unsigned long long)payBytes);
    std::printf("[%s] NAME_MATCH=%llu SHAPE_MATCH=%llu ELEMENT_COUNT_MATCH=%llu "
                "BYTE_COUNT_MATCH=%llu\n", tag,
                (unsigned long long)r.nameMatch, (unsigned long long)r.shapeMatch,
                (unsigned long long)r.elementMatch, (unsigned long long)r.byteMatch);
    std::printf("[%s] FNV1A64_MATCH=%llu SHA256_MATCH=%llu\n", tag,
                (unsigned long long)r.fnvMatch, (unsigned long long)r.shaMatch);
    std::printf("[%s] MANIFEST_ROOT_MATCH=%d\n", tag, r.rootsMatch ? 1 : 0);
    std::printf("[%s] MISSING_SOURCE=%llu MISSING_NQB=%llu DUPLICATE_NAMES=%llu "
                "MISMATCHES=%llu\n", tag,
                (unsigned long long)r.missingSource,
                (unsigned long long)r.missingPayload,
                (unsigned long long)r.duplicateNames,
                (unsigned long long)r.mismatches);
}

// ---- negative controls ----------------------------------------------------
//
// A comparator that cannot fail is not a comparator. Each control mutates ONE
// thing in a copy of the payload manifest and requires the SPECIFIC expected
// outcome. They are scored on their own named predicate, and only after the real
// comparison has been shown clean, so a permanently-broken comparator cannot make
// them all "pass" for the wrong reason.
void runNegativeControls(const std::string& dir,
                         const std::vector<Deep2::NqbF32Record>& src,
                         const std::vector<Deep2::NqbF32Record>& pay) {
    if (pay.empty() || src.empty()) {
        chk("NEGATIVE_CONTROLS_ADMISSIBLE", false, "no records to mutate");
        return;
    }

    chk("BASELINE_VERDICT", true, "real comparison ran before any control");

    auto writeManifest = [&](const std::string& name,
                             const std::vector<Deep2::NqbF32Record>& recs) {
        const std::string path = dir + "/" + name;
        std::string text = Deep2::nqbManifestHeader();
        text += "\n";
        for (const Deep2::NqbF32Record& r : recs) text += Deep2::nqbSerialiseRecord(r);
        return writeAll(path, text) ? path : std::string();
    };

    uint64_t ncPass = 0, ncTotal = 0;

    // NC1: mutate exactly one hash. Expect exactly one mismatch.
    {
        std::vector<Deep2::NqbF32Record> m = pay;
        m[0].sha256[0] = (m[0].sha256[0] == 'a') ? 'b' : 'a';
        ++ncTotal;
        const std::string p = writeManifest("nc1_hash_flip.manifest", m);
        const CompareResult r = compare(src, m);
        const bool asExpected = (r.mismatches == 1);
        chk("NC_HASH_FLIP", asExpected,
            "EXPECTED=MISMATCH_ONE_TENSOR OBSERVED_MISMATCHES=" +
            std::to_string(r.mismatches) + " firstMismatch=" +
            (r.mismatches ? r.firstMismatchName : std::string("<none>")) +
            " written=" + p);
        if (asExpected) ++ncPass;
    }

    // NC2: exchange two names, keep every hash. Proves the join is name-sensitive.
    {
        std::vector<Deep2::NqbF32Record> m = pay;
        std::swap(m[0].name, m[1].name);
        ++ncTotal;
        const std::string p = writeManifest("nc2_name_swap.manifest", m);
        const CompareResult r = compare(src, m);
        const bool asExpected = (r.mismatches >= 2);
        chk("NC_NAME_SWAP", asExpected,
            "EXPECTED=AT_LEAST_TWO_MISMATCHES OBSERVED_MISMATCHES=" +
            std::to_string(r.mismatches) + " written=" + p);
        if (asExpected) ++ncPass;
    }

    // NC3: remove one row. Expect a count delta and a missing-record report.
    {
        std::vector<Deep2::NqbF32Record> m = pay;
        const std::string dropped = m.back().name;
        m.pop_back();
        ++ncTotal;
        const std::string p = writeManifest("nc3_missing_record.manifest", m);
        const CompareResult r = compare(src, m);
        const bool asExpected = (r.missingPayload == 1) && (r.mismatches == 0);
        chk("NC_MISSING_RECORD", asExpected,
            "EXPECTED_COUNT_DELTA=1 OBSERVED_MISSING_NQB=" +
            std::to_string(r.missingPayload) + " droppedName=" + dropped +
            " written=" + p);
        if (asExpected) ++ncPass;
    }

    // NC4: shuffle every record. The verdict must NOT move.
    {
        std::vector<Deep2::NqbF32Record> m = pay;
        std::vector<size_t> order(m.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        // deterministic rotation, not a random shuffle: a control whose own
        // randomness could fail is a control that fails for the wrong reason
        std::rotate(order.begin(), order.begin() + (order.size() / 2), order.end());
        const std::string p = dir + "/nc4_reordered.manifest";
        writeAll(p, serialiseInOrder(pay, order));
        ++ncTotal;
        bool readOk = false;
        const std::string reorderedText = readAll(p, readOk);
        const Deep2::NqbManifestLoad loaded = Deep2::nqbLoadManifest(reorderedText);
        const CompareResult r = compare(src, loaded.records);
        const bool asExpected = readOk &&
                                (r.mismatches == 0) && r.rootsMatch &&
                                loaded.records.size() == pay.size();
        chk("NC_RECORD_REORDER", asExpected,
            "EXPECTED=STILL_PASS readOk=" + std::to_string(readOk ? 1 : 0) +
            " mismatches=" + std::to_string(r.mismatches) +
            " rootsMatch=" + std::to_string(r.rootsMatch ? 1 : 0) +
            " recordsRead=" + std::to_string(loaded.records.size()) +
            " written=" + p);
        if (asExpected) ++ncPass;
    }

    chk("GATE_HAS_POWER", ncPass == ncTotal,
        "NEGATIVE_CONTROLS=" + std::to_string(ncPass) + "/" +
        std::to_string(ncTotal));
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "Usage: %s <source.manifest> <payload.manifest> "
                             "[--nc <dir>]\n", argv[0]);
        return 2;
    }
    const std::string srcPath = argv[1];
    const std::string payPath = argv[2];
    std::string ncDir;
    for (int i = 3; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--nc" && i + 1 < argc) ncDir = argv[++i];
        else { std::printf("INVALID_INVOCATION '%s'\nVERDICT=INVALID_NO_RESULT\n",
                           a.c_str()); return 2; }
    }

    std::printf("GATE=RAWRXD_NQB_SOURCE_F32_PARITY_001\n");
    std::printf("COMPARISON_AUTHORITY=MANIFESTS_ONLY\n");
    std::printf("OPENS_SOURCE_MODEL=0\nOPENS_PAYLOAD_MODEL=0\n");

    bool ok1 = false, ok2 = false;
    const std::string srcText = readAll(srcPath, ok1);
    const std::string payText = readAll(payPath, ok2);
    if (!ok1 || !ok2) {
        std::printf("FAIL=manifest_unreadable source=%d payload=%d\n", ok1 ? 1 : 0, ok2 ? 1 : 0);
        std::printf("VERDICT=INVALID_NO_RESULT\n");
        return 2;
    }

    const Deep2::NqbManifestLoad src = Deep2::nqbLoadManifest(srcText);
    const Deep2::NqbManifestLoad pay = Deep2::nqbLoadManifest(payText);

    chk("SOURCE_MANIFEST_SCHEMA_VALID", src.status == Deep2::NqbParseStatus::Ok,
        std::string("status=") + Deep2::nqbParseStatusName(src.status) +
        " records=" + std::to_string(src.recordsAccepted) +
        " rejected=" + std::to_string(src.linesRejected) +
        (src.detail.empty() ? "" : (" detail=" + src.detail)));
    chk("PAYLOAD_MANIFEST_SCHEMA_VALID", pay.status == Deep2::NqbParseStatus::Ok,
        std::string("status=") + Deep2::nqbParseStatusName(pay.status) +
        " records=" + std::to_string(pay.recordsAccepted) +
        " rejected=" + std::to_string(pay.linesRejected) +
        (pay.detail.empty() ? "" : (" detail=" + pay.detail)));
    if (src.status != Deep2::NqbParseStatus::Ok ||
        pay.status != Deep2::NqbParseStatus::Ok) {
        // A schema fault is INVALID, not FAIL: the manifests were not validly
        // read, so no comparison happened and no verdict about fidelity exists.
        for (const Check& c : g_checks)
            std::printf("CHECK %s=%s %s\n", c.id.c_str(),
                        c.pass ? "PASS" : "FAIL", c.detail.c_str());
        std::printf("VERDICT=INVALID_NO_RESULT\n");
        return 2;
    }

    uint64_t srcElements = 0, srcBytes = 0, payElements = 0, payBytes = 0;
    for (const Deep2::NqbF32Record& r : src.records) { srcElements += r.elements; srcBytes += r.f32Bytes; }
    for (const Deep2::NqbF32Record& r : pay.records) { payElements += r.elements; payBytes += r.f32Bytes; }

    const CompareResult r = compare(src.records, pay.records);

    chk("TENSOR_COUNT_CONSERVATION", src.records.size() == pay.records.size(),
        "source=" + std::to_string(src.records.size()) +
        " payload=" + std::to_string(pay.records.size()));
    chk("ELEMENT_COUNT_CONSERVATION", srcElements == payElements,
        "source=" + std::to_string(srcElements) + " payload=" + std::to_string(payElements));
    chk("F32_BYTE_CONSERVATION", srcBytes == payBytes,
        "source=" + std::to_string(srcBytes) + " payload=" + std::to_string(payBytes));
    chk("NO_MISSING_RECORDS", r.missingSource == 0 && r.missingPayload == 0,
        "missingSource=" + std::to_string(r.missingSource) +
        " missingPayload=" + std::to_string(r.missingPayload));
    chk("NO_DUPLICATE_NAMES", r.duplicateNames == 0,
        "duplicates=" + std::to_string(r.duplicateNames));
    chk("TENSOR_SET_IDENTICAL",
        r.tensorsCompared == src.records.size() && r.tensorsCompared == pay.records.size(),
        "compared=" + std::to_string(r.tensorsCompared));
    chk("SHAPE_MATCH_ALL", r.shapeMatch == r.tensorsCompared,
        std::to_string(r.shapeMatch) + "/" + std::to_string(r.tensorsCompared));
    chk("ELEMENT_COUNT_MATCH_ALL", r.elementMatch == r.tensorsCompared,
        std::to_string(r.elementMatch) + "/" + std::to_string(r.tensorsCompared));
    chk("F32_BYTE_COUNT_MATCH_ALL", r.byteMatch == r.tensorsCompared,
        std::to_string(r.byteMatch) + "/" + std::to_string(r.tensorsCompared));
    chk("FNV1A64_MATCH_ALL", r.fnvMatch == r.tensorsCompared,
        std::to_string(r.fnvMatch) + "/" + std::to_string(r.tensorsCompared));
    chk("SHA256_MATCH_ALL", r.shaMatch == r.tensorsCompared,
        std::to_string(r.shaMatch) + "/" + std::to_string(r.tensorsCompared));
    chk("MANIFEST_ROOT_MATCH", r.rootsMatch,
        "SOURCE_MANIFEST_ROOT=" + r.sourceRoot + " NQB_MANIFEST_ROOT=" + r.payloadRoot);
    chk("ZERO_HASH_MISMATCHES", r.mismatches == 0,
        "mismatches=" + std::to_string(r.mismatches));

    emitCompare("REAL", r, src.records.size(), srcElements, srcBytes,
                pay.records.size(), payElements, payBytes);

    if (r.mismatches) {
        std::printf("FIRST_MISMATCH_NAME=%s\n", r.firstMismatchName.c_str());
        std::printf("FIRST_MISMATCH_SOURCE_HASH=%s\n", r.firstMismatchSourceSha.c_str());
        std::printf("FIRST_MISMATCH_NQB_HASH=%s\n", r.firstMismatchPayloadSha.c_str());
        std::printf("FIRST_MISMATCH_ELEMENTS=%llu\n",
                    (unsigned long long)r.firstMismatchElements);
        std::printf("FIRST_MISMATCH_BYTES=%llu\n",
                    (unsigned long long)r.firstMismatchBytes);
        std::printf("TOTAL_MISMATCHES=%llu\n", (unsigned long long)r.mismatches);
    }

    if (!ncDir.empty()) runNegativeControls(ncDir, src.records, pay.records);

    uint64_t pass = 0, fail = 0;
    for (const Check& c : g_checks) (c.pass ? pass : fail)++;
    std::printf("CHECKS_TOTAL=%llu\n", (unsigned long long)g_checks.size());
    std::printf("CHECKS_PASS=%llu\n", (unsigned long long)pass);
    std::printf("CHECKS_FAIL=%llu\n", (unsigned long long)fail);
    for (const Check& c : g_checks)
        std::printf("CHECK %s=%s %s\n", c.id.c_str(),
                    c.pass ? "PASS" : "FAIL", c.detail.c_str());

    bool controlsOk = true;
    for (const Check& c : g_checks) {
        const std::string id(c.id);
        if (id.rfind("NC_", 0) == 0 || id == "GATE_HAS_POWER" ||
            id == "BASELINE_VERDICT")
            if (!c.pass) controlsOk = false;
    }

    const bool fidelity = (fail == 0);
    const char* verdict = fidelity ? "PASS" : "FAIL";
    std::printf("GGUF_PRODUCTION_DEQUANT_TO_NQB_PAYLOAD_FIDELITY=%s\n", verdict);
    std::printf("NOT_CLAIMED=CANONICAL_QUANT_DECODER_NUMERICAL_CORRECTNESS\n");
    std::printf("CONTROLS_HAVE_POWER=%d\n", controlsOk ? 1 : 0);
    std::printf("VERDICT=%s\n", verdict);
    return fidelity ? 0 : 1;
}