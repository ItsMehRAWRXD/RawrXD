// =============================================================================
// quant_parity_cert.cpp — Model Genie capability admission + parity certification
// =============================================================================
// Answers the two questions the gap audit raises:
//
//   1. PRIMITIVE / DISPATCH REALITY — is MlaDecompressFwd implemented, and is it
//      bound? This tool reads the ground truth from the executor's dispatch, not
//      from the generated CapabilityManifest (which had gone stale).
//
//   2. ADMISSION — for each quantization type, may it execute, probe-only, or is
//      it refused? No certificate is issued without recorded evidence.
//
//   3. PRIMITIVE PROVENANCE — emit the machine-readable primitive manifest that
//      `rawr capabilities` cannot produce for itself. That CLI is compiled
//      without QuantParityRegistry.cpp, so src/deep2/QuantParityRegistry.h
//      (which includes ../modelgenie/ModelGenome.hpp through a relative path
//      that only resolves under the registry's CMake include dirs) is out of
//      reach and the CLI can only transcribe statuses. This tool links the
//      registry TU, so it reads the gate directly and emits the authoritative
//      manifest; --verify-against then compares it field-for-field against the
//      committed evidence so stale committed metadata fails the ctest gate.
//
// Exit codes:
//   0  all required primitives available AND Q8_K packing certified AND the
//      primitive manifest (when requested) matches committed evidence
//   1  a required primitive is unavailable, a certification is missing/Failed,
//      the primitive manifest fails its exactly-once coverage check, or the
//      committed evidence manifest is stale
//   2  usage error
// =============================================================================
#include "QuantParityRegistry.h"
#include "Q8KParity.h"
#include "Q8KQuant.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <map>
#include <random>
#include <vector>

using namespace RawrXD::Deep2;
using json = nlohmann::json;
// The byte-level oracle lives in RawrXD::Parity; Q8KBlock is re-exported there
// from the production header so there is only one geometry.
using RawrXD::Parity::Q8KBlock;
using RawrXD::Parity::QuantizeRowQ8KReference;
using RawrXD::Parity::CompareQ8KBlocks;

namespace {

void PrintPrimitiveTable() {
    std::printf("\n=== Primitive dispatch audit (ground truth from ModelGenieExecutor.cpp) ===\n");
    std::printf("%-26s %-10s %-12s %-8s %s\n",
                "primitive", "available", "impl_reqd", "kernel", "source");
    std::printf("%-26s %-10s %-12s %-8s %s\n",
                "--------------------------", "----------", "------------", "--------",
                "-------------------------");

    struct Row { ModelGenie::Primitive p; const char* name; const char* src; };
    static const Row rows[] = {
        {ModelGenie::Primitive::RmsNormFwd,       "RmsNormFwd",       "ModelGenieExecutor.cpp:RmsNormFwd"},
        {ModelGenie::Primitive::LinearFwd,        "LinearFwd",        "ModelGenieExecutor.cpp:LinearFwd"},
        {ModelGenie::Primitive::AttentionFwd,     "AttentionFwd",     "ModelGenieExecutor.cpp:AttentionFwd"},
        {ModelGenie::Primitive::MlaDecompressFwd, "MlaDecompressFwd", "ModelGenieExecutor.cpp:MlaDecompressFwd"},
        {ModelGenie::Primitive::MoEExecuteFwd,    "MoEExecuteFwd",    "ModelGenieExecutor.cpp:MoEExecuteFwd"},
        {ModelGenie::Primitive::TopKFwd,          "TopKFwd",          "ModelGenieExecutor.cpp:TopKFwd"},
        {ModelGenie::Primitive::RouterFwd,        "RouterFwd",        "ModelGenieExecutor.cpp:RouterFwd"},
        {ModelGenie::Primitive::ResidualAddFwd,   "ResidualAddFwd",   "ModelGenieExecutor.cpp:ResidualAddFwd"},
        {ModelGenie::Primitive::LMHeadFwd,        "LMHeadFwd",        "ModelGenieExecutor.cpp:LMHeadFwd"},
        // Declared and gated, but the dispatcher returns false and no graph
        // producer emits it, so it is reported as declared-unimplemented
        // rather than borrowed provenance.
        {ModelGenie::Primitive::MatMulFwd,        "MatMulFwd",        "ModelGenieExecutor.cpp:dispatch returns false (unreachable in produced graphs)"},
    };

    int available = 0, required = 0;
    for (const auto& r : rows) {
        const PrimitiveGate g =
            QuantParityRegistry::GatePrimitive(r.p);
        std::printf("%-26s %-10s %-12s %-8s %s\n",
                    r.name,
                    g.available ? "YES" : "no",
                    g.implementationRequired ? "true" : "false",
                    g.kernelPresent ? "present" : "absent",
                    r.src);
        if (g.available) ++available;
        if (g.implementationRequired) ++required;
    }
    std::printf("\navailable: %d / %zu required\n", available, sizeof(rows) / sizeof(rows[0]));
}

// Run the Q8_K byte-level differential over a deterministic activation and
// record the outcome as evidence. This is the permanent regression gate.
bool RunQ8KGateAndRecord(int64_t blocks, uint32_t seed) {
    std::printf("\n=== Q8_K packing parity gate ===\n");

    const int64_t k = blocks * 256;
    std::vector<float> x(k);
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> small(-1.0f, 1.0f);
    for (int64_t b = 0; b < blocks; ++b) {
        for (int i = 0; i < 256; ++i) x[b * 256 + i] = small(rng) * 0.05f;
        const int ei = static_cast<int>(rng() % 256);
        const float sign = (b % 2 == 0) ? 1.0f : -1.0f;
        x[b * 256 + ei] = sign * (3.5f + 0.5f * small(rng));
    }

    std::vector<Q8KBlock> ref(static_cast<size_t>(blocks)), fix(static_cast<size_t>(blocks));
    QuantizeRowQ8KReference(x.data(), ref.data(), k);
    QuantizeRowQ8K(x.data(), fix.data(), k);

    auto report = CompareQ8KBlocks(x.data(), k, ref.data(), fix.data());

    std::printf("blocks                : %lld\n", static_cast<long long>(report.blocks_compared));
    std::printf("d bit mismatches      : %lld\n", static_cast<long long>(report.d_bits_mismatches));
    std::printf("qs value mismatches   : %lld\n", static_cast<long long>(report.qs_value_mismatches));
    std::printf("bsum value mismatches : %lld\n", static_cast<long long>(report.bsum_value_mismatches));
    std::printf("byte-identical        : %s\n", report.fully_identical ? "YES" : "NO");

    // Evidence must name the harness that produced it, or it is not recorded.
    const std::string evidence =
        "q8k_parity_tool/q8k_edge_tests: quant_parity_cert seed=" + std::to_string(seed) +
        " blocks=" + std::to_string(blocks);

    ParityStatus status = report.fully_identical
        ? ParityStatus::PackingVerified
        : ParityStatus::Failed;

    const bool recorded = QuantParityRegistry::Instance().RecordParity(
        static_cast<uint32_t>(GGMLType::GGML_TYPE_Q8_K),
        ParityPath::Packing, status, evidence,
        report.fully_identical
            ? "d/qs[256]/bsums[16] byte-identical vs ggml quantize_row_q8_K_ref"
            : "Q8_K packing diverges from the ggml reference");

    if (!recorded) {
        std::printf("FAILED TO RECORD EVIDENCE (empty or rejected reference)\n");
        return false;
    }
    return report.fully_identical;
}

} // namespace

// ---------------------------------------------------------------------------
// Primitive manifest (Gate 2 provenance)
// ---------------------------------------------------------------------------
// quant_parity_cert links src/deep2/QuantParityRegistry.cpp, so it is the only
// binary that can read the primitive gate directly. Everything below is
// therefore the authoritative emitter, and the exactly-once coverage check runs
// BEFORE the file is written: a manifest that is missing a primitive, carries a
// duplicate, or names one the gate never reported is refused outright rather
// than normalized into looking complete.
namespace {

const char* kManifestSchema = "RAWRXD_PRIMITIVE_MANIFEST/1.0";
const char* kManifestGenerator = "quant_parity_cert --manifest";

json PrimitiveRecordToJson(const QuantParityRegistry::PrimitiveRecord& r) {
    json e;
    e["name"]                    = r.name;
    e["registration_source"]     = r.registrationSource;
    e["status"]                  = r.status;
    e["available"]               = r.available;
    e["implementation_required"] = r.implementationRequired;
    e["kernel_present"]          = r.kernelPresent;
    e["gate_verdict"]            = r.gateVerdict;
    return e;
}

bool EmitPrimitiveManifest(const std::string& path) {
    std::printf("\n=== Primitive manifest (Gate 2 provenance) ===\n");

    const auto& known   = QuantParityRegistry::KnownPrimitives();
    const auto  records = QuantParityRegistry::DescribePrimitiveGates();

    // ---- exactly-once coverage proof -------------------------------------
    std::vector<std::string> problems;

    std::map<std::string, int> counts;
    for (const auto& r : records) {
        if (r.name.empty()) {
            problems.push_back("emitted a row with an empty primitive name");
            continue;
        }
        ++counts[r.name];
    }

    // Every primitive the gate reports must appear exactly once.
    for (const auto p : known) {
        const std::string n = QuantParityRegistry::PrimitiveNameOf(p);
        const auto it = counts.find(n);
        if (it == counts.end()) {
            problems.push_back("primitive reported by the gate is missing from the manifest: " + n);
        } else if (it->second != 1) {
            problems.push_back("duplicate primitive: " + n + " appears " +
                               std::to_string(it->second) + " times");
            counts.erase(it);
        } else {
            counts.erase(it);
        }
    }
    // Anything left over is not in the gate-reported surface at all.
    for (const auto& kv : counts) {
        problems.push_back("unknown primitive, not in the gate-reported surface: " + kv.first);
    }
    if (records.size() != known.size()) {
        problems.push_back("row count " + std::to_string(records.size()) +
                           " != gate-reported primitive count " + std::to_string(known.size()));
    }
    // Each row must identify the primitive it actually describes, and must be a
    // primitive the gate really reports on.
    for (const auto& r : records) {
        const std::string canonical = QuantParityRegistry::PrimitiveNameOf(r.primitive);
        if (r.primitive == ModelGenie::Primitive::None) {
            problems.push_back("row '" + r.name + "' carries no primitive identity");
        } else if (r.name != canonical) {
            problems.push_back("row '" + r.name + "' describes primitive '" + canonical + "'");
        }
        if (!QuantParityRegistry::PrimitiveIsReported(r.primitive)) {
            problems.push_back("unknown primitive, GatePrimitive() reports no verdict for: " +
                               r.name);
        }
    }

    if (!problems.empty()) {
        for (const auto& p : problems) std::printf("  [FAIL] %s\n", p.c_str());
        std::printf("  primitive manifest REFUSED - not written to %s\n", path.c_str());
        return false;
    }
    std::printf("  exactly-once coverage : %zu/%zu gate-reported primitives, no gaps, no duplicates\n",
                records.size(), known.size());

    // ---- build -------------------------------------------------------------
    json manifest;
    manifest["schema"]              = kManifestSchema;
    manifest["generator"]           = kManifestGenerator;
    manifest["gate_source"]         = "src/deep2/QuantParityRegistry.cpp:QuantParityRegistry::GatePrimitive";
    manifest["gate_binding_source"] = "src/modelgenie/ModelGenieExecutor.cpp";
    manifest["primitive_count"]     = static_cast<int>(records.size());

    json prims = json::array();
    int available = 0, unimplemented = 0, notRequired = 0;
    for (const auto& r : records) {
        prims.push_back(PrimitiveRecordToJson(r));
        if (r.available)                    ++available;
        else if (r.implementationRequired)  ++unimplemented;
        else                                ++notRequired;
    }
    manifest["primitives"] = prims;

    json countsJson;
    countsJson["available"]              = available;
    countsJson["declared_unimplemented"] = unimplemented;
    countsJson["not_required"]           = notRequired;
    manifest["counts"] = countsJson;

    // ---- write -------------------------------------------------------------
    std::ofstream f(path);
    if (!f) {
        std::printf("  [FAIL] cannot open manifest path for writing: %s\n", path.c_str());
        return false;
    }
    f << manifest.dump(2) << "\n";
    f.flush();
    if (!f) {
        std::printf("  [FAIL] write failed: %s\n", path.c_str());
        return false;
    }

    std::printf("  manifest written      : %s\n", path.c_str());
    std::printf("  %-20s %-34s %-9s %-9s %-8s %s\n",
                "primitive", "registration_source", "available", "impl_req", "kernel", "verdict");
    for (const auto& r : records) {
        std::printf("  %-20s %-34s %-9s %-9s %-8s %s\n",
                    r.name.c_str(), r.registrationSource.c_str(),
                    r.available ? "true" : "false",
                    r.implementationRequired ? "true" : "false",
                    r.kernelPresent ? "true" : "false",
                    r.gateVerdict.c_str());
    }
    std::printf("  available=%d  declared_unimplemented=%d  not_required=%d\n",
                available, unimplemented, notRequired);
    return true;
}

// Compares a freshly generated manifest against the committed evidence file,
// field for field. Committed metadata that no longer describes what the
// registry actually reports is stale, and stale evidence fails the gate.
bool VerifyPrimitiveManifest(const std::string& generatedPath,
                             const std::string& committedPath) {
    std::printf("\n=== Primitive manifest staleness check ===\n");
    std::printf("  generated : %s\n", generatedPath.c_str());
    std::printf("  committed : %s\n", committedPath.c_str());

    std::ifstream gf(generatedPath);
    if (!gf) { std::printf("  [FAIL] cannot read generated manifest: %s\n", generatedPath.c_str()); return false; }
    std::ifstream cf(committedPath);
    if (!cf) { std::printf("  [FAIL] cannot read committed evidence: %s\n", committedPath.c_str()); return false; }

    json gen, com;
    try {
        gen = json::parse(gf);
        com = json::parse(cf);
    } catch (const std::exception& e) {
        std::printf("  [FAIL] manifest is not valid JSON: %s\n", e.what());
        return false;
    }

    bool ok = true;
    auto fail = [&](const std::string& m) { std::printf("  [FAIL] %s\n", m.c_str()); ok = false; };

    static const char* kMetaKeys[] = {
        "schema", "generator", "gate_source", "gate_binding_source", "primitive_count"
    };
    for (const char* k : kMetaKeys) {
        if (!gen.contains(k)) { fail(std::string("generated manifest is missing '") + k + "'"); continue; }
        if (!com.contains(k)) { fail(std::string("committed manifest is missing '") + k + "'"); continue; }
        if (gen[k] != com[k]) {
            fail(std::string("metadata '") + k + "' differs: committed=" + com[k].dump() +
                 " generated=" + gen[k].dump());
        }
    }
    if (gen.value("counts", json()) != com.value("counts", json())) {
        fail("counts differ: committed=" + com.value("counts", json()).dump() +
             " generated=" + gen.value("counts", json()).dump());
    }

    if (!gen.contains("primitives") || !gen["primitives"].is_array() ||
        !com.contains("primitives") || !com["primitives"].is_array()) {
        fail("'primitives' must be an array in both manifests");
        return false;
    }

    const json& gp = gen["primitives"];
    const json& cp = com["primitives"];
    if (gp.size() != cp.size()) {
        fail("primitive row count differs: committed=" + std::to_string(cp.size()) +
             " generated=" + std::to_string(gp.size()));
        return false;
    }

    // Index the committed rows by name, not by position, so the two files must
    // agree on the SET of primitives and on every field of each one.
    std::map<std::string, json> committedByName;
    for (const auto& row : cp) {
        if (!row.contains("name") || !row["name"].is_string()) {
            fail("committed manifest has a row without a string 'name'");
            continue;
        }
        committedByName[row["name"].get<std::string>()] = row;
    }

    static const char* kFields[] = {
        "name", "registration_source", "status", "available",
        "implementation_required", "kernel_present", "gate_verdict"
    };
    for (const auto& row : gp) {
        if (!row.contains("name") || !row["name"].is_string()) {
            fail("generated manifest has a row without a string 'name'");
            continue;
        }
        const std::string name = row["name"].get<std::string>();
        const auto it = committedByName.find(name);
        if (it == committedByName.end()) {
            fail("primitive '" + name + "' is generated but absent from committed evidence");
            continue;
        }
        const json& crow = it->second;
        for (const char* k : kFields) {
            if (!row.contains(k) || !crow.contains(k)) {
                fail(std::string("primitive '") + name + "' is missing field '" + k + "'");
                continue;
            }
            if (row[k] != crow[k]) {
                fail("primitive '" + name + "' field '" + k + "' differs: committed=" +
                     crow[k].dump() + " generated=" + row[k].dump());
            }
        }
        committedByName.erase(it);
    }
    for (const auto& kv : committedByName) {
        fail("primitive '" + kv.first + "' is committed evidence but not generated (stale)");
    }

    if (ok) {
        std::printf("  [PASS] generated manifest matches committed evidence field-for-field "
                    "(%zu primitives)\n", static_cast<size_t>(gp.size()));
    } else {
        std::printf("  evidence/primitive_manifest.json is STALE - regenerate it with "
                    "quant_parity_cert --manifest\n");
    }
    return ok;
}

} // namespace

int main(int argc, char** argv) {
    int64_t blocks = 8;
    uint32_t seed = 12345u;
    std::string json_out;
    std::string manifest_out;
    std::string verify_against;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--blocks" && i + 1 < argc)    blocks = std::atoll(argv[++i]);
        else if (a == "--seed" && i + 1 < argc) seed = static_cast<uint32_t>(std::atoi(argv[++i]));
        else if (a == "--json" && i + 1 < argc) json_out = argv[++i];
        else if (a == "--manifest" && i + 1 < argc) manifest_out = argv[++i];
        else if (a == "--verify-against" && i + 1 < argc) verify_against = argv[++i];
        else if (a == "--help" || a == "-h") {
            std::printf("Usage: %s [--blocks N] [--seed S] [--json out.json]\n", argv[0]);
            std::printf("          [--manifest out.json] [--verify-against committed.json]\n");
            return 0;
        }
    }

    std::printf("=== Model Genie capability admission + parity certification ===\n");

    // 1. Bind the kernels Deep2 actually implements (QuantTypeTable.kernelReady).
    QuantParityRegistry::Instance().RegisterBuiltinKernels();
    std::printf("kernel bindings registered from QuantTypeTable geometry\n");

    // 2. Primitive reality.
    PrintPrimitiveTable();

    // 2b. Primitive manifest: the authoritative, machine-readable provenance
    //     that `rawr capabilities` cannot emit for itself. Refused (and the
    //     whole run failed) if the exactly-once coverage check does not hold.
    if (!verify_against.empty() && manifest_out.empty()) {
        std::printf("ERROR: --verify-against requires --manifest <file>\n");
        return 2;
    }
    bool manifest_ok = true;
    if (!manifest_out.empty()) {
        manifest_ok = EmitPrimitiveManifest(manifest_out);
        if (manifest_ok && !verify_against.empty()) {
            manifest_ok = VerifyPrimitiveManifest(manifest_out, verify_against);
        }
    }

    // 3. Q8_K gate -> recorded evidence.
    const bool q8k_ok = RunQ8KGateAndRecord(blocks, seed);

    // 4. Admission decisions for the K-quants that matter to the dot gates.
    std::printf("\n=== Quantization admission (Q4_K, Q6_K, Q8_K, Q8_0) ===\n");
    struct QEntry { uint32_t id; const char* name; };
    static const QEntry kQuants[] = {
        { static_cast<uint32_t>(GGMLType::GGML_TYPE_Q4_K), "Q4_K" },
        { static_cast<uint32_t>(GGMLType::GGML_TYPE_Q6_K), "Q6_K" },
        { static_cast<uint32_t>(GGMLType::GGML_TYPE_Q8_K), "Q8_K" },
        { static_cast<uint32_t>(GGMLType::GGML_TYPE_Q8_0), "Q8_0" },
        { static_cast<uint32_t>(GGMLType::GGML_TYPE_Q8_1), "Q8_1" },
    };

    int certified = 0, probe_only = 0, refused = 0;
    for (const auto& q : kQuants) {
        const auto d = QuantParityRegistry::Instance().Admit(q.id);
        const char* verdict = "REFUSED";
        switch (d.verdict) {
            case Admission::Certified: verdict = "CERTIFIED"; ++certified; break;
            case Admission::ProbeOnly: verdict = "probe-only"; ++probe_only; break;
            default:                   verdict = "REFUSED";  ++refused;  break;
        }
        std::printf("  %-6s %-11s  %s\n", q.name, verdict, d.reason.c_str());
    }

    // 5. Coverage summary.
    const auto cov = QuantParityRegistry::Instance().ComputeCoverage();
    std::printf("\n=== coverage ===\n");
    std::printf("known ggml types      : %d\n", cov.knownTypes);
    std::printf("kernel bound          : %d\n", cov.bound);
    std::printf("kernel missing        : %d\n", cov.kernelMissing);
    std::printf("packing verified      : %d\n", cov.packingVerified);

    // 6. Final verdict.
    std::printf("\n=== VERDICT ===\n");
    const bool mla_available = QuantParityRegistry::GatePrimitive(
        ModelGenie::Primitive::MlaDecompressFwd).available;
    const bool primitives_ok = mla_available &&
        QuantParityRegistry::GatePrimitive(ModelGenie::Primitive::AttentionFwd).available &&
        QuantParityRegistry::GatePrimitive(ModelGenie::Primitive::MoEExecuteFwd).available;

    std::printf("MLA decompression     : %s\n", mla_available ? "IMPLEMENTED + BOUND" : "MISSING");
    std::printf("Q8_K packing parity   : %s\n", q8k_ok ? "PASS" : "FAIL");
    std::printf("required primitives   : %s\n", primitives_ok ? "available" : "INCOMPLETE");
    std::printf("primitive manifest    : %s\n",
                manifest_out.empty() ? "not requested"
                                     : (manifest_ok ? "PASS" : "FAIL"));

    const bool pass = q8k_ok && primitives_ok && manifest_ok;
    std::printf("\nRESULT: %s\n", pass ? "PASS" : "FAIL");

    if (!json_out.empty()) {
        std::ofstream f(json_out);
        if (f) {
            json j = json::parse(QuantParityRegistry::Instance().ToJson());
            j["tool"] = "quant_parity_cert";
            j["mla_decompress_available"] = mla_available;
            j["q8k_packing_parity"] = q8k_ok ? "PASS" : "FAIL";
            j["admission_certified"] = certified;
            j["admission_probe_only"] = probe_only;
            j["admission_refused"] = refused;
            j["result"] = pass ? "PASS" : "FAIL";
            if (!manifest_out.empty()) {
                j["primitive_manifest"] = manifest_out;
                j["primitive_manifest_ok"] = manifest_ok;
            }
            f << j.dump(2);
            std::printf("JSON written: %s\n", json_out.c_str());
        }
    }

    return pass ? 0 : 1;
}
