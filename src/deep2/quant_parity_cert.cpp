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
// Exit codes:
//   0  all required primitives available AND Q8_K packing certified
//   1  a required primitive is unavailable, or a certification is missing/Failed
//   2  usage error
// =============================================================================
#include "QuantParityRegistry.h"
#include "Q8KParity.h"
#include "Q8KQuant.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <random>

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
        {ModelGenie::Primitive::RmsNormFwd,       "RmsNormFwd",       "ModelGenieExecutor.cpp"},
        {ModelGenie::Primitive::LinearFwd,        "LinearFwd",        "ModelGenieExecutor.cpp"},
        {ModelGenie::Primitive::AttentionFwd,     "AttentionFwd",     "ModelGenieExecutor.cpp"},
        {ModelGenie::Primitive::MlaDecompressFwd, "MlaDecompressFwd", "ModelGenieExecutor.cpp:1917"},
        {ModelGenie::Primitive::MoEExecuteFwd,    "MoEExecuteFwd",    "ModelGenieExecutor.cpp"},
        {ModelGenie::Primitive::TopKFwd,          "TopKFwd",          "ModelGenieExecutor.cpp"},
        {ModelGenie::Primitive::RouterFwd,        "RouterFwd",        "ModelGenieExecutor.cpp"},
        {ModelGenie::Primitive::ResidualAddFwd,   "ResidualAddFwd",   "ModelGenieExecutor.cpp"},
        {ModelGenie::Primitive::LMHeadFwd,        "LMHeadFwd",        "ModelGenieExecutor.cpp"},
        {ModelGenie::Primitive::MatMulFwd,        "MatMulFwd",        "dispatch returns false"},
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

int main(int argc, char** argv) {
    int64_t blocks = 8;
    uint32_t seed = 12345u;
    std::string json_out;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--blocks" && i + 1 < argc)    blocks = std::atoll(argv[++i]);
        else if (a == "--seed" && i + 1 < argc) seed = static_cast<uint32_t>(std::atoi(argv[++i]));
        else if (a == "--json" && i + 1 < argc) json_out = argv[++i];
        else if (a == "--help" || a == "-h") {
            std::printf("Usage: %s [--blocks N] [--seed S] [--json out.json]\n", argv[0]);
            return 0;
        }
    }

    std::printf("=== Model Genie capability admission + parity certification ===\n");

    // 1. Bind the kernels Deep2 actually implements (QuantTypeTable.kernelReady).
    QuantParityRegistry::Instance().RegisterBuiltinKernels();
    std::printf("kernel bindings registered from QuantTypeTable geometry\n");

    // 2. Primitive reality.
    PrintPrimitiveTable();

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

    const bool pass = q8k_ok && primitives_ok;
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
            f << j.dump(2);
            std::printf("JSON written: %s\n", json_out.c_str());
        }
    }

    return pass ? 0 : 1;
}
