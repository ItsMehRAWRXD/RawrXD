// Reproducible enterprise closure manifest for Qwen4Exp lowering.
// Hashes every source, shader, SPIR-V, probe, and parity reference involved in
// the path, then records the exact boundary that still blocks ExecuteToken.

#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

struct Artifact { std::string path; bool present = false; std::string sha256; uintmax_t bytes = 0; };
struct Blocker {
    std::string id;
    std::string severity;
    std::string status;
    std::string boundary;
    std::string evidence;
    std::string closure;
};

static std::string Hex(const std::vector<unsigned char>& b) {
    std::ostringstream o; o << std::hex << std::setfill('0');
    for (unsigned char c : b) o << std::setw(2) << static_cast<unsigned>(c);
    return o.str();
}

static bool HashFile(const std::filesystem::path& p, std::string& digest, uintmax_t& bytes) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD hash_len = 0, result = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &result, 0) != 0 || hash_len == 0) {
        BCryptCloseAlgorithmProvider(alg, 0); return false;
    }
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0); return false;
    }
    std::vector<unsigned char> buf(1u << 20); bytes = 0;
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const auto n = in.gcount(); if (n <= 0) break;
        if (BCryptHashData(hash, buf.data(), static_cast<ULONG>(n), 0) != 0) { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0); return false; }
        bytes += static_cast<uintmax_t>(n);
    }
    std::vector<unsigned char> out(hash_len);
    const bool ok = BCryptFinishHash(hash, out.data(), hash_len, 0) == 0;
    if (ok) digest = Hex(out);
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static std::string Json(const std::string& s) {
    std::string o; for (char c : s) { if (c == '\\' || c == '"') o.push_back('\\'); o.push_back(c); } return o;
}

static std::string ReadText(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

int main(int argc, char** argv) {
    if (argc < 3) { std::cerr << "usage: deep2_enterprise_manifest <repo-root> <output-json>\n"; return 2; }
    const std::filesystem::path root = argv[1], out_path = argv[2];
    const std::vector<std::string> paths = {
        "CMakeLists.txt",
        "tools/deep2_enterprise_manifest.cpp",
        "tools/deep2_reverse_engineer.cpp",
        "tools/reverse_engineer_qwen4exp.py",
        "tools/deep2_qwen4exp_pipeline_probe.cpp",
        "src/deep2/runtime_graph_executor.cpp",
        "src/deep2/runtime_graph_executor.hpp",
        "src/deep2/shaders/deep2_qwen4exp_ple.comp",
        "src/deep2/shaders/deep2_qwen4exp_ple.spv",
        "src/deep2/shaders/deep2_qwen4exp_hc_combine.comp",
        "src/deep2/shaders/deep2_qwen4exp_hc_combine.spv",
        "src/deep2/op_gdn.hpp",
        "src/deep2/op_gdn.cpp",
        "src/deep2/op_ple.hpp",
        "src/deep2/op_ple.cpp",
        "src/deep2/op_qsa.hpp",
        "src/deep2/op_qsa.cpp",
        "src/deep2/op_hyperconnection.hpp",
        "src/deep2/op_hyperconnection.cpp",
        "src/deep2/op_sparse_moe.hpp",
        "src/deep2/op_sparse_moe.cpp",
        "tools/deep2_gdn_parity_harness.cpp",
        "tools/deep2_qwen4exp_operator_harness.cpp",
        "tools/deep2_qwen4exp_gdn_probe.cpp",
        "src/deep2/shaders/deep2_qwen4exp_gdn.comp",
        "src/deep2/shaders/deep2_qwen4exp_gdn.spv",
        "src/deep2/shaders/deep2_qwen4exp_qsa_score.comp",
        "src/deep2/shaders/deep2_qwen4exp_qsa_score.spv",
        "src/deep2/shaders/deep2_qwen4exp_moe_router.comp",
        "src/deep2/shaders/deep2_qwen4exp_moe_router.spv",
        "3rdparty/r9700-stack/r9700_vllm/ple/short_conv.py",
        "3rdparty/r9700-stack/r9700_vllm/hc.py",
        "3rdparty/r9700-stack/tests/test_hc_r9k.py",
        "evidence/qwen4exp_operator_contract_20261020/operator_contract.json",
        "evidence/qwen4exp_operator_contract_20261020/native_contract.md",
        "evidence/qwen4exp_manifest_shard1.json",
        "evidence/qwen4exp_manifest_shard2.json",
        "evidence/qwen4exp_pipeline_wiring_20261020.md",
        "evidence/deep2_enterprise_closure_manifest_20261020/native_contract_rerun.md",
        "evidence/deep2_enterprise_closure_manifest_20261020/pipeline_probe_rerun.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/dependency_closure_matrix.md",
        "evidence/deep2_enterprise_closure_manifest_20261020/qwen4exp_blocker_audit.md",
        "evidence/deep2_enterprise_closure_manifest_20261020/README.md",
        "evidence/deep2_enterprise_closure_manifest_20261020/shard_manifest_json_validation.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/qwen4exp_role_reconciliation.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/qwen4exp_full_model_blocked_receipt.json",
        "evidence/deep2_enterprise_closure_manifest_20261020/gdn_reference_harness.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/gdn_spirv_validation.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/gdn_component_probe.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/operator_harness.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/operator_spirv_validation.txt",
        "evidence/QWEN4EXP_OPERATOR_IMPLEMENTATION_20261020.md",
        "evidence/qwen4exp_gr_source_drop_20261020/Qwen4ExpGatedResidual.hpp",
        "evidence/qwen4exp_gr_source_drop_20261020/test_gr.cpp",
        "evidence/qwen4exp_gr_source_drop_20261020/QWEN4EXP_FAIL_CLOSED_INVENTORY.md",
        "evidence/qwen4exp_gr_source_drop_20261020/PROVENANCE.md"
    };
    std::vector<Artifact> artifacts; bool all_present = true;
    for (const auto& rel : paths) {
        Artifact a; a.path = rel; a.present = HashFile(root / rel, a.sha256, a.bytes); all_present &= a.present; artifacts.push_back(std::move(a));
    }
    const std::string contract = ReadText(root / "evidence/qwen4exp_operator_contract_20261020/native_contract.md");
    const std::string operator_contract = ReadText(root / "evidence/qwen4exp_operator_contract_20261020/operator_contract.json");
    const std::string manifest_shard1 = ReadText(root / "evidence/qwen4exp_manifest_shard1.json");
    const std::string manifest_shard2 = ReadText(root / "evidence/qwen4exp_manifest_shard2.json");
    const std::string pipeline = ReadText(root / "evidence/qwen4exp_pipeline_wiring_20261020.md");
    const std::string contract_rerun = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/native_contract_rerun.md");
    const std::string pipeline_rerun = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/pipeline_probe_rerun.txt");
    const std::string executor = ReadText(root / "src/deep2/runtime_graph_executor.cpp");
    const std::string gr_inventory = ReadText(root / "evidence/qwen4exp_gr_source_drop_20261020/QWEN4EXP_FAIL_CLOSED_INVENTORY.md");
    const std::string full_model_receipt = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/qwen4exp_full_model_blocked_receipt.json");
    const std::string gdn_harness = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/gdn_reference_harness.txt");
    const std::string gdn_spirv = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/gdn_spirv_validation.txt");
    const std::string gdn_component_probe = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/gdn_component_probe.txt");
    const std::string operator_harness = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/operator_harness.txt");
    const std::string operator_spirv = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/operator_spirv_validation.txt");
    const std::string role_reconciliation = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/qwen4exp_role_reconciliation.txt");
    const bool execute_token_has_qwen_cases = [&]() {
        const auto start = executor.find("bool Executor::ExecuteToken");
        if (start == std::string::npos) return false;
        const std::string body = executor.substr(start);
        return body.find("case OpKind::Qsa") != std::string::npos &&
               body.find("case OpKind::Gdn") != std::string::npos &&
               body.find("case OpKind::Ple") != std::string::npos &&
               body.find("case OpKind::Hyperconnection") != std::string::npos &&
               body.find("case OpKind::SparseMoE") != std::string::npos;
    }();
    const bool contract_geometry = contract.find("Tensors: 1224") != std::string::npos &&
                                   contract.find("Geometry checks: PASS") != std::string::npos &&
                                   contract_rerun.find("Tensors: 1224") != std::string::npos &&
                                   contract_rerun.find("Geometry checks: PASS") != std::string::npos;
    const bool pipeline_wiring = pipeline.find("PLE_PIPELINE=PASS") != std::string::npos &&
                                 pipeline.find("HC_PIPELINE=PASS") != std::string::npos &&
                                 pipeline.find("GDN_PIPELINE=PASS") != std::string::npos &&
                                 pipeline_rerun.find("PLE_PIPELINE=PASS") != std::string::npos &&
                                 pipeline_rerun.find("HC_PIPELINE=PASS") != std::string::npos &&
                                 pipeline_rerun.find("GDN_PIPELINE=PASS") != std::string::npos &&
                                 pipeline_rerun.find("DISPATCHES=0") != std::string::npos &&
                                 pipeline_rerun.find("EXECUTION=NOT_RUN") != std::string::npos;
    const bool executor_fail_closed = executor.find("qwen4exp_unbound") != std::string::npos &&
                                      executor.find("OpKind::Qsa") != std::string::npos &&
                                      executor.find("OpKind::SparseMoE") != std::string::npos;
    const bool gr_reference_cpu_only = gr_inventory.find("isolated CPU arithmetic-contract tested only") != std::string::npos &&
                                       gr_inventory.find("full-model certificate") != std::string::npos;
    const bool full_model_blocked = full_model_receipt.find("\"status\":\"BLOCKED_NATIVE_GRAPH\"") != std::string::npos &&
                                    full_model_receipt.find("\"execution_status\":\"NOT_RUN\"") != std::string::npos &&
                                    full_model_receipt.find("\"unsupported_ops\":5") != std::string::npos &&
                                    full_model_receipt.find("\"tensor_count\":1224") != std::string::npos;
    const bool gdn_reference = gdn_harness.find("GDN_GEOMETRY=PASS") != std::string::npos &&
                               gdn_harness.find("GDN_REFERENCE_FINITE=PASS") != std::string::npos &&
                               gdn_harness.find("GDN_STATE_CONTINUITY=PASS") != std::string::npos &&
                               gdn_harness.find("GDN_GPU_DISPATCHES=0") != std::string::npos &&
                               gdn_spirv.find("SPIRV_VAL=PASS") != std::string::npos;
    const bool gdn_component_dispatch = gdn_component_probe.find("GDN_DISPATCHES=1 GDN_EXECUTION=PASS") != std::string::npos &&
                                         gdn_component_probe.find("GDN_INDEPENDENT_PARITY=PASS") != std::string::npos;
    const bool operator_contract_pass =
        operator_harness.find("PLE_GEOMETRY=PASS") != std::string::npos &&
        operator_harness.find("HC_GEOMETRY=PASS") != std::string::npos &&
        operator_harness.find("QSA_GEOMETRY=PASS") != std::string::npos &&
        operator_harness.find("SPARSE_MOE_ROUTE=PASS") != std::string::npos &&
        operator_harness.find("SPARSE_MOE_EXPERT_EXECUTION=FAIL_CLOSED_UNDEQUANTIZED") != std::string::npos &&
        operator_harness.find("QWEN4EXP_OPERATOR_HARNESS=PASS") != std::string::npos;
    const bool operator_spirv_pass =
        operator_spirv.find("PLE_SPIRV_VAL=PASS") != std::string::npos &&
        operator_spirv.find("HC_SPIRV_VAL=PASS") != std::string::npos &&
        operator_spirv.find("QSA_SCORE_SPIRV_VAL=PASS") != std::string::npos &&
        operator_spirv.find("MOE_ROUTER_SPIRV_VAL=PASS") != std::string::npos &&
        operator_spirv.find("GDN_SPIRV_VAL=PASS") != std::string::npos;
    const bool contract_report_reconciled =
        contract_rerun.find("Ownership reconciliation: GDN 216+36, PLE 6+1, HYPERCONNECTION 384+3") != std::string::npos &&
        contract_rerun.find("| GDN | 252 | 216 | 36 |") != std::string::npos &&
        contract_rerun.find("| PLE | 7 | 6 | 1 |") != std::string::npos &&
        contract_rerun.find("| HYPERCONNECTION | 387 | 384 | 3 |") != std::string::npos;
    const bool canonical_role_schema =
        operator_contract.find("\"primary_tensor_count\": 216") != std::string::npos &&
        operator_contract.find("\"auxiliary_tensor_count\": 36") != std::string::npos &&
        operator_contract.find("\"primary_tensor_count\": 6") != std::string::npos &&
        operator_contract.find("\"auxiliary_tensor_count\": 1") != std::string::npos &&
        operator_contract.find("\"primary_tensor_count\": 384") != std::string::npos &&
        operator_contract.find("\"auxiliary_tensor_count\": 3") != std::string::npos;
    const bool shard_manifests_json_valid =
        manifest_shard1.find("F:\\OllamaModels") == std::string::npos &&
        manifest_shard2.find("F:\\OllamaModels") == std::string::npos;
    const bool role_reconciliation_explained =
        role_reconciliation.find("UNIQUE_TENSOR_NAMES=1224") != std::string::npos &&
        role_reconciliation.find("DUPLICATE_NAME_GROUPS=0") != std::string::npos &&
        role_reconciliation.find("GDN_AUXILIARY=36") != std::string::npos &&
        role_reconciliation.find("PLE_AUXILIARY=1") != std::string::npos &&
        role_reconciliation.find("HYPERCONNECTION_AUXILIARY=3") != std::string::npos;
    std::vector<Blocker> blockers = {
        {"QWEN-B01", "CRITICAL", executor_fail_closed ? "BLOCKED" : "NOT_VERIFIED",
         "Executor::Bind admission", "runtime_graph_executor.cpp:768-772; qwen4exp_full_model_blocked_receipt.json:unsupported_ops=5",
         "Implement and bind every QSA/GDN/PLE/Hyperconnection/SparseMoE graph node before allowing Bind to succeed."},
        {"QWEN-B02", "CRITICAL", execute_token_has_qwen_cases ? "IMPLEMENTED_UNVERIFIED" : "BLOCKED",
         "Executor::ExecuteToken lowering", "runtime_graph_executor.cpp:3461 onward; no Qwen4Exp case labels in ExecuteToken",
         "Add descriptor allocation, tensor upload/binding, command recording, dispatch, completion, and arena/state publication for each OpKind."},
        {"QWEN-B03", "CRITICAL", pipeline_wiring ? "NOT_RUN" : "NOT_VERIFIED",
         "Physical command submission", "pipeline_probe_rerun.txt: DISPATCHES=0 EXECUTION=NOT_RUN",
         "Submit real buffers through the production executor, wait on a fence/timeline, and record nonzero GPU dispatches plus output parity."},
        {"QWEN-B04", "CRITICAL", "BLOCKED",
         "QSA lowering and cache", "operator_contract.json:native_execution.QSA=false; no QSA shader/pipeline artifact is in the closure manifest",
         "Implement indexer projections, compressed-key scoring/top-K causal selection, rotary positions, KV updates, and long-context cache continuity."},
        {"QWEN-B05", "CRITICAL", "BLOCKED",
         "SparseMoE lowering and residency", "operator_contract.json:native_execution.SparseMoE=false; dependency matrix: no native top-K/grouped-GEMM executor",
         "Implement deterministic top-10-of-512 routing, shared/routed expert scaling, MXFP4/IQ2 grouped GEMM, expert residency, and GPU parity."},
        {"QWEN-B06", "HIGH", gdn_component_dispatch ? "COMPONENT_DISPATCH_PASS" : (gdn_reference ? "REFERENCE_ONLY" : "NOT_VERIFIED"),
         "GDN production dispatch", gdn_component_dispatch
             ? "gdn_component_probe.txt:GDN_DISPATCHES=1/GDN_EXECUTION=PASS/GDN_INDEPENDENT_PARITY=PASS; this is isolated, not ExecuteToken"
             : "gdn_reference_harness.txt:GDN_REFERENCE_FINITE=PASS/GDN_STATE_CONTINUITY=PASS/GDN_GPU_DISPATCHES=0",
         "Bind the verified GDN descriptors and state lifecycle into the Qwen4Exp Executor graph, then repeat parity through ExecuteToken."},
        {"QWEN-B07", "HIGH", "NOT_RUN",
         "PLE and Hyperconnection production dispatch", "pipeline_probe_rerun.txt:PLE_PIPELINE=PASS HC_PIPELINE=PASS but DISPATCHES=0",
         "Allocate real tensor/state buffers, dispatch both pipelines, compare outputs against independent references, and wire them into ExecuteToken."},
        {"QWEN-B08", "HIGH", gr_reference_cpu_only ? "REFERENCE_ONLY" : "NOT_VERIFIED",
         "Gated Residual production path", "QWEN4EXP_FAIL_CLOSED_INVENTORY.md: isolated CPU arithmetic-contract tested only",
         "Implement GPU GR read/write/combine in the production graph and prove finite independent parity with zero CPU fallback."},
        {"QWEN-B09", "CRITICAL", "NOT_RUN",
         "Full-model independent parity", "qwen4exp_full_model_blocked_receipt.json:execution_status=NOT_RUN; gpu_calls=0; cpu_calls=0",
         "Run every layer and expert path on the complete two-shard model, compare full logits and intermediate checkpoints to an independent oracle."},
        {"QWEN-B10", "CRITICAL", full_model_blocked ? "BLOCKED" : "NOT_VERIFIED",
         "Autoregressive generation and certification", "qwen4exp_full_model_blocked_receipt.json:status=BLOCKED_NATIVE_GRAPH/certification_status=NOT_CERTIFIED",
         "Only after all operators execute, run deterministic multi-token decode, cache continuity, repeated output, and issue a full-model certificate."},
        {"QWEN-B11", "HIGH", (role_reconciliation_explained && contract_report_reconciled && canonical_role_schema) ? "PASS" : (role_reconciliation_explained ? "EXPLAINED_RECONCILIATION_REQUIRED" : "RECONCILIATION_REQUIRED"),
         "Source-to-contract tensor-role ownership", role_reconciliation_explained
             ? "qwen4exp_role_reconciliation.txt:1224 unique names, zero duplicates; native excess is 36 ssm_dt.bias + 1 global per_layer_token_embd + 3 global output_hc tensors"
             : "native_contract_rerun.md reports GDN=252/PLE=7/HC=387 while operator_contract.json records GDN=216/PLE=6/HC=384",
         "Extend the canonical contract with explicit primary block ownership plus auxiliary/global ownership, then make descriptor binding consume that authoritative map."},
        {"QWEN-B12", "CRITICAL", shard_manifests_json_valid ? "PASS" : "BLOCKED",
         "Shard manifest parseability", "qwen4exp_manifest_shard1.json and shard2.json contain unescaped Windows paths; ConvertFrom-Json fails with Bad JSON escape sequence: \\\\O",
         "Regenerate or normalize both manifests with valid JSON escaping, validate with an independent parser, then rerun ownership reconciliation."}
        ,{"QWEN-B13", "CRITICAL", (operator_contract_pass && operator_spirv_pass) ? "COMPONENT_CONTRACT_PASS" : "NOT_VERIFIED",
         "Operator source and shader closure", operator_contract_pass && operator_spirv_pass
             ? "operator_harness.txt: PLE/HC/QSA/router contracts pass; expert execution remains explicitly fail-closed; operator_spirv_validation.txt: all five validators pass"
             : "operator_harness.txt or operator_spirv_validation.txt is missing a required receipt",
         "Connect every validated operator to production graph execution, add real GPU probes for PLE/HC/QSA/router, and certify IQ2_S/MXFP4 expert GEMM before full-model admission."}
    };
    all_present = all_present && contract_geometry && pipeline_wiring && executor_fail_closed && gr_reference_cpu_only && full_model_blocked && gdn_reference && operator_contract_pass && operator_spirv_pass;
    std::filesystem::create_directories(out_path.parent_path());
    std::ofstream out(out_path); if (!out) return 3;
    out << "{\n  \"schema\":\"rawrxd.deep2.enterprise_closure_manifest.v1\",\n";
    out << "  \"source_to_parity_integrity\":\"" << (all_present ? "PASS" : "FAIL") << "\",\n";
    out << "  \"contract_geometry\":\"" << (contract_geometry ? "PASS" : "FAIL") << "\",\n";
    out << "  \"pipeline_wiring\":\"" << (pipeline_wiring ? "PASS" : "FAIL") << "\",\n";
    out << "  \"executor_fail_closed_boundary\":\"" << (executor_fail_closed ? "PRESENT" : "NOT_VERIFIED") << "\",\n";
    out << "  \"gr_reference\":\"" << (gr_reference_cpu_only ? "CPU_ONLY_NOT_EXECUTOR" : "NOT_VERIFIED") << "\",\n";
    out << "  \"GR_REFERENCE_ARITHMETIC\":\"" << (gr_reference_cpu_only ? "PASS_REPORTED" : "NOT_VERIFIED") << "\",\n";
    out << "  \"GR_PRODUCTION_DISPATCH\":\"NOT_RUN\",\n";
    out << "  \"GR_PIPELINE_INTEGRATION\":\"NOT_RUN\",\n";
    out << "  \"GR_INDEPENDENT_PARITY\":\"NOT_RUN\",\n";
    out << "  \"QWEN4EXP_FULL_MODEL\":\"BLOCKED\",\n";
    out << "  \"full_model_attempt\":\"" << (full_model_blocked ? "BLOCKED_NATIVE_GRAPH" : "NOT_VERIFIED") << "\",\n";
    out << "  \"GDN_REFERENCE_ARITHMETIC\":\"" << (gdn_reference ? "PASS" : "NOT_VERIFIED") << "\",\n";
    out << "  \"GDN_SHADER_VALIDATION\":\"" << (gdn_reference ? "PASS" : "NOT_VERIFIED") << "\",\n";
    out << "  \"GDN_COMPONENT_DISPATCH\":\"" << (gdn_component_dispatch ? "PASS" : "NOT_RUN") << "\",\n";
    out << "  \"GDN_PRODUCTION_DISPATCH\":\"NOT_RUN\",\n";
    out << "  \"QWEN4EXP_OPERATOR_CONTRACT\":\"" << (operator_contract_pass ? "PASS" : "NOT_VERIFIED") << "\",\n";
    out << "  \"QWEN4EXP_OPERATOR_SPIRV\":\"" << (operator_spirv_pass ? "PASS" : "NOT_VERIFIED") << "\",\n";
    out << "  \"command_submission\":\"NOT_RUN\",\n  \"full_model_execution\":\"NOT_RUN\",\n  \"certification\":\"NOT_CERTIFIED\",\n";
    out << "  \"contract_reconciliation\":\"" << (contract_report_reconciled && canonical_role_schema ? "PASS" : "RECONCILIATION_REQUIRED") << "\",\n";
    out << "  \"role_reconciliation\":\"" << ((role_reconciliation_explained && contract_report_reconciled && canonical_role_schema) ? "PASS" : (role_reconciliation_explained ? "EXPLAINED_RECONCILIATION_REQUIRED" : "RECONCILIATION_REQUIRED")) << "\",\n";
    out << "  \"shard_manifest_json\":\"" << (shard_manifests_json_valid ? "PASS" : "FAIL") << "\",\n";
    out << "  \"executor_blocking_boundary\":\"Executor::Bind still rejects QSA, GDN, PLE, Hyperconnection, and SparseMoE; ExecuteToken has no descriptor allocation, tensor upload, command recording, or dispatch cases for these OpKinds.\",\n";
    out << "  \"required_closure\":\"Wire Qwen4Exp tensor handles to descriptor updates and command submission in ExecuteToken, then run independent full-logit and autoregressive parity.\",\n";
    out << "  \"blockers\":[\n";
    for (size_t i = 0; i < blockers.size(); ++i) {
        const auto& b = blockers[i];
        out << "    {\"id\":\"" << Json(b.id) << "\",\"severity\":\"" << Json(b.severity)
            << "\",\"status\":\"" << Json(b.status) << "\",\"boundary\":\"" << Json(b.boundary)
            << "\",\"evidence\":\"" << Json(b.evidence) << "\",\"closure\":\"" << Json(b.closure)
            << "\"}" << (i + 1 == blockers.size() ? "\n" : ",\n");
    }
    out << "  ],\n";
    out << "  \"artifacts\":[\n";
    for (size_t i = 0; i < artifacts.size(); ++i) {
        const auto& a = artifacts[i];
        out << "    {\"path\":\"" << Json(a.path) << "\",\"present\":" << (a.present ? "true" : "false")
            << ",\"bytes\":" << a.bytes << ",\"sha256\":\"" << a.sha256 << "\"}" << (i + 1 == artifacts.size() ? "\n" : ",\n");
    }
    out << "  ]\n}\n";
    std::cout << "MANIFEST=" << out_path.string() << "\nSOURCE_PARITY_INTEGRITY=" << (all_present ? "PASS" : "FAIL")
              << "\nCONTRACT_GEOMETRY=" << (contract_geometry ? "PASS" : "FAIL")
              << "\nPIPELINE_WIRING=" << (pipeline_wiring ? "PASS" : "FAIL")
              << "\nEXECUTOR_BOUNDARY=" << (executor_fail_closed ? "Bind-rejects-unimplemented-Qwen4Exp-OpKinds" : "NOT_VERIFIED")
              << "\nCERTIFICATION=NOT_CERTIFIED\n";
    return all_present ? 0 : 4;
}
