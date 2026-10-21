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
        "tools/deep2_gdn_parity_harness.cpp",
        "src/deep2/shaders/deep2_qwen4exp_gdn.comp",
        "src/deep2/shaders/deep2_qwen4exp_gdn.spv",
        "3rdparty/r9700-stack/r9700_vllm/ple/short_conv.py",
        "3rdparty/r9700-stack/r9700_vllm/hc.py",
        "3rdparty/r9700-stack/tests/test_hc_r9k.py",
        "evidence/qwen4exp_operator_contract_20261020/operator_contract.json",
        "evidence/qwen4exp_operator_contract_20261020/native_contract.md",
        "evidence/qwen4exp_pipeline_wiring_20261020.md",
        "evidence/deep2_enterprise_closure_manifest_20261020/native_contract_rerun.md",
        "evidence/deep2_enterprise_closure_manifest_20261020/pipeline_probe_rerun.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/dependency_closure_matrix.md",
        "evidence/deep2_enterprise_closure_manifest_20261020/qwen4exp_full_model_blocked_receipt.json",
        "evidence/deep2_enterprise_closure_manifest_20261020/gdn_reference_harness.txt",
        "evidence/deep2_enterprise_closure_manifest_20261020/gdn_spirv_validation.txt",
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
    const std::string pipeline = ReadText(root / "evidence/qwen4exp_pipeline_wiring_20261020.md");
    const std::string contract_rerun = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/native_contract_rerun.md");
    const std::string pipeline_rerun = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/pipeline_probe_rerun.txt");
    const std::string executor = ReadText(root / "src/deep2/runtime_graph_executor.cpp");
    const std::string gr_inventory = ReadText(root / "evidence/qwen4exp_gr_source_drop_20261020/QWEN4EXP_FAIL_CLOSED_INVENTORY.md");
    const std::string full_model_receipt = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/qwen4exp_full_model_blocked_receipt.json");
    const std::string gdn_harness = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/gdn_reference_harness.txt");
    const std::string gdn_spirv = ReadText(root / "evidence/deep2_enterprise_closure_manifest_20261020/gdn_spirv_validation.txt");
    const bool contract_geometry = contract.find("Tensors: 1224") != std::string::npos &&
                                   contract.find("Geometry checks: PASS") != std::string::npos &&
                                   contract_rerun.find("Tensors: 1224") != std::string::npos &&
                                   contract_rerun.find("Geometry checks: PASS") != std::string::npos;
    const bool pipeline_wiring = pipeline.find("PLE_PIPELINE=PASS") != std::string::npos &&
                                 pipeline.find("HC_PIPELINE=PASS") != std::string::npos &&
                                 pipeline_rerun.find("PLE_PIPELINE=PASS") != std::string::npos &&
                                 pipeline_rerun.find("HC_PIPELINE=PASS") != std::string::npos &&
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
    all_present = all_present && contract_geometry && pipeline_wiring && executor_fail_closed && gr_reference_cpu_only && full_model_blocked && gdn_reference;
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
    out << "  \"GDN_PRODUCTION_DISPATCH\":\"NOT_RUN\",\n";
    out << "  \"command_submission\":\"NOT_RUN\",\n  \"full_model_execution\":\"NOT_RUN\",\n  \"certification\":\"NOT_CERTIFIED\",\n";
    out << "  \"executor_blocking_boundary\":\"Executor::Bind still rejects QSA, GDN, PLE, Hyperconnection, and SparseMoE; ExecuteToken has no descriptor allocation, tensor upload, command recording, or dispatch cases for these OpKinds.\",\n";
    out << "  \"required_closure\":\"Wire Qwen4Exp tensor handles to descriptor updates and command submission in ExecuteToken, then run independent full-logit and autoregressive parity.\",\n";
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
