// B014 — Compute Decomposition Measurement Harness
// Runs a deterministic inference workload with B014 profiling enabled,
// then exports per-invocation timing decomposition (JSON + CSV).
//
// Usage:
//   b014_compute_decomposition.exe <model_path> [prompt] [decode_length]
//
// Output:
//   B014/logs/B014_compute_profile.json
//   B014/logs/B014_compute_profile.csv
//   Summary printed to stdout

#include "cpu_inference_engine.h"
#include "rawrxd_inference.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) { return {}; }
#ifdef _WIN32
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) { return {}; }
    std::wstring w;
    w.resize(static_cast<size_t>(len));
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], len);
    if (!w.empty() && w.back() == L'\0') { w.pop_back(); }
    return w;
#else
    return std::wstring(s.begin(), s.end());
#endif
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model_path> [prompt] [decode_length]\n";
        std::cerr << "  default prompt: \"The quick brown fox\"\n";
        std::cerr << "  default decode_length: 16\n";
        return 1;
    }

    const std::string modelPath = argv[1];
    if (!std::filesystem::exists(modelPath)) {
        std::cerr << "FAIL: model path does not exist: " << modelPath << "\n";
        return 2;
    }

    const std::string prompt = (argc > 2) ? argv[2] : "The quick brown fox";
    const uint32_t decodeLength = (argc > 3) ? static_cast<uint32_t>(std::atoi(argv[3])) : 16;

    // Tokenizer files are optional; byte-level fallback is used if absent
    std::filesystem::path modelDir = std::filesystem::path(modelPath).parent_path();
    std::string vocabPath = (modelDir / "tokenizer.json").string();
    std::string mergesPath = (modelDir / "merges.txt").string();
    if (!std::filesystem::exists(vocabPath)) vocabPath.clear();
    if (!std::filesystem::exists(mergesPath)) mergesPath.clear();

    // Create output directories
    std::filesystem::create_directories("B014/logs");
    std::filesystem::create_directories("B014/performance");

    std::cout << "{\n";
    std::cout << "  \"experiment\": \"B014\",\n";
    std::cout << "  \"model\": \"" << modelPath << "\",\n";
    std::cout << "  \"prompt\": \"" << prompt << "\",\n";
    std::cout << "  \"decode_length\": " << decodeLength << ",\n";

    // Initialize inference
    auto* inference = new RawrXDInference();
    if (!inference->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str())) {
        std::cerr << "  \"status\": \"FAIL\",\n";
        std::cerr << "  \"reason\": \"Inference initialization failed\"\n}\n";
        delete inference;
        return 3;
    }

    // Enable B014 profiling
    inference->GetLoader().B014EnableProfiling(true);
    inference->GetLoader().B014ClearProfile();

    // Tokenize prompt
    std::vector<uint32_t> promptTokens;
    {
        auto tokens = inference->Tokenize(prompt);
        promptTokens.assign(tokens.begin(), tokens.end());
    }

    // Run deterministic generation
    std::cout << "  \"generation_started\": true,\n";
    auto generated = inference->GenerateFromTokens(promptTokens, decodeLength,
        [&](uint32_t token, const std::string& text) {
            // No-op callback — deterministic workload
        });

    std::cout << "  \"tokens_generated\": " << generated.size() << ",\n";

    // Export B014 profile
    const std::string jsonPath = "B014/logs/B014_compute_profile.json";
    const std::string csvPath = "B014/logs/B014_compute_profile.csv";
    bool jsonOk = inference->GetLoader().B014ExportProfileJson(jsonPath);
    bool csvOk = inference->GetLoader().B014ExportProfileCsv(csvPath);

    // Get summary
    auto summary = inference->GetLoader().B014ComputeSummary();

    std::cout << "  \"profile_export_json\": " << (jsonOk ? "true" : "false") << ",\n";
    std::cout << "  \"profile_export_csv\": " << (csvOk ? "true" : "false") << ",\n";
    std::cout << "  \"summary\": {\n";
    std::cout << "    \"total_invocations\": " << summary.totalInvocations << ",\n";
    std::cout << "    \"total_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(summary.totalNs) / 1.0e6) << ",\n";
    std::cout << "    \"mean_total_ms\": " << std::fixed << std::setprecision(3) << summary.meanTotalMs << ",\n";
    std::cout << "    \"mean_acq_ms\": " << std::fixed << std::setprecision(3) << (summary.totalInvocations > 0 ? (static_cast<double>(summary.totalAcqNs) / 1.0e6 / summary.totalInvocations) : 0.0) << ",\n";
    std::cout << "    \"mean_dequant_ms\": " << std::fixed << std::setprecision(3) << summary.meanDequantMs << ",\n";
    std::cout << "    \"mean_dot_ms\": " << std::fixed << std::setprecision(3) << summary.meanDotMs << ",\n";
    std::cout << "    \"mean_overhead_ms\": " << std::fixed << std::setprecision(3) << summary.meanOverheadMs << ",\n";
    std::cout << "    \"acq_pct\": " << std::fixed << std::setprecision(2) << summary.acqPct << ",\n";
    std::cout << "    \"dequant_pct\": " << std::fixed << std::setprecision(2) << summary.dequantPct << ",\n";
    std::cout << "    \"dot_pct\": " << std::fixed << std::setprecision(2) << summary.dotPct << ",\n";
    std::cout << "    \"overhead_pct\": " << std::fixed << std::setprecision(2) << summary.overheadPct << "\n";
    std::cout << "  },\n";
    std::cout << "  \"status\": \"PASS\"\n";
    std::cout << "}\n";

    delete inference;
    return 0;
}
