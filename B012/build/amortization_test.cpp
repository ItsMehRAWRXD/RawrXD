// B012 — Amortization Crossover Experiment
// Measures wall/prefill/decode time for B010 (no cache) vs B011 (with cache)
// across varying decode lengths to find the crossover point.
//
// Usage:
//   b012_amortization_test.exe <decode_length> <mode>
//   mode: 0 = B010 (no cache), 1 = B011 (with cache)
//
// Output: structured JSON lines to stdout for downstream analysis.

#include "cpu_inference_engine.h"
#include "rawrxd_inference.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>

namespace {

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) {
        return {};
    }
#ifdef _WIN32
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring w;
    w.resize(static_cast<size_t>(len));
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], len);
    if (!w.empty() && w.back() == L'\0') {
        w.pop_back();
    }
    return w;
#else
    return std::wstring(s.begin(), s.end());
#endif
}

// High-resolution timer using QueryPerformanceCounter on Windows
int64_t NowNs() {
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000000LL) / freq.QuadPart;
#else
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
#endif
}

void PrintJsonLine(const std::string& key, const std::string& value, bool last = false) {
    std::cout << "  \"" << key << "\": " << value;
    if (!last) std::cout << ",";
    std::cout << "\n";
}

void PrintJsonLine(const std::string& key, int64_t value, bool last = false) {
    std::cout << "  \"" << key << "\": " << value;
    if (!last) std::cout << ",";
    std::cout << "\n";
}

void PrintJsonLine(const std::string& key, double value, bool last = false) {
    std::cout << "  \"" << key << "\": " << value;
    if (!last) std::cout << ",";
    std::cout << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <decode_length> <mode>\n";
        std::cerr << "  decode_length: number of tokens to generate (1,2,8,16,32,64,128,256)\n";
        std::cerr << "  mode: 0 = B010 (no cache), 1 = B011 (with cache)\n";
        return 1;
    }

    const int decodeLength = std::atoi(argv[1]);
    const int mode = std::atoi(argv[2]);
    if (decodeLength < 1 || decodeLength > 8192) {
        std::cerr << "FAIL: decode_length out of range\n";
        return 1;
    }
    if (mode != 0 && mode != 1) {
        std::cerr << "FAIL: mode must be 0 or 1\n";
        return 1;
    }

    const char* modelEnv = std::getenv("RAWRXD_TEST_MODEL");
    if (!modelEnv || !*modelEnv) {
        std::cout << "SKIP: set RAWRXD_TEST_MODEL to run B012 amortization test\n";
        return 0;
    }

    const std::string modelPath(modelEnv);
    if (!std::filesystem::exists(modelPath)) {
        std::cerr << "FAIL: model path does not exist: " << modelPath << "\n";
        return 2;
    }

    std::filesystem::path modelDir = std::filesystem::path(modelPath).parent_path();
    const std::string vocabPath = (modelDir / "tokenizer.json").string();
    const std::string mergesPath = (modelDir / "merges.txt").string();

    auto* inference = new RawrXDInference();
    if (!inference->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str())) {
        std::cerr << "FAIL: RawrXDInference::Initialize failed\n";
        return 3;
    }

    const std::vector<uint32_t> promptTokens = inference->Tokenize("Hi");
    if (promptTokens.empty()) {
        std::cerr << "FAIL: tokenization returned empty prompt tokens\n";
        return 4;
    }

    // Configure mode
    if (mode == 0) {
        // B010: no cache
        inference->GetLoader().B011EnableResidency(false);
        inference->GetLoader().B011ClearResidency();
        inference->GetLoader().ResetWeightProfile();
    } else {
        // B011: with cache
        inference->GetLoader().B011ClearResidency();
        inference->GetLoader().B011ResetResidencyStats();
        inference->GetLoader().B011EnableResidency(true);
    }

    size_t callbackCount = 0;
    std::vector<uint32_t> generated;

    // Measure total wall time
    const int64_t tWallStart = NowNs();

    // Measure prefill time (first Forward call inside GenerateFromTokens)
    // We approximate prefill as the time until first callback
    int64_t tPrefillEnd = 0;
    int64_t tFirstCallback = 0;
    bool firstCallbackSeen = false;

    generated = inference->GenerateFromTokens(promptTokens, static_cast<uint32_t>(decodeLength),
        [&](uint32_t token, const std::string& text) {
            if (!firstCallbackSeen) {
                tFirstCallback = NowNs();
                firstCallbackSeen = true;
            }
            ++callbackCount;
        });

    const int64_t tWallEnd = NowNs();

    // Gather stats
    const int64_t wallNs = tWallEnd - tWallStart;
    const int64_t prefillNs = firstCallbackSeen ? (tFirstCallback - tWallStart) : wallNs;
    const int64_t decodeNs = firstCallbackSeen ? (tWallEnd - tFirstCallback) : 0;

    // Print structured JSON result
    std::cout << "{\n";
    PrintJsonLine("experiment", "\"B012\"");
    PrintJsonLine("decode_length", static_cast<int64_t>(decodeLength));
    PrintJsonLine("mode", mode == 0 ? "\"B010\"" : "\"B011\"");
    PrintJsonLine("prompt_tokens", static_cast<int64_t>(promptTokens.size()));
    PrintJsonLine("generated_tokens", static_cast<int64_t>(generated.size()));
    PrintJsonLine("callback_count", static_cast<int64_t>(callbackCount));
    PrintJsonLine("wall_time_ms", wallNs / 1000000);
    PrintJsonLine("prefill_time_ms", prefillNs / 1000000);
    PrintJsonLine("decode_time_ms", decodeNs / 1000000);

    if (mode == 0) {
        // B010: print weight profile
        inference->GetLoader().PrintWeightProfile();
    } else {
        // B011: print residency stats
        inference->GetLoader().B011PrintResidencyStats();
    }

    // Token validation
    if (generated.empty()) {
        std::cerr << "FAIL: generation produced no tokens\n";
        return 5;
    }
    if (callbackCount == 0) {
        std::cerr << "FAIL: GenerateFromTokens callback never fired\n";
        return 6;
    }

    std::cout << "  \"status\": \"PASS\"\n";
    std::cout << "}\n";
    std::cout.flush();
    std::fflush(stdout);

    std::quick_exit(0);
}
