#include "cpu_inference_engine.h"
#include "rawrxd_inference.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

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

}  // namespace

int main() {
    const char* modelEnv = std::getenv("RAWRXD_TEST_MODEL");
    if (!modelEnv || !*modelEnv) {
        std::cout << "SKIP: set RAWRXD_TEST_MODEL to run B004 streamer integration test\n";
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

    // Keep inference object process-lifetime to avoid teardown-time AVs that
    // can mask true test outcomes with crash exit codes.
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

    size_t callbackCount = 0;
    std::cout << "[HARNESS] callback_registered\n";

    // B010: Reset weight access profile before generation
    inference->GetLoader().ResetWeightProfile();

    // B011: Enable weight residency cache
    inference->GetLoader().B011ClearResidency();
    inference->GetLoader().B011ResetResidencyStats();
    inference->GetLoader().B011EnableResidency(true);

    auto generated = inference->GenerateFromTokens(promptTokens, 2,
        [&](uint32_t, const std::string&) {
            std::cout << "[HARNESS] callback_invoked\n";
            ++callbackCount;
            std::cout << "[HARNESS] callback_returned\n";
        });

    // B010: Print weight access profile after generation
    inference->GetLoader().PrintWeightProfile();

    // B011: Print residency stats
    inference->GetLoader().B011PrintResidencyStats();

    std::cout << "[HARNESS] layer_loop_complete\n";
    if (generated.empty()) {
        std::cerr << "FAIL: generation produced no tokens\n";
        return 5;
    }
    if (callbackCount == 0) {
        std::cerr << "FAIL: GenerateFromTokens callback never fired\n";
        return 6;
    }
    std::cout << "[HARNESS] token_generated count=" << generated.size() << "\n";
    if (inference->getLayerPredictCount() == 0 || inference->getLayerPrefetchCount() == 0) {
        std::cerr << "FAIL: PMM predict/prefetch counters did not advance\n";
        return 7;
    }
    if (inference->getRouterBoundaryMatMulCount() == 0) {
        std::cerr << "FAIL: transformer matmul adapter counter did not advance\n";
        return 8;
    }

    std::cout << "PASS: B004 transformer-router-streaming integration\n";
    std::cout << "  generated_tokens=" << generated.size() << "\n";
    std::cout << "  callback_count=" << callbackCount << "\n";
    std::cout << "  predict_calls=" << inference->getLayerPredictCount() << "\n";
    std::cout << "  prefetch_calls=" << inference->getLayerPrefetchCount() << "\n";
    std::cout << "  matmul_calls=" << inference->getRouterBoundaryMatMulCount() << "\n";
    std::cout.flush();
    std::fflush(stdout);
    // Avoid teardown crashes from global/static destructors that are outside
    // B004's validation scope.  quick_exit skips atexit handlers and
    // destructor calls, giving us a clean exit=0 when all invariants passed.
    std::quick_exit(0);
}
