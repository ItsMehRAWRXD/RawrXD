// B014 — Single Boundary Probe: Test ONE boundary per invocation
// Usage: b014_single_boundary.exe <model_path> <boundary_id> [prompt]
//   boundary_id: 1=ModelLoad, 2=Tokenize, 3=Forward, 4=Forward+B014, 5=OneDecode+B014

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

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <model_path> <boundary_id> [prompt]\n";
        std::cerr << "  boundary_id: 1=ModelLoad 2=Tokenize 3=Forward 4=Forward+B014 5=OneDecode+B014\n";
        return 1;
    }

    const std::string modelPath = argv[1];
    const int boundary = std::atoi(argv[2]);
    const std::string prompt = (argc > 3) ? argv[3] : "A";

    if (!std::filesystem::exists(modelPath)) {
        std::cerr << "FAIL: model path does not exist: " << modelPath << "\n";
        return 2;
    }
    if (boundary < 1 || boundary > 5) {
        std::cerr << "FAIL: boundary_id must be 1-5\n";
        return 2;
    }

    std::filesystem::path modelDir = std::filesystem::path(modelPath).parent_path();
    std::string vocabPath = (modelDir / "tokenizer.json").string();
    std::string mergesPath = (modelDir / "merges.txt").string();
    if (!std::filesystem::exists(vocabPath)) vocabPath.clear();
    if (!std::filesystem::exists(mergesPath)) mergesPath.clear();

    std::cout << "{\n";
    std::cout << "  \"experiment\": \"B014-SingleBoundary\",\n";
    std::cout << "  \"boundary_id\": " << boundary << ",\n";
    std::cout << "  \"boundary_name\": \"";
    switch (boundary) {
        case 1: std::cout << "B1_ModelLoad"; break;
        case 2: std::cout << "B2_Tokenize"; break;
        case 3: std::cout << "B3_Forward"; break;
        case 4: std::cout << "B4_Forward_B014"; break;
        case 5: std::cout << "B5_OneDecode_B014"; break;
    }
    std::cout << "\",\n";

    bool pass = false;
    int64_t elapsedNs = 0;
    std::string detail;

    int64_t t0 = NowNs();
    try {
        auto* inf = new RawrXDInference();
        bool ok = inf->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str());
        if (!ok) {
            elapsedNs = NowNs() - t0;
            detail = "Initialize returned false";
            delete inf;
        } else {
            if (boundary >= 4) {
                inf->GetLoader().B014EnableProfiling(true);
                inf->GetLoader().B014ClearProfile();
            }

            if (boundary == 1) {
                elapsedNs = NowNs() - t0;
                pass = true;
                detail = "Initialize returned true";
                delete inf;
            } else {
                auto tokens = inf->Tokenize(prompt);
                if (tokens.empty()) {
                    elapsedNs = NowNs() - t0;
                    detail = "Tokenizer returned empty";
                    delete inf;
                } else if (boundary == 2) {
                    elapsedNs = NowNs() - t0;
                    pass = true;
                    detail = "token_count=" + std::to_string(tokens.size());
                    delete inf;
                } else {
                    auto logits = inf->ForwardTokens(tokens, 0);
                    if (logits.empty()) {
                        elapsedNs = NowNs() - t0;
                        detail = "ForwardTokens returned empty logits";
                        delete inf;
                    } else if (boundary == 3) {
                        elapsedNs = NowNs() - t0;
                        pass = true;
                        detail = "logits_size=" + std::to_string(logits.size());
                        delete inf;
                    } else if (boundary == 4) {
                        elapsedNs = NowNs() - t0;
                        pass = true;
                        auto summary = inf->GetLoader().B014ComputeSummary();
                        detail = "logits_size=" + std::to_string(logits.size()) +
                                 ", b014_invocations=" + std::to_string(summary.totalInvocations);
                        delete inf;
                    } else if (boundary == 5) {
                        uint32_t nextTok = 0;
                        for (size_t i = 0; i < logits.size(); ++i) {
                            if (logits[i] > logits[nextTok]) nextTok = static_cast<uint32_t>(i);
                        }
                        std::vector<uint32_t> nextVec = {nextTok};
                        auto logits2 = inf->ForwardTokens(nextVec, static_cast<uint32_t>(tokens.size()));
                        elapsedNs = NowNs() - t0;
                        pass = true;
                        auto summary = inf->GetLoader().B014ComputeSummary();
                        detail = "logits2_size=" + std::to_string(logits2.size()) +
                                 ", b014_invocations=" + std::to_string(summary.totalInvocations);
                        delete inf;
                    } else {
                        delete inf;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        elapsedNs = NowNs() - t0;
        detail = std::string("exception: ") + e.what();
    }

    std::cout << "  \"pass\": " << (pass ? "true" : "false") << ",\n";
    std::cout << "  \"elapsed_ms\": " << std::fixed << std::setprecision(3)
              << (static_cast<double>(elapsedNs) / 1.0e6) << ",\n";
    std::cout << "  \"detail\": \"" << detail << "\"\n";
    std::cout << "}\n";

    return pass ? 0 : 1;
}
