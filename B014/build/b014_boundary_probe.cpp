// B014 — Boundary Probe: Isolate the first failure point in inference initialization
// Tests each runtime boundary independently with B014 profiling enabled/disabled.
//
// Usage:
//   b014_boundary_probe.exe <model_path> [prompt]
//
// Output: structured JSON lines to stdout; each boundary reports PASS/FAIL.

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

struct BoundaryResult {
    std::string name;
    bool pass = false;
    int64_t elapsedNs = 0;
    std::string detail;
};

void PrintBoundary(const BoundaryResult& r, bool last = false) {
    std::cout << "  {\n";
    std::cout << "    \"boundary\": \"" << r.name << "\",\n";
    std::cout << "    \"pass\": " << (r.pass ? "true" : "false") << ",\n";
    std::cout << "    \"elapsed_ms\": " << std::fixed << std::setprecision(3)
              << (static_cast<double>(r.elapsedNs) / 1.0e6) << ",\n";
    std::cout << "    \"detail\": \"" << r.detail << "\"\n";
    std::cout << "  }" << (last ? "" : ",") << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model_path> [prompt]\n";
        return 1;
    }

    const std::string modelPath = argv[1];
    const std::string prompt = (argc > 2) ? argv[2] : "A";

    if (!std::filesystem::exists(modelPath)) {
        std::cerr << "FAIL: model path does not exist: " << modelPath << "\n";
        return 2;
    }

    std::filesystem::path modelDir = std::filesystem::path(modelPath).parent_path();
    std::string vocabPath = (modelDir / "tokenizer.json").string();
    std::string mergesPath = (modelDir / "merges.txt").string();
    if (!std::filesystem::exists(vocabPath)) vocabPath.clear();
    if (!std::filesystem::exists(mergesPath)) mergesPath.clear();

    std::cout << "{\n";
    std::cout << "  \"experiment\": \"B014-BoundaryProbe\",\n";
    std::cout << "  \"model\": \"" << modelPath << "\",\n";
    std::cout << "  \"prompt\": \"" << prompt << "\",\n";
    std::cout << "  \"boundaries\": [\n";

    std::vector<BoundaryResult> results;

    // ========================================================================
    // Boundary 1: Model Load Only (no B014)
    // ========================================================================
    {
        BoundaryResult r{"B1_ModelLoad_NoB014", false, 0, ""};
        int64_t t0 = NowNs();
        try {
            auto* inf = new RawrXDInference();
            bool ok = inf->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str());
            r.elapsedNs = NowNs() - t0;
            if (ok) {
                r.pass = true;
                r.detail = "Initialize returned true";
                delete inf;
            } else {
                r.detail = "Initialize returned false";
                delete inf;
            }
        } catch (const std::exception& e) {
            r.elapsedNs = NowNs() - t0;
            r.detail = std::string("exception: ") + e.what();
        }
        results.push_back(r);
    }

    // ========================================================================
    // Boundary 2: Model Load + Tokenize (no B014)
    // ========================================================================
    {
        BoundaryResult r{"B2_ModelLoad_Tokenize_NoB014", false, 0, ""};
        int64_t t0 = NowNs();
        try {
            auto* inf = new RawrXDInference();
            bool ok = inf->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str());
            if (!ok) {
                r.elapsedNs = NowNs() - t0;
                r.detail = "Initialize returned false";
                delete inf;
            } else {
                auto tokens = inf->Tokenize(prompt);
                r.elapsedNs = NowNs() - t0;
                r.pass = true;
                r.detail = "token_count=" + std::to_string(tokens.size());
                delete inf;
            }
        } catch (const std::exception& e) {
            r.elapsedNs = NowNs() - t0;
            r.detail = std::string("exception: ") + e.what();
        }
        results.push_back(r);
    }

    // ========================================================================
    // Boundary 3: Model Load + Tokenize + ForwardTokens (no B014)
    // ========================================================================
    {
        BoundaryResult r{"B3_ModelLoad_Forward_NoB014", false, 0, ""};
        int64_t t0 = NowNs();
        try {
            auto* inf = new RawrXDInference();
            bool ok = inf->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str());
            if (!ok) {
                r.elapsedNs = NowNs() - t0;
                r.detail = "Initialize returned false";
                delete inf;
            } else {
                auto tokens = inf->Tokenize(prompt);
                if (tokens.empty()) {
                    r.elapsedNs = NowNs() - t0;
                    r.detail = "Tokenizer returned empty";
                    delete inf;
                } else {
                    auto logits = inf->ForwardTokens(tokens, 0);
                    r.elapsedNs = NowNs() - t0;
                    r.pass = true;
                    r.detail = "logits_size=" + std::to_string(logits.size());
                    delete inf;
                }
            }
        } catch (const std::exception& e) {
            r.elapsedNs = NowNs() - t0;
            r.detail = std::string("exception: ") + e.what();
        }
        results.push_back(r);
    }

    // ========================================================================
    // Boundary 4: Model Load + Tokenize + ForwardTokens (B014 ENABLED)
    // ========================================================================
    {
        BoundaryResult r{"B4_ModelLoad_Forward_B014Enabled", false, 0, ""};
        int64_t t0 = NowNs();
        try {
            auto* inf = new RawrXDInference();
            bool ok = inf->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str());
            if (!ok) {
                r.elapsedNs = NowNs() - t0;
                r.detail = "Initialize returned false";
                delete inf;
            } else {
                inf->GetLoader().B014EnableProfiling(true);
                inf->GetLoader().B014ClearProfile();
                auto tokens = inf->Tokenize(prompt);
                if (tokens.empty()) {
                    r.elapsedNs = NowNs() - t0;
                    r.detail = "Tokenizer returned empty";
                    delete inf;
                } else {
                    auto logits = inf->ForwardTokens(tokens, 0);
                    r.elapsedNs = NowNs() - t0;
                    r.pass = true;
                    r.detail = "logits_size=" + std::to_string(logits.size());
                    // Check if B014 recorded anything
                    auto summary = inf->GetLoader().B014ComputeSummary();
                    r.detail += ", b014_invocations=" + std::to_string(summary.totalInvocations);
                    delete inf;
                }
            }
        } catch (const std::exception& e) {
            r.elapsedNs = NowNs() - t0;
            r.detail = std::string("exception: ") + e.what();
        }
        results.push_back(r);
    }

    // ========================================================================
    // Boundary 5: Model Load + Tokenize + ForwardTokens + ONE decode step (B014)
    // ========================================================================
    {
        BoundaryResult r{"B5_OneDecodeStep_B014Enabled", false, 0, ""};
        int64_t t0 = NowNs();
        try {
            auto* inf = new RawrXDInference();
            bool ok = inf->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str());
            if (!ok) {
                r.elapsedNs = NowNs() - t0;
                r.detail = "Initialize returned false";
                delete inf;
            } else {
                inf->GetLoader().B014EnableProfiling(true);
                inf->GetLoader().B014ClearProfile();
                auto tokens = inf->Tokenize(prompt);
                if (tokens.empty()) {
                    r.elapsedNs = NowNs() - t0;
                    r.detail = "Tokenizer returned empty";
                    delete inf;
                } else {
                    auto logits = inf->ForwardTokens(tokens, 0);
                    if (logits.empty()) {
                        r.elapsedNs = NowNs() - t0;
                        r.detail = "ForwardTokens returned empty logits";
                        delete inf;
                    } else {
                        // One decode step: sample one token, forward again
                        uint32_t nextTok = 0;
                        for (size_t i = 0; i < logits.size(); ++i) {
                            if (logits[i] > logits[nextTok]) nextTok = static_cast<uint32_t>(i);
                        }
                        std::vector<uint32_t> nextVec = {nextTok};
                        auto logits2 = inf->ForwardTokens(nextVec, static_cast<uint32_t>(tokens.size()));
                        r.elapsedNs = NowNs() - t0;
                        r.pass = true;
                        r.detail = "logits2_size=" + std::to_string(logits2.size());
                        auto summary = inf->GetLoader().B014ComputeSummary();
                        r.detail += ", b014_invocations=" + std::to_string(summary.totalInvocations);
                        delete inf;
                    }
                }
            }
        } catch (const std::exception& e) {
            r.elapsedNs = NowNs() - t0;
            r.detail = std::string("exception: ") + e.what();
        }
        results.push_back(r);
    }

    // ========================================================================
    // Print results
    // ========================================================================
    for (size_t i = 0; i < results.size(); ++i) {
        PrintBoundary(results[i], i + 1 == results.size());
    }

    bool overall = true;
    for (const auto& r : results) {
        if (!r.pass) { overall = false; break; }
    }

    std::cout << "  ],\n";
    std::cout << "  \"overall_pass\": " << (overall ? "true" : "false") << "\n";
    std::cout << "}\n";

    return overall ? 0 : 1;
}
