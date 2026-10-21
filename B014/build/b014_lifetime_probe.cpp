// B014 — Lifetime Boundary Probe: Pinpoint exact destructor/cleanup failure
// Tests each lifetime stage with explicit markers to distinguish:
//   - operation hang vs
//   - operation returns but cleanup/destruction hangs
//
// Usage: b014_lifetime_probe.exe <model_path> <boundary_id> [prompt]
//   boundary_id: 1=ModelLoad+Destroy 2=Tokenize+Destroy 3=Forward+Destroy
//                4=Forward+B014+Destroy 5=OneDecode+B014+Destroy

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

void Marker(const std::string& stage) {
    std::cout << "[B014-LIFETIME] " << stage << "\n";
    std::cout.flush();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <model_path> <boundary_id> [prompt]\n";
        std::cerr << "  boundary_id: 1=LoadDestroy 2=TokenizeDestroy 3=ForwardDestroy 4=ForwardB014Destroy 5=DecodeB014Destroy\n";
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
    std::cout << "  \"experiment\": \"B014-LifetimeProbe\",\n";
    std::cout << "  \"boundary_id\": " << boundary << ",\n";
    std::cout << "  \"boundary_name\": \"";
    switch (boundary) {
        case 1: std::cout << "L1_LoadDestroy"; break;
        case 2: std::cout << "L2_TokenizeDestroy"; break;
        case 3: std::cout << "L3_ForwardDestroy"; break;
        case 4: std::cout << "L4_ForwardB014Destroy"; break;
        case 5: std::cout << "L5_DecodeB014Destroy"; break;
    }
    std::cout << "\",\n";

    bool pass = false;
    int64_t elapsedNs = 0;
    std::string detail;
    std::string lastMarker = "ENTER_main";

    int64_t t0 = NowNs();
    try {
        Marker("ENTER boundary " + std::to_string(boundary));

        Marker("before RawrXDInference allocation");
        auto* inf = new RawrXDInference();
        Marker("after RawrXDInference allocation");

        Marker("before Initialize");
        bool ok = inf->Initialize(Utf8ToWide(modelPath).c_str(), vocabPath.c_str(), mergesPath.c_str());
        Marker("after Initialize");

        if (!ok) {
            elapsedNs = NowNs() - t0;
            detail = "Initialize returned false";
            Marker("before delete inf (init failed)");
            delete inf;
            Marker("after delete inf (init failed)");
        } else {
            if (boundary >= 4) {
                Marker("before B014EnableProfiling");
                inf->GetLoader().B014EnableProfiling(true);
                inf->GetLoader().B014ClearProfile();
                Marker("after B014EnableProfiling");
            }

            if (boundary == 1) {
                // Just load and destroy — no operation
                Marker("before delete inf (load only)");
                delete inf;
                Marker("after delete inf (load only)");
                elapsedNs = NowNs() - t0;
                pass = true;
                detail = "Load+Destroy completed";
            } else {
                Marker("before Tokenize");
                auto tokens = inf->Tokenize(prompt);
                Marker("after Tokenize");

                if (tokens.empty()) {
                    elapsedNs = NowNs() - t0;
                    detail = "Tokenizer returned empty";
                    Marker("before delete inf (tokenize empty)");
                    delete inf;
                    Marker("after delete inf (tokenize empty)");
                } else if (boundary == 2) {
                    Marker("before delete inf (tokenize ok)");
                    delete inf;
                    Marker("after delete inf (tokenize ok)");
                    elapsedNs = NowNs() - t0;
                    pass = true;
                    detail = "token_count=" + std::to_string(tokens.size());
                } else {
                    Marker("before ForwardTokens");
                    auto logits = inf->ForwardTokens(tokens, 0);
                    Marker("after ForwardTokens");

                    if (logits.empty()) {
                        elapsedNs = NowNs() - t0;
                        detail = "ForwardTokens returned empty logits";
                        Marker("before delete inf (forward empty)");
                        delete inf;
                        Marker("after delete inf (forward empty)");
                    } else if (boundary == 3) {
                        Marker("before delete inf (forward ok)");
                        delete inf;
                        Marker("after delete inf (forward ok)");
                        elapsedNs = NowNs() - t0;
                        pass = true;
                        detail = "logits_size=" + std::to_string(logits.size());
                    } else if (boundary == 4) {
                        Marker("before B014ComputeSummary");
                        auto summary = inf->GetLoader().B014ComputeSummary();
                        Marker("after B014ComputeSummary");
                        Marker("before delete inf (forward+b014 ok)");
                        delete inf;
                        Marker("after delete inf (forward+b014 ok)");
                        elapsedNs = NowNs() - t0;
                        pass = true;
                        detail = "logits_size=" + std::to_string(logits.size()) +
                                 ", b014_invocations=" + std::to_string(summary.totalInvocations);
                    } else if (boundary == 5) {
                        Marker("before OneDecodeStep");
                        uint32_t nextTok = 0;
                        for (size_t i = 0; i < logits.size(); ++i) {
                            if (logits[i] > logits[nextTok]) nextTok = static_cast<uint32_t>(i);
                        }
                        std::vector<uint32_t> nextVec = {nextTok};
                        auto logits2 = inf->ForwardTokens(nextVec, static_cast<uint32_t>(tokens.size()));
                        Marker("after OneDecodeStep");

                        Marker("before B014ComputeSummary");
                        auto summary = inf->GetLoader().B014ComputeSummary();
                        Marker("after B014ComputeSummary");

                        Marker("before delete inf (decode+b014 ok)");
                        delete inf;
                        Marker("after delete inf (decode+b014 ok)");
                        elapsedNs = NowNs() - t0;
                        pass = true;
                        detail = "logits2_size=" + std::to_string(logits2.size()) +
                                 ", b014_invocations=" + std::to_string(summary.totalInvocations);
                    } else {
                        Marker("before delete inf (fallback)");
                        delete inf;
                        Marker("after delete inf (fallback)");
                    }
                }
            }
        }
        Marker("EXIT boundary " + std::to_string(boundary));
    } catch (const std::exception& e) {
        elapsedNs = NowNs() - t0;
        detail = std::string("exception: ") + e.what();
        Marker("EXCEPTION caught");
    }

    std::cout << "  \"pass\": " << (pass ? "true" : "false") << ",\n";
    std::cout << "  \"elapsed_ms\": " << std::fixed << std::setprecision(3)
              << (static_cast<double>(elapsedNs) / 1.0e6) << ",\n";
    std::cout << "  \"detail\": \"" << detail << "\"\n";
    std::cout << "}\n";

    return pass ? 0 : 1;
}
