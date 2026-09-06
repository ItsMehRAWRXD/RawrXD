// P1_REPEATABILITY_TRIAL_VALIDITY_DIAG_001 — MeasuredGenerate acceptance only
#include "Deep2IDEIntegration.hpp"
#include "Deep2Engine.h"
#include "execution_policy/ExecutionPolicy.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <powrprof.h>

namespace fs = std::filesystem;
using namespace Deep2::Exec;

static const char* kFrozenExeSha =
    "7DFDA62A55A092B59EA223D0604F27DAEB19417FA86681BEFDB164DDDEF7DBD1";
static const char* kFrozenModelSha =
    "DA3087FB14AEDE55FDE6EB81A0E55E886810E43509EC82ECDC7AA5D62A03B556";

static std::string FnvText(const std::string& s) {
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    char out[32];
    std::snprintf(out, sizeof(out), "fnv:%016llx",
                  static_cast<unsigned long long>(h));
    return out;
}

static void ApplyProductionPolicy() {
    ExecutionPolicy p = MakeDefaultPolicy();
    p.mode = UiMode::Expert;
    p.persistRuntimeChanges.force(false, SettingAuthority::Session,
                                  SettingMutability::Immediate);
    p.streaming.enabled.force(true, SettingAuthority::Session,
                              SettingMutability::Immediate);
    p.placement.layerRanges.clear();
    p.placement.layerRanges.push_back({LayerRange{0, 10}, DeviceKind::Gpu0});
    p.placement.layerRanges.push_back({LayerRange{11, -1}, DeviceKind::Stream});
    p.placement.embeddings.force(DeviceKind::Host, SettingAuthority::UserLocked,
                                 SettingMutability::TokenBoundary);
    p.placement.lmHead.force(DeviceKind::Gpu0, SettingAuthority::UserLocked,
                             SettingMutability::TokenBoundary);
    (void)ExecutionPolicyStore::Instance().apply(
        p, SettingAuthority::Session, "REAL_SPEEDUP_PRODUCTION");
}

static void ApplyBaselinePolicy() {
    ExecutionPolicy p = MakeDefaultPolicy();
    p.mode = UiMode::Expert;
    p.persistRuntimeChanges.force(false, SettingAuthority::Session,
                                  SettingMutability::Immediate);
    p.streaming.enabled.force(false, SettingAuthority::Session,
                              SettingMutability::Immediate);
    p.hotpatch.enabled.force(false, SettingAuthority::Session,
                             SettingMutability::Immediate);
    p.placement.layerRanges.clear();
    p.placement.layerRanges.push_back({LayerRange{0, -1}, DeviceKind::Host});
    p.placement.embeddings.force(DeviceKind::Host, SettingAuthority::UserLocked,
                                 SettingMutability::TokenBoundary);
    p.placement.lmHead.force(DeviceKind::Host, SettingAuthority::UserLocked,
                             SettingMutability::TokenBoundary);
    (void)ExecutionPolicyStore::Instance().apply(
        p, SettingAuthority::Session, "REAL_SPEEDUP_BASELINE");
}

struct Pred {
    const char* name = nullptr;
    bool pass = false;
};

struct DiagTrial {
    const char* label = nullptr;
    std::string firstFalse = "NONE";
    std::string outputHash;
    std::string outputPreview;
    std::string policyShaAtSeam;
    std::string policyShaAfter;
    uint32_t tokens = 0;
    uint32_t maxTokensCfg = 0;
    uint64_t wallNs = 0;
    std::string finishReason;
    std::vector<Pred> preds;
    bool measuredOk = false;

    void Set(const char* n, bool ok) {
        preds.push_back({n, ok});
        if (!ok && firstFalse == "NONE") firstFalse = n;
    }
};

static uint64_t QpcFreq() {
    LARGE_INTEGER f{};
    QueryPerformanceFrequency(&f);
    return static_cast<uint64_t>(f.QuadPart);
}

static uint64_t ElapsedNs(uint64_t t0, uint64_t t1, uint64_t freq) {
    return (freq == 0) ? 0 : (t1 - t0) * 1000000000ULL / freq;
}

static DiagTrial RunMeasured(const char* label, bool baseline,
                             const std::string& model,
                             const std::string& prompt, uint32_t maxTokens,
                             uint64_t freq) {
    DiagTrial d{};
    d.label = label;
    d.maxTokensCfg = maxTokens;
    EnsurePolicyLoaded();
    if (baseline)
        ApplyBaselinePolicy();
    else
        ApplyProductionPolicy();

    RawrXD::Deep2ModelLoader::Unload();
    const auto load = RawrXD::Deep2ModelLoader::Load(model);
    d.Set("LOAD_OK", load.success);
    if (!load.success) return d;

    RawrXD::Deep2InferenceSession session;
    auto cfg = RawrXD::Deep2InferenceSession::SessionConfig::FromActivePolicy();
    cfg.maxContextLength = maxTokens + 64;
    const bool initOk = session.Initialize(load, cfg);
    d.Set("INIT_OK", initOk);
    if (!initOk) return d;

    d.policyShaAtSeam = PolicySha256(ActivePolicy());
    const std::string shaBefore = d.policyShaAtSeam;
    LARGE_INTEGER t0{}, t1{};
    QueryPerformanceCounter(&t0);
    const auto gr = session.Generate(prompt);
    QueryPerformanceCounter(&t1);
    d.wallNs = ElapsedNs(static_cast<uint64_t>(t0.QuadPart),
                         static_cast<uint64_t>(t1.QuadPart), freq);

    d.tokens = gr.tokensGenerated;
    d.outputPreview = gr.text.substr(0, 120);
    d.outputHash = FnvText(gr.text);
    d.finishReason = gr.finishReason;

    d.Set("GENERATE_RETURNED", true);
    d.Set("TOKEN_COUNT_VALID", gr.tokensGenerated > 0);
    d.Set("OUTPUT_NONEMPTY", !gr.text.empty());
    d.Set("GENERATE_OUTPUT_OK",
          (gr.tokensGenerated > 0) || !gr.text.empty());
    d.Set("WALL_NS_NONZERO", d.wallNs > 0);

    d.policyShaAfter = PolicySha256(ActivePolicy());
    d.Set("POLICY_SHA_STABLE", d.policyShaAfter == shaBefore);

    d.measuredOk = (d.firstFalse == "NONE");
    d.Set("MEASURED_GENERATE_OK", d.measuredOk);
    return d;
}

static void PrintTrial(const DiagTrial& d, FILE* out) {
    std::fprintf(out, "TRIAL  %s\n", d.label);
    for (const auto& p : d.preds)
        std::fprintf(out, "%-28s %s\n", p.name, p.pass ? "PASS" : "FAIL");
    std::fprintf(out, "TOKENS=%u MAX_TOKENS_CFG=%u\n", d.tokens, d.maxTokensCfg);
    std::fprintf(out, "OUTPUT_HASH=%s\n", d.outputHash.c_str());
    std::fprintf(out, "OUTPUT_PREVIEW=%s\n", d.outputPreview.c_str());
    std::fprintf(out, "FINISH_REASON=%s\n", d.finishReason.c_str());
    std::fprintf(out, "POLICY_SHA_AT_SEAM=%s\n", d.policyShaAtSeam.c_str());
    std::fprintf(out, "POLICY_SHA_AFTER=%s\n", d.policyShaAfter.c_str());
    std::fprintf(out, "WALL_NS=%llu\n",
                 static_cast<unsigned long long>(d.wallNs));
    std::fprintf(out, "MEASURED_GENERATE_OK=%s\n",
                 d.measuredOk ? "PASS" : "FAIL");
    std::fprintf(out, "FIRST_FALSE=%s\n\n", d.firstFalse.c_str());
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const fs::path evDir =
        fs::path("F:/~dev/rawrxd/evidence") /
        "P1_REPEATABILITY_TRIAL_VALIDITY_DIAG_001";
    fs::create_directories(evDir);

    const std::string model = (argc > 1) ? argv[1]
                                         : "F:/~dev/tinyllama_fresh.gguf";
    const std::string prompt = "ping";
    const uint32_t maxTokens = 16;
    const uint64_t freq = QpcFreq();

    char exePath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    const std::string diagExeSha =
        "DIAG_ONLY";  // logged separately; frozen ref unchanged

    std::printf("=== P1_REPEATABILITY_TRIAL_VALIDITY_DIAG_001 ===\n");
    std::printf("FROZEN_SPEEDUP_EXE_SHA=%s\n", kFrozenExeSha);
    std::printf("MODEL=%s\n", model.c_str());

    const auto b = RunMeasured("BASELINE_01", true, model, prompt, maxTokens, freq);
    const auto c = RunMeasured("CANDIDATE_01", false, model, prompt, maxTokens, freq);

    PrintTrial(b, stdout);
    PrintTrial(c, stdout);

    const bool outputMatch = !b.outputHash.empty() && b.outputHash == c.outputHash;
    std::printf("REFERENCE_OUTPUT_HASH_MATCH=%s\n",
                outputMatch ? "PASS" : "FAIL");

    {
        std::ofstream g(evDir / "TRIALS.txt");
        auto writeTrial = [&](const DiagTrial& d) {
            g << "TRIAL  " << d.label << "\n";
            for (const auto& p : d.preds)
                g << p.name << "=" << (p.pass ? "PASS" : "FAIL") << "\n";
            g << "TOKENS=" << d.tokens << "\n";
            g << "MAX_TOKENS_CFG=" << d.maxTokensCfg << "\n";
            g << "OUTPUT_HASH=" << d.outputHash << "\n";
            g << "OUTPUT_PREVIEW=" << d.outputPreview << "\n";
            g << "FINISH_REASON=" << d.finishReason << "\n";
            g << "POLICY_SHA_AT_SEAM=" << d.policyShaAtSeam << "\n";
            g << "POLICY_SHA_AFTER=" << d.policyShaAfter << "\n";
            g << "WALL_NS=" << d.wallNs << "\n";
            g << "MEASURED_GENERATE_OK="
              << (d.measuredOk ? "PASS" : "FAIL") << "\n";
            g << "FIRST_FALSE=" << d.firstFalse << "\n\n";
        };
        writeTrial(b);
        writeTrial(c);
        g << "REFERENCE_OUTPUT_HASH_MATCH="
          << (outputMatch ? "PASS" : "FAIL") << "\n";
    }

    std::ofstream gate(evDir / "GATE.txt");
    gate << "P1_REPEATABILITY_TRIAL_VALIDITY_DIAG_001\n\n";
    gate << "FROZEN_SPEEDUP_EXE_SHA=" << kFrozenExeSha << "\n";
    gate << "DIAG_EXE=" << exePath << "\n";
    gate << "BASELINE_FIRST_FALSE=" << b.firstFalse << "\n";
    gate << "CANDIDATE_FIRST_FALSE=" << c.firstFalse << "\n";
    gate << "REFERENCE_OUTPUT_HASH_MATCH="
         << (outputMatch ? "PASS" : "FAIL") << "\n";
    gate << "ROOT_CAUSE_HYPOTHESIS="
         << (b.firstFalse == "POLICY_SHA_STABLE" ||
                     c.firstFalse == "POLICY_SHA_STABLE"
                 ? "harness POLICY_SHA_STABLE predicate"
                 : "see TRIALS.txt")
         << "\n";

    RawrXD::Deep2ModelLoader::Unload();
    return (b.firstFalse == "NONE" && c.firstFalse == "NONE") ? 0 : 1;
}
