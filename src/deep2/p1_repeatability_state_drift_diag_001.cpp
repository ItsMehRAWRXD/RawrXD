// P1_REPEATABILITY_STATE_DRIFT_DIAG_001 — profile/state drift experiment
#include "Deep2IDEIntegration.hpp"
#include "Deep2Engine.h"
#include "execution_policy/ExecutionPolicy.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"
#include "execution_policy/LearnedProfileStore.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fs = std::filesystem;
using namespace Deep2::Exec;

static const char* kRepo = "F:/~dev/rawrxd";
static const char* kPostfixExeSha =
    "F6999662BF84C55CD3E9E1D52D0EBA02A9174B4925AEA56BC2F2F3D3D6BF2E89";

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

static std::string Sha256File(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    uint64_t h = 14695981039346656037ULL;
    char buf[65536];
    while (in) {
        in.read(buf, sizeof(buf));
        const auto n = in.gcount();
        if (n <= 0) break;
        const auto* b = reinterpret_cast<const unsigned char*>(buf);
        for (std::streamsize i = 0; i < n; ++i) {
            h ^= b[i];
            h *= 1099511628211ULL;
        }
    }
    char out[32];
    std::snprintf(out, sizeof(out), "fnv:%016llx",
                  static_cast<unsigned long long>(h));
    return out;
}

static void SetupPaths(const std::string& profilesDir) {
    const std::string settings = std::string(kRepo) + "/config/rawrxd.settings.yaml";
    ExecutionPolicyStore::Instance().setPaths(settings, profilesDir);
    LearnedProfileStore::Instance().setDir(profilesDir);
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
    (void)ExecutionPolicyStore::Instance().apply(
        p, SettingAuthority::Session, "REAL_SPEEDUP_BASELINE");
}

enum class Side { Baseline, Candidate };

static uint64_t QpcFreq() {
    LARGE_INTEGER f{};
    QueryPerformanceFrequency(&f);
    return static_cast<uint64_t>(f.QuadPart);
}

static uint64_t RunBaselineOnce(const std::string& model, const std::string& prompt,
                                uint32_t maxTokens, uint64_t freq) {
    EnsurePolicyLoaded();
    ApplyBaselinePolicy();
    RawrXD::Deep2ModelLoader::Unload();
    const auto load = RawrXD::Deep2ModelLoader::Load(model);
    if (!load.success) return 0;
    RawrXD::Deep2InferenceSession session;
    auto cfg = RawrXD::Deep2InferenceSession::SessionConfig::FromActivePolicy();
    cfg.maxContextLength = maxTokens + 64;
    if (!session.Initialize(load, cfg)) return 0;
    LARGE_INTEGER t0{}, t1{};
    QueryPerformanceCounter(&t0);
    (void)session.Generate(prompt);
    QueryPerformanceCounter(&t1);
    return (freq == 0) ? 0
                      : static_cast<uint64_t>((t1.QuadPart - t0.QuadPart) *
                                              1000000000ULL / freq);
}

static void RunGenerate(const std::string& model, const std::string& prompt,
                        Side side, uint32_t maxTokens) {
    EnsurePolicyLoaded();
    if (side == Side::Baseline)
        ApplyBaselinePolicy();
    else
        ApplyProductionPolicy();
    RawrXD::Deep2ModelLoader::Unload();
    const auto load = RawrXD::Deep2ModelLoader::Load(model);
    if (!load.success) return;
    RawrXD::Deep2InferenceSession session;
    auto cfg = RawrXD::Deep2InferenceSession::SessionConfig::FromActivePolicy();
    cfg.maxContextLength = maxTokens + 64;
    if (!session.Initialize(load, cfg)) return;
    (void)session.Generate(prompt);
}

static void RunSession01Workload(const std::string& model,
                                 const std::string& prompt, uint32_t maxTokens) {
    RunGenerate(model, prompt, Side::Baseline, maxTokens);
    RunGenerate(model, prompt, Side::Candidate, maxTokens);
    static const Side kOrder[] = {Side::Baseline, Side::Candidate, Side::Candidate,
                                  Side::Baseline, Side::Baseline, Side::Candidate,
                                  Side::Candidate, Side::Baseline, Side::Baseline,
                                  Side::Candidate};
    for (Side s : kOrder) RunGenerate(model, prompt, s, maxTokens);
}

static std::string ProfilePathGuess() {
    const auto& hw = ActiveHardwareSnapshot();
    std::string hwFp = hw.fingerprint;
    if (hwFp.empty() && !hw.gpus.empty())
        hwFp = MakeHardwareFingerprint(hw);
    std::string mfp = ExecutionPolicyStore::Instance().modelFingerprint();
    if (mfp.empty()) mfp = "name:tinyllama_fresh.gguf";
    if (hwFp.empty()) return {};
    return LearnedProfileStore::Instance().pathFor(hwFp, mfp);
}

static void WriteSnap(std::ostream& o, const char* tag, const std::string& model,
                      const std::string& prompt, uint64_t baselineWallNs) {
    const auto& p = ActivePolicy();
    o << "PHASE=" << tag << "\n";
    o << "EXE_SHA=" << kPostfixExeSha << "\n";
    o << "MODEL_SHA=" << Sha256File(model) << "\n";
    o << "PROMPT_SHA=" << FnvText(prompt) << "\n";
    o << "POLICY_SHA=" << PolicySha256(p) << "\n";
    o << "POLICY_MODE=" << static_cast<int>(p.mode) << "\n";
    o << "STREAMING_MODE="
      << (p.streaming.enabled.present && p.streaming.enabled.value ? 1 : 0)
      << "\n";
    o << "REUSE_MODE="
      << (p.reuse.mode.present ? static_cast<int>(p.reuse.mode.value) : -1)
      << "\n";
    o << "GPU_LAYER_RANGES=" << p.placement.layerRanges.size() << "\n";
    o << "VRAM_BUDGET="
      << (p.memory.vramBudget.present ? p.memory.vramBudget.value.n : 0) << "\n";
    o << "RAM_BUDGET="
      << (p.memory.ramBudget.present ? p.memory.ramBudget.value.n : 0) << "\n";
    o << "ACTIVE_EXECUTION_PLAN_SHA=" << PolicySha256(p) << "\n";
    const std::string pp = ProfilePathGuess();
    o << "PROFILE_PATH=" << pp << "\n";
    if (!pp.empty() && fs::exists(pp)) {
        o << "PROFILE_EXISTS=1\n";
        o << "PROFILE_CONTENT_SHA=" << Sha256File(pp) << "\n";
        o << "PROFILE_MTIME="
          << fs::last_write_time(pp).time_since_epoch().count() << "\n";
        o << "PROFILE_SIZE=" << fs::file_size(pp) << "\n";
    } else {
        o << "PROFILE_EXISTS=0\n";
    }
    o << "BASELINE_WALL_NS=" << baselineWallNs << "\n";
    o << "BASELINE_WALL_S=" << (baselineWallNs / 1e9) << "\n\n";
}

struct Args {
    std::string phase;
    std::string profilesDir;
    std::string model;
    std::string out;
};

static Args ParseArgs(int argc, char** argv) {
    Args a;
    a.model = "F:/~dev/tinyllama_fresh.gguf";
    for (int i = 1; i < argc; ++i) {
        const std::string k = argv[i];
        auto next = [&] { return (i + 1 < argc) ? std::string(argv[++i]) : std::string{}; };
        if (k == "--phase") a.phase = next();
        else if (k == "--profiles-dir") a.profilesDir = next();
        else if (k == "--model") a.model = next();
        else if (k == "--out") a.out = next();
    }
    return a;
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const Args a = ParseArgs(argc, argv);
    if (a.phase.empty() || a.profilesDir.empty() || a.out.empty()) {
        std::fprintf(stderr, "usage: --phase A|B|D|E --profiles-dir DIR --out FILE [model]\n");
        return 2;
    }
    fs::create_directories(a.profilesDir);
    SetupPaths(a.profilesDir);
    const std::string prompt = "ping";
    const uint32_t maxTokens = 16;
    const uint64_t freq = QpcFreq();

    uint64_t wall = 0;
    if (a.phase == "B") {
        RunSession01Workload(a.model, prompt, maxTokens);
    } else {
        wall = RunBaselineOnce(a.model, prompt, maxTokens, freq);
    }

    std::ostringstream snap;
    WriteSnap(snap, a.phase.c_str(), a.model, prompt, wall);
    const std::string text = snap.str();
    std::printf("%s", text.c_str());
    std::ofstream out(a.out, std::ios::app);
    out << text;
    RawrXD::Deep2ModelLoader::Unload();
    return 0;
}
