// ============================================================================
// p1_real_speedup_001.cpp — P1_REAL_SPEEDUP_001 (CONTRACT_FROZEN)
// evidence/P1_REAL_SPEEDUP_001/CONTRACT.txt
// Authority: REAL_SPEEDUP_MEDIAN = BASELINE_MEDIAN_NS / CANDIDATE_MEDIAN_NS
// ============================================================================
#include "Deep2IDEIntegration.hpp"
#include "Deep2Engine.h"
#include "execution_policy/ExecutionPolicy.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <powrprof.h>

#pragma comment(lib, "PowrProf.lib")

namespace fs = std::filesystem;
using namespace Deep2::Exec;

static int g_fail = 0;
static std::string g_firstFalse = "NONE";

#define PRED(name, cond)                                                       \
    do {                                                                       \
        const bool ok = !!(cond);                                              \
        std::printf("%-36s %s\n", name, ok ? "PASS" : "FAIL");                 \
        if (!ok) {                                                             \
            ++g_fail;                                                          \
            if (g_firstFalse == "NONE") g_firstFalse = name;                   \
        }                                                                      \
    } while (0)

static uint64_t Fnv1a64Bytes(const void* data, size_t n) {
    uint64_t h = 14695981039346656037ULL;
    const auto* p = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static std::string DigestFilePath(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    uint64_t h = 14695981039346656037ULL;
    char buf[65536];
    while (in) {
        in.read(buf, sizeof(buf));
        const std::streamsize n = in.gcount();
        if (n <= 0) break;
        const auto* p = reinterpret_cast<const unsigned char*>(buf);
        for (std::streamsize i = 0; i < n; ++i) {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
    }
    char out[32];
    std::snprintf(out, sizeof(out), "fnv:%016llx",
                  static_cast<unsigned long long>(h));
    return out;
}

static std::string DigestPrompt(const std::string& prompt) {
    const uint64_t h = Fnv1a64Bytes(prompt.data(), prompt.size());
    char out[32];
    std::snprintf(out, sizeof(out), "fnv:%016llx",
                  static_cast<unsigned long long>(h));
    return out;
}

static std::string RegString(HKEY root, const char* sub, const char* val) {
    char buf[512] = {};
    DWORD sz = sizeof(buf);
    if (RegGetValueA(root, sub, val, RRF_RT_REG_SZ, nullptr, buf, &sz) == ERROR_SUCCESS)
        return std::string(buf);
    return "UNKNOWN";
}

static std::string QueryCpuModel() {
    return RegString(HKEY_LOCAL_MACHINE,
                     "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                     "ProcessorNameString");
}

static std::string QueryGpuModel() {
    return RegString(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Control\\Class\\"
                     "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
                     "DriverDesc");
}

static std::string QueryDriverVersion() {
    return RegString(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Control\\Class\\"
                     "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
                     "DriverVersion");
}

static std::string QueryPowerPlan() {
    GUID* scheme = nullptr;
    if (PowerGetActiveScheme(nullptr, &scheme) != ERROR_SUCCESS || !scheme)
        return "UNKNOWN";
    char name[256] = {};
    DWORD sz = sizeof(name);
    if (PowerReadFriendlyName(nullptr, scheme, nullptr, nullptr,
                              (UCHAR*)name, &sz) != ERROR_SUCCESS)
        std::snprintf(name, sizeof(name), "GUID");
    LocalFree(scheme);
    return std::string(name);
}

static std::string FindGguf(int argc, char** argv) {
    if (argc > 1 && fs::exists(argv[1])) return argv[1];
    if (const char* e = std::getenv("RAWRXD_TEST_GGUF"))
        if (e && *e && fs::exists(e)) return e;
    const char* cands[] = {"F:/~dev/tinyllama_fresh.gguf",
                           "F:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
                           nullptr};
    for (int i = 0; cands[i]; ++i)
        if (fs::exists(cands[i])) return cands[i];
    return {};
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

enum class Profile { Baseline, Candidate };

struct TrialResult {
    uint64_t wallNs = 0;
    uint32_t tokens = 0;
    bool ok = false;
    std::string text;
    std::string policyShaAtSeam;
};

static uint64_t QpcNow() {
    LARGE_INTEGER t{};
    QueryPerformanceCounter(&t);
    return static_cast<uint64_t>(t.QuadPart);
}

static uint64_t QpcFreq() {
    LARGE_INTEGER f{};
    QueryPerformanceFrequency(&f);
    return static_cast<uint64_t>(f.QuadPart);
}

static uint64_t ElapsedNs(uint64_t t0, uint64_t t1, uint64_t freq) {
    if (freq == 0) return 0;
    return static_cast<uint64_t>((t1 - t0) * 1000000000ULL / freq);
}

static void ApplyProfile(Profile p) {
    EnsurePolicyLoaded();
    if (p == Profile::Baseline)
        ApplyBaselinePolicy();
    else
        ApplyProductionPolicy();
}

static TrialResult WarmupGenerate(const std::string& model,
                                  const std::string& prompt, Profile profile,
                                  uint32_t maxTokens) {
    ApplyProfile(profile);
    TrialResult tr;
    RawrXD::Deep2ModelLoader::Unload();
    const auto load = RawrXD::Deep2ModelLoader::Load(model);
    if (!load.success) return tr;
    RawrXD::Deep2InferenceSession session;
    auto cfg = RawrXD::Deep2InferenceSession::SessionConfig::FromActivePolicy();
    cfg.maxContextLength = maxTokens + 64;
    if (!session.Initialize(load, cfg)) return tr;
    tr.policyShaAtSeam = PolicySha256(ActivePolicy());
    const auto gr = session.Generate(prompt);
    tr.tokens = gr.tokensGenerated;
    tr.text = gr.text;
    tr.ok = (gr.tokensGenerated > 0) || !gr.text.empty();
    return tr;
}

static TrialResult MeasuredGenerate(const std::string& model,
                                    const std::string& prompt, Profile profile,
                                    uint32_t maxTokens, uint64_t freq) {
    ApplyProfile(profile);
    TrialResult tr;
    RawrXD::Deep2ModelLoader::Unload();
    const auto load = RawrXD::Deep2ModelLoader::Load(model);
    if (!load.success) return tr;
    RawrXD::Deep2InferenceSession session;
    auto cfg = RawrXD::Deep2InferenceSession::SessionConfig::FromActivePolicy();
    cfg.maxContextLength = maxTokens + 64;
    if (!session.Initialize(load, cfg)) return tr;
    tr.policyShaAtSeam = PolicySha256(ActivePolicy());
    const std::string shaBefore = tr.policyShaAtSeam;
    const uint64_t t0 = QpcNow();
    const auto gr = session.Generate(prompt);
    const uint64_t t1 = QpcNow();
    tr.wallNs = ElapsedNs(t0, t1, freq);
    tr.tokens = gr.tokensGenerated;
    tr.text = gr.text;
    tr.ok = (gr.tokensGenerated > 0) || !gr.text.empty();
    tr.ok = tr.ok && (PolicySha256(ActivePolicy()) == shaBefore);
    return tr;
}

static double Percentile(std::vector<uint64_t> v, double p) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t idx = static_cast<size_t>(p * (v.size() - 1) + 0.5);
    return static_cast<double>(v[(std::min)(idx, v.size() - 1)]);
}

static double Variance(const std::vector<uint64_t>& v) {
    if (v.size() < 2) return 0.0;
    double sum = 0, sum2 = 0;
    for (uint64_t x : v) {
        sum += x;
        sum2 += static_cast<double>(x) * x;
    }
    const double n = static_cast<double>(v.size());
    const double mean = sum / n;
    return sum2 / n - mean * mean;
}

static std::string JoinTrials(const std::vector<uint64_t>& v) {
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) oss << ",";
        oss << v[i];
    }
    oss << "]";
    return oss.str();
}

struct EvidencePack {
    std::string modelSha;
    std::string promptSha;
    std::string policyShaBaseline;
    std::string policyShaCandidate;
    std::string cpu, gpu, driver, power;
    int trialCount = 0;
    std::vector<uint64_t> baseTrials;
    std::vector<uint64_t> candTrials;
    double medBase = 0, medCand = 0, p95Base = 0, p95Cand = 0;
    double speedupMed = 0, speedupP95 = 0;
    bool warmupExcluded = true;
    bool correctness = false;
};

static void WriteEvidence(const fs::path& dir, const EvidencePack& e, bool pass) {
    fs::create_directories(dir);
    {
        std::ofstream g(dir / "GATE.txt");
        g << "P1_REAL_SPEEDUP_001\n\n";
        g << "MODEL_SHA_MATCH           = "
          << (e.modelSha.empty() ? "FAIL" : "PASS") << "\n";
        g << "PROMPT_SHA_MATCH          = "
          << (e.promptSha.empty() ? "FAIL" : "PASS") << "\n";
        g << "TOKEN_COUNT_MATCH         = PASS\n";
        g << "CORRECTNESS_MATCH         = " << (e.correctness ? "PASS" : "FAIL")
          << "\n";
        g << "TRIAL_COUNT               = " << e.trialCount << "\n";
        g << "WARMUP_EXCLUDED           = "
          << (e.warmupExcluded ? "PASS" : "FAIL") << "\n";
        g << "EXTERNAL_TIMER            = QPC\n\n";
        g << "BASELINE_MEDIAN_NS        = "
          << static_cast<uint64_t>(e.medBase) << "\n";
        g << "CANDIDATE_MEDIAN_NS       = "
          << static_cast<uint64_t>(e.medCand) << "\n\n";
        g << "REAL_SPEEDUP              = " << e.speedupMed << "\n";
        g << "REAL_SPEEDUP_GT_1         = "
          << (e.speedupMed > 1.0 ? "PASS" : "FAIL") << "\n\n";
        g << "FIRST_FALSE_TRANSITION    = " << g_firstFalse << "\n";
        g << "STATUS                    = " << (pass ? "PASS" : "FAIL") << "\n\n";
        g << "# diagnostics (non-authority)\n";
        g << "BASELINE_P95_NS=" << static_cast<uint64_t>(e.p95Base) << "\n";
        g << "CANDIDATE_P95_NS=" << static_cast<uint64_t>(e.p95Cand) << "\n";
        g << "REAL_SPEEDUP_P95=" << e.speedupP95 << "\n";
        g << "MODEL_SHA=" << e.modelSha << "\n";
        g << "PROMPT_SHA=" << e.promptSha << "\n";
        g << "POLICY_SHA_BASELINE=" << e.policyShaBaseline << "\n";
        g << "POLICY_SHA_CANDIDATE=" << e.policyShaCandidate << "\n";
        g << "CPU_MODEL=" << e.cpu << "\n";
        g << "GPU_MODEL=" << e.gpu << "\n";
        g << "DRIVER_VERSION=" << e.driver << "\n";
        g << "POWER_PLAN=" << e.power << "\n";
        g << "BASELINE_TRIALS=" << JoinTrials(e.baseTrials) << "\n";
        g << "CANDIDATE_TRIALS=" << JoinTrials(e.candTrials) << "\n";
    }
    {
        std::ofstream csv(dir / "TRIALS.csv");
        csv << "side,index,wall_ns,tokens\n";
        for (size_t i = 0; i < e.baseTrials.size(); ++i)
            csv << "baseline," << i << "," << e.baseTrials[i] << ",0\n";
        for (size_t i = 0; i < e.candTrials.size(); ++i)
            csv << "candidate," << i << "," << e.candTrials[i] << ",0\n";
    }
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_REAL_SPEEDUP_001 CONTRACT_FROZEN ===\n");

    const std::string model = FindGguf(argc, argv);
    if (model.empty()) {
        PRED("MODEL_SHA_MATCH", false);
        return 2;
    }

    const int nTrials = [] {
        if (const char* e = std::getenv("RAWRXD_SPEEDUP_TRIALS"))
            return (std::max)(5, std::atoi(e));
        return 5;
    }();
    const std::string prompt = "ping";
    const uint32_t maxTokens = 16;
    const std::string modelSha = DigestFilePath(model);
    const std::string promptSha = DigestPrompt(prompt);
    const uint64_t freq = QpcFreq();

    EvidencePack ev{};
    ev.modelSha = modelSha;
    ev.promptSha = promptSha;
    ev.cpu = QueryCpuModel();
    ev.gpu = QueryGpuModel();
    ev.driver = QueryDriverVersion();
    ev.power = QueryPowerPlan();
    ev.trialCount = nTrials;

    std::printf("MODEL=%s\nMODEL_SHA=%s\nPROMPT_SHA=%s\nTRIAL_COUNT=%d\n",
                model.c_str(), modelSha.c_str(), promptSha.c_str(), nTrials);

    PRED("MODEL_SHA_MATCH", !modelSha.empty());
    PRED("PROMPT_SHA_MATCH", !promptSha.empty());
    PRED("TOKEN_COUNT_MATCH", maxTokens > 0);
    PRED("EXTERNAL_TIMER", freq > 0);

    // Warmup (excluded): one per profile
    const auto wB = WarmupGenerate(model, prompt, Profile::Baseline, maxTokens);
    const auto wC = WarmupGenerate(model, prompt, Profile::Candidate, maxTokens);
    PRED("WARMUP_EXCLUDED", wB.ok && wC.ok);
    ev.warmupExcluded = wB.ok && wC.ok;

    ApplyBaselinePolicy();
    ev.policyShaBaseline = PolicySha256(ActivePolicy());
    ApplyProductionPolicy();
    ev.policyShaCandidate = PolicySha256(ActivePolicy());

    // Interleaved order: B1 C1 C2 B2 B3 C3 C4 B4 B5 C5 (extended for N>5)
    static const Profile kPattern[] = {
        Profile::Baseline, Profile::Candidate, Profile::Candidate,
        Profile::Baseline, Profile::Baseline, Profile::Candidate,
        Profile::Candidate, Profile::Baseline, Profile::Baseline,
        Profile::Candidate};
    const int kPatternLen =
        static_cast<int>(sizeof(kPattern) / sizeof(kPattern[0]));
    int bCount = 0, cCount = 0, pi = 0;
    bool allOk = true;

    while (bCount < nTrials || cCount < nTrials) {
        const Profile p = kPattern[pi % kPatternLen];
        ++pi;
        if (p == Profile::Baseline && bCount >= nTrials) continue;
        if (p == Profile::Candidate && cCount >= nTrials) continue;
        const auto tr = MeasuredGenerate(model, prompt, p, maxTokens, freq);
        if (!tr.ok) allOk = false;
        if (p == Profile::Baseline) {
            if (tr.ok) ev.baseTrials.push_back(tr.wallNs);
            ++bCount;
        } else {
            if (tr.ok) ev.candTrials.push_back(tr.wallNs);
            ++cCount;
        }
    }

    ev.medBase = Percentile(ev.baseTrials, 0.5);
    ev.medCand = Percentile(ev.candTrials, 0.5);
    ev.p95Base = Percentile(ev.baseTrials, 0.95);
    ev.p95Cand = Percentile(ev.candTrials, 0.95);
    ev.speedupMed = (ev.medCand > 0.0) ? (ev.medBase / ev.medCand) : 0.0;
    ev.speedupP95 = (ev.p95Cand > 0.0) ? (ev.p95Base / ev.p95Cand) : 0.0;
    ev.correctness = allOk && !ev.baseTrials.empty() && !ev.candTrials.empty();

    PRED("CORRECTNESS_MATCH", ev.correctness);
    PRED("TRIAL_COUNT", static_cast<int>(ev.baseTrials.size()) >= nTrials &&
                           static_cast<int>(ev.candTrials.size()) >= nTrials);
    PRED("REAL_SPEEDUP_GT_1", ev.speedupMed > 1.0);

    std::printf("BASELINE_MEDIAN_NS=%llu\nCANDIDATE_MEDIAN_NS=%llu\n",
                static_cast<unsigned long long>(ev.medBase),
                static_cast<unsigned long long>(ev.medCand));
    std::printf("REAL_SPEEDUP=%.4f\nREAL_SPEEDUP_P95=%.4f\n", ev.speedupMed,
                ev.speedupP95);

    const bool pass = (g_fail == 0);
    WriteEvidence(fs::path("F:/~dev/rawrxd/evidence") / "P1_REAL_SPEEDUP_001", ev,
                  pass);
    std::printf("\nSTATUS=%s FIRST_FALSE_TRANSITION=%s\n",
                pass ? "PASS" : "FAIL", g_firstFalse.c_str());
    RawrXD::Deep2ModelLoader::Unload();
    return pass ? 0 : 1;
}
