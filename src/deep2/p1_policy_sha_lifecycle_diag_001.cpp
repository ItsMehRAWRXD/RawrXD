// P1_POLICY_SHA_LIFECYCLE_DIAG_001 — policy SHA transition field audit
#include "Deep2IDEIntegration.hpp"
#include "Deep2Engine.h"
#include "execution_policy/ExecutionPolicy.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"
#include "execution_policy/ExecutionPolicyApply.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fs = std::filesystem;
using namespace Deep2::Exec;

struct FieldSnap {
    std::string sha;
    uint64_t version = 0;
    int mode = 0;
    std::string modelFingerprint;
    uint64_t vramBudget = 0;
    bool streamingEnabled = false;
    uint64_t streamChunk = 0;
    int kvPlacement = -1;
    int reuseMode = -1;
    uint64_t vramPartsSum = 0;
    std::string layerRanges;
    size_t ruleCount = 0;
};

static FieldSnap Snap(const ExecutionPolicy& p) {
    FieldSnap s;
    s.sha = PolicySha256(p);
    s.version = p.version;
    s.mode = static_cast<int>(p.mode);
    if (p.modelFingerprint.present) s.modelFingerprint = p.modelFingerprint.value;
    if (p.memory.vramBudget.present) s.vramBudget = p.memory.vramBudget.value.n;
    if (p.streaming.enabled.present) s.streamingEnabled = p.streaming.enabled.value;
    if (p.streaming.chunkSize.present) s.streamChunk = p.streaming.chunkSize.value.n;
    if (p.kv.placement.present) s.kvPlacement = static_cast<int>(p.kv.placement.value);
    if (p.reuse.mode.present) s.reuseMode = static_cast<int>(p.reuse.mode.value);
    s.vramPartsSum = p.memory.vramParts.sum();
    std::ostringstream lr;
    for (const auto& r : p.placement.layerRanges)
        lr << "[" << r.first.first << "," << r.first.last << "]="
           << static_cast<int>(r.second) << ";";
    s.layerRanges = lr.str();
    s.ruleCount = p.placement.rules.size();
    return s;
}

static std::vector<std::string> DiffFields(const FieldSnap& a, const FieldSnap& b) {
    std::vector<std::string> d;
    if (a.sha == b.sha) return d;
    if (a.version != b.version) d.push_back("version");
    if (a.mode != b.mode) d.push_back("mode");
    if (a.modelFingerprint != b.modelFingerprint) d.push_back("modelFingerprint");
    if (a.vramBudget != b.vramBudget) d.push_back("vramBudget");
    if (a.streamingEnabled != b.streamingEnabled) d.push_back("streaming.enabled");
    if (a.streamChunk != b.streamChunk) d.push_back("streaming.chunkSize");
    if (a.kvPlacement != b.kvPlacement) d.push_back("kv.placement");
    if (a.reuseMode != b.reuseMode) d.push_back("reuse.mode");
    if (a.vramPartsSum != b.vramPartsSum) d.push_back("vramParts.sum");
    if (a.layerRanges != b.layerRanges) d.push_back("placement.layerRanges");
    if (a.ruleCount != b.ruleCount) d.push_back("placement.rules");
    if (d.empty()) d.push_back("sha_changed_unattributed");
    return d;
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

struct Life {
    std::string tag;
    FieldSnap snap;
};

static void LogLife(std::ostream& o, const Life& l) {
    o << l.tag << " sha=" << l.snap.sha << " ver=" << l.snap.version
      << " mode=" << l.snap.mode << " mfp=" << l.snap.modelFingerprint
      << " stream=" << (l.snap.streamingEnabled ? 1 : 0)
      << " layers=" << l.snap.layerRanges << "\n";
}

static void LogTransition(std::ostream& o, const Life& from, const Life& to) {
    const auto d = DiffFields(from.snap, to.snap);
    o << "TRANSITION " << from.tag << " -> " << to.tag << "\n";
    o << "  SHA " << from.snap.sha << " -> " << to.snap.sha << "\n";
    o << "  VERSION " << from.snap.version << " -> " << to.snap.version << "\n";
    o << "  FIELDS_CHANGED=";
    for (size_t i = 0; i < d.size(); ++i) {
        if (i) o << ",";
        o << d[i];
    }
    o << "\n\n";
}

static std::vector<Life> RunCandidateLifecycle(const std::string& model,
                                               const std::string& prompt,
                                               uint32_t maxTokens) {
    std::vector<Life> pts;
    auto add = [&](const char* tag) {
        pts.push_back({tag, Snap(ActivePolicy())});
    };

    EnsurePolicyLoaded();
    ApplyProductionPolicy();
    add("POLICY_SHA_PRE_GENERATE");
    add("POLICY_SHA_PRE_LOAD");

    RawrXD::Deep2ModelLoader::Unload();
    const auto load = RawrXD::Deep2ModelLoader::Load(model);
    add("POLICY_SHA_POST_LOAD");

    RawrXD::Deep2InferenceSession session;
    auto cfg = RawrXD::Deep2InferenceSession::SessionConfig::FromActivePolicy();
    cfg.maxContextLength = maxTokens + 64;
    (void)session.Initialize(load, cfg);
    add("POLICY_SHA_AT_CERTIFIED_SEAM");
    add("POLICY_SHA_GENERATE_ENTRY");

    bool gotFirst = false;
    {
        RawrXD::Deep2InferenceSession streamSess;
        RawrXD::Deep2ModelLoader::Unload();
        const auto ls = RawrXD::Deep2ModelLoader::Load(model);
        (void)streamSess.Initialize(ls, cfg);
        streamSess.GenerateStream(prompt, [&](const std::string&, bool done) {
            if (!gotFirst && !done) {
                pts.push_back(
                    {"POLICY_SHA_FIRST_TOKEN", Snap(ActivePolicy())});
                gotFirst = true;
            }
        });
    }
    if (!gotFirst)
        pts.push_back({"POLICY_SHA_FIRST_TOKEN", Snap(ActivePolicy())});

    RawrXD::Deep2ModelLoader::Unload();
    const auto load2 = RawrXD::Deep2ModelLoader::Load(model);
    RawrXD::Deep2InferenceSession session2;
    (void)session2.Initialize(load2, cfg);
    add("POLICY_SHA_AT_CERTIFIED_SEAM_RELOAD");
    add("POLICY_SHA_GENERATE_ENTRY_RELOAD");
    (void)session2.Generate(prompt);
    add("POLICY_SHA_GENERATE_EXIT");
    add("POLICY_SHA_AFTER");

    EnsurePolicyLoaded();
    add("POLICY_SHA_POST_ENSURE");

    return pts;
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const fs::path ev =
        fs::path("F:/~dev/rawrxd/evidence") / "P1_POLICY_SHA_LIFECYCLE_DIAG_001";
    fs::create_directories(ev);

    const std::string model = (argc > 1) ? argv[1]
                                         : "F:/~dev/tinyllama_fresh.gguf";
    const std::string prompt = "ping";
    const uint32_t maxTokens = 16;

    std::printf("=== P1_POLICY_SHA_LIFECYCLE_DIAG_001 ===\n");
    const auto pts = RunCandidateLifecycle(model, prompt, maxTokens);

    std::ostringstream life;
    for (const auto& p : pts) LogLife(life, p);
    for (size_t i = 1; i < pts.size(); ++i) LogTransition(life, pts[i - 1], pts[i]);

    const std::string lifeText = life.str();
    std::printf("%s", lifeText.c_str());

    Life seamLife{}, afterLife{};
    for (const auto& p : pts) {
        if (p.tag == "POLICY_SHA_AT_CERTIFIED_SEAM_RELOAD") seamLife = p;
        if (p.tag == "POLICY_SHA_AFTER") afterLife = p;
    }
    std::string seamToAfterFields;
    std::ostringstream seamTrans;
    if (!seamLife.tag.empty() && !afterLife.tag.empty()) {
        const auto d = DiffFields(seamLife.snap, afterLife.snap);
        for (size_t j = 0; j < d.size(); ++j) {
            if (j) seamToAfterFields += ",";
            seamToAfterFields += d[j];
        }
        LogTransition(seamTrans, seamLife, afterLife);
    }

    std::ofstream lf(ev / "LIFECYCLE.txt");
    lf << lifeText << seamTrans.str();

    auto findSha = [&](const char* tag) -> std::string {
        for (const auto& p : pts)
            if (p.tag == tag) return p.snap.sha;
        return {};
    };
    const std::string pre = findSha("POLICY_SHA_PRE_GENERATE");
    const std::string postLoad = findSha("POLICY_SHA_POST_LOAD");
    const std::string atSeamReload = findSha("POLICY_SHA_AT_CERTIFIED_SEAM_RELOAD");
    const std::string after = findSha("POLICY_SHA_AFTER");
    const std::string postEnsure = findSha("POLICY_SHA_POST_ENSURE");

    std::ofstream gate(ev / "GATE.txt");
    gate << "P1_POLICY_SHA_LIFECYCLE_DIAG_001\n\n";
    gate << "STATUS=DIAG_COMPLETE\n";
    gate << "FROZEN_SPEEDUP_EXE_SHA=7DFDA62A55A092B59EA223D0604F27DAEB19417FA86681BEFDB164DDDEF7DBD1\n";
    gate << "POLICY_SHA_PRE_GENERATE=" << pre << "\n";
    gate << "POLICY_SHA_POST_LOAD=" << postLoad << "\n";
    gate << "POLICY_SHA_AT_CERTIFIED_SEAM=" << atSeamReload << "\n";
    gate << "POLICY_SHA_GENERATE_EXIT=" << findSha("POLICY_SHA_GENERATE_EXIT") << "\n";
    gate << "POLICY_SHA_AFTER=" << after << "\n";
    gate << "POLICY_SHA_POST_ENSURE=" << postEnsure << "\n";
    gate << "AT_SEAM_EQ_AFTER=" << (atSeamReload == after ? "PASS" : "FAIL") << "\n";
    gate << "SEAM_TO_AFTER_FIELDS=" << seamToAfterFields << "\n";
    gate << "PRE_TO_POST_LOAD_MUTATION="
         << (pre == postLoad ? "NONE" : "PRESENT") << "\n";

    RawrXD::Deep2ModelLoader::Unload();
    return 0;
}
