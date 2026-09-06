// ============================================================================
// ExecutionPolicyStore.cpp — persistence + merge + hot reload
// ============================================================================
#include "ExecutionPolicyStore.hpp"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <cctype>

namespace Deep2 {
namespace Exec {
namespace fs = std::filesystem;

namespace {

std::string Trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    return s;
}

std::string Unquote(std::string s) {
    s = Trim(s);
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') ||
         (s.front() == '\'' && s.back() == '\'')))
        return s.substr(1, s.size() - 2);
    return s;
}

bool ParseBytes(const std::string& raw, Bytes& out) {
    std::string s = Trim(raw);
    if (s.empty()) return false;
    char* end = nullptr;
    double v = std::strtod(s.c_str(), &end);
    if (end == s.c_str()) return false;
    std::string unit = Trim(std::string(end));
    for (auto& c : unit) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (unit.empty() || unit == "b") out = Bytes::Of(static_cast<uint64_t>(v));
    else if (unit == "kb" || unit == "kib") out = Bytes::Of(static_cast<uint64_t>(v * KB));
    else if (unit == "mb" || unit == "mib") out = Bytes::MiB(v);
    else if (unit == "gb" || unit == "gib") out = Bytes::GiB(v);
    else return false;
    return true;
}

std::string FormatBytes(Bytes b) {
    if (b.n >= GB && (b.n % GB) == 0)
        return std::to_string(b.n / GB) + "GB";
    if (b.n >= MB && (b.n % MB) == 0)
        return std::to_string(b.n / MB) + "MB";
    return std::to_string(b.n) + "B";
}

DeviceKind ParseDevice(const std::string& s0) {
    std::string s = s0;
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (s == "gpu" || s == "gpu0") return DeviceKind::Gpu0;
    if (s == "gpu1") return DeviceKind::Gpu1;
    if (s == "ram" || s == "cpu" || s == "host") return DeviceKind::Host;
    if (s == "stream" || s == "streamed") return DeviceKind::Stream;
    if (s == "hybrid" || s == "adaptive") return DeviceKind::Hybrid;
    if (s == "disk" || s == "nvme") return DeviceKind::Disk;
    return DeviceKind::Host;
}

const char* DeviceName(DeviceKind d) {
    switch (d) {
    case DeviceKind::Gpu0: return "gpu0";
    case DeviceKind::Gpu1: return "gpu1";
    case DeviceKind::Stream: return "stream";
    case DeviceKind::Hybrid: return "hybrid";
    case DeviceKind::Disk: return "disk";
    default: return "ram";
    }
}

template <typename T>
void OverlayTunable(Tunable<T>& dst, const Tunable<T>& src) {
    if (!src.present) return;
    if (dst.present && AuthorityOutranks(dst.authority, src.authority))
        return;
    if (dst.present && dst.authority == SettingAuthority::UserLocked &&
        src.authority != SettingAuthority::UserLocked &&
        src.authority != SettingAuthority::Session)
        return;
    dst = src;
}

void OverlayPolicy(ExecutionPolicy& dst, const ExecutionPolicy& src) {
    OverlayTunable(dst.persistRuntimeChanges, src.persistRuntimeChanges);
    OverlayTunable(dst.modelPath, src.modelPath);
    OverlayTunable(dst.modelFingerprint, src.modelFingerprint);
    OverlayTunable(dst.context, src.context);
    OverlayTunable(dst.batchSize, src.batchSize);
    OverlayTunable(dst.microbatch, src.microbatch);

    OverlayTunable(dst.memory.vramBudget, src.memory.vramBudget);
    OverlayTunable(dst.memory.vramCapKind, src.memory.vramCapKind);
    OverlayTunable(dst.memory.ramBudget, src.memory.ramBudget);
    OverlayTunable(dst.memory.ramCapKind, src.memory.ramCapKind);
    OverlayTunable(dst.memory.diskCacheBudget, src.memory.diskCacheBudget);
    OverlayTunable(dst.memory.vramParts.weights, src.memory.vramParts.weights);
    OverlayTunable(dst.memory.vramParts.kv, src.memory.vramParts.kv);
    OverlayTunable(dst.memory.vramParts.activations, src.memory.vramParts.activations);
    OverlayTunable(dst.memory.vramParts.streaming, src.memory.vramParts.streaming);
    OverlayTunable(dst.memory.vramParts.scratch, src.memory.vramParts.scratch);
    OverlayTunable(dst.memory.vramParts.reserve, src.memory.vramParts.reserve);

    OverlayTunable(dst.memory.ram.hardCap, src.memory.ram.hardCap);
    OverlayTunable(dst.memory.ram.softCap, src.memory.ram.softCap);
    OverlayTunable(dst.memory.ram.maxMapped, src.memory.ram.maxMapped);
    OverlayTunable(dst.memory.ram.weightCache, src.memory.ram.weightCache);
    OverlayTunable(dst.memory.ram.kvSpill, src.memory.ram.kvSpill);
    OverlayTunable(dst.memory.ram.staging, src.memory.ram.staging);
    OverlayTunable(dst.memory.ram.hugePages, src.memory.ram.hugePages);
    OverlayTunable(dst.memory.ram.lockPages, src.memory.ram.lockPages);
    OverlayTunable(dst.memory.ram.numaNode, src.memory.ram.numaNode);

    if (!src.memory.gpus.empty())
        dst.memory.gpus = src.memory.gpus;

    OverlayTunable(dst.placement.embeddings, src.placement.embeddings);
    OverlayTunable(dst.placement.lmHead, src.placement.lmHead);
    OverlayTunable(dst.placement.norms, src.placement.norms);
    OverlayTunable(dst.placement.attentionClass, src.placement.attentionClass);
    OverlayTunable(dst.placement.ffnClass, src.placement.ffnClass);
    OverlayTunable(dst.placement.weightPolicy, src.placement.weightPolicy);
    if (!src.placement.layerRanges.empty())
        dst.placement.layerRanges = src.placement.layerRanges;
    if (!src.placement.rules.empty())
        dst.placement.rules = src.placement.rules;
    if (!src.placement.pinned.empty())
        dst.placement.pinned = src.placement.pinned;

    OverlayTunable(dst.streaming.enabled, src.streaming.enabled);
    OverlayTunable(dst.streaming.chunkSize, src.streaming.chunkSize);
    OverlayTunable(dst.streaming.prefetchDepth, src.streaming.prefetchDepth);
    OverlayTunable(dst.streaming.queueDepth, src.streaming.queueDepth);
    OverlayTunable(dst.streaming.buffers, src.streaming.buffers);
    OverlayTunable(dst.streaming.directIo, src.streaming.directIo);
    OverlayTunable(dst.streaming.prefetch, src.streaming.prefetch);
    OverlayTunable(dst.streaming.granularity, src.streaming.granularity);

    OverlayTunable(dst.kv.placement, src.kv.placement);
    OverlayTunable(dst.kv.gpuBudget, src.kv.gpuBudget);
    OverlayTunable(dst.kv.ramBudget, src.kv.ramBudget);
    OverlayTunable(dst.kv.quant, src.kv.quant);
    OverlayTunable(dst.kv.pageSize, src.kv.pageSize);
    OverlayTunable(dst.kv.context, src.kv.context);
    OverlayTunable(dst.kv.slidingWindow, src.kv.slidingWindow);

    OverlayTunable(dst.compute.attention, src.compute.attention);
    OverlayTunable(dst.compute.ffn, src.compute.ffn);
    OverlayTunable(dst.compute.sampling, src.compute.sampling);
    OverlayTunable(dst.compute.tokenizer, src.compute.tokenizer);
    OverlayTunable(dst.compute.lmHead, src.compute.lmHead);

    OverlayTunable(dst.reuse.enabled, src.reuse.enabled);
    OverlayTunable(dst.reuse.mode, src.reuse.mode);
    OverlayTunable(dst.reuse.persistentCache, src.reuse.persistentCache);
    OverlayTunable(dst.reuse.failClosed, src.reuse.failClosed);

    OverlayTunable(dst.scheduler.objective, src.scheduler.objective);
    OverlayTunable(dst.scheduler.eviction, src.scheduler.eviction);
    OverlayTunable(dst.scheduler.autoTune, src.scheduler.autoTune);
    OverlayTunable(dst.scheduler.respectOverrides, src.scheduler.respectOverrides);

    OverlayTunable(dst.hotpatch.enabled, src.hotpatch.enabled);
    OverlayTunable(dst.hotpatch.adaptive, src.hotpatch.adaptive);
    OverlayTunable(dst.hotpatch.persistLearnedPlan, src.hotpatch.persistLearnedPlan);

    // Mode: higher layer wins if explicitly set via session/model/global
    // (UiMode not Tunable — last overlay wins when src differs from default Auto).
    if (src.mode != UiMode::Auto || dst.mode == UiMode::Auto)
        dst.mode = src.mode;
}

} // namespace

ExecutionPolicyStore& ExecutionPolicyStore::Instance() {
    static ExecutionPolicyStore s;
    return s;
}

ExecutionPolicyStore::ExecutionPolicyStore() {
    autoDetect_ = MakeDefaultPolicy();
    effective_ = autoDetect_;
    globalPath_ = "rawrxd.settings.yaml";
    profilesDir_ = "profiles";
}

void ExecutionPolicyStore::setPaths(std::string globalYaml, std::string profilesDir) {
    std::lock_guard<std::mutex> lock(mu_);
    globalPath_ = std::move(globalYaml);
    profilesDir_ = std::move(profilesDir);
}

bool ExecutionPolicyStore::readFile(const std::string& path, std::string& out) const {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool ExecutionPolicyStore::writeFile(const std::string& path, const std::string& data) const {
    fs::path p(path);
    if (p.has_parent_path())
        fs::create_directories(p.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(out);
}

std::string ExecutionPolicyStore::profilePath() const {
    std::string name = modelFp_.empty() ? "default" : modelFp_;
    for (char& c : name) {
        if (c == ':' || c == '/' || c == '\\' || c == ' ')
            c = '_';
    }
    if (name.size() > 64) name = name.substr(0, 64);
    return (fs::path(profilesDir_) / (name + ".yaml")).string();
}

void ExecutionPolicyStore::rebuildEffective() {
    effective_ = autoDetect_;
    if (haveGlobal_) OverlayPolicy(effective_, global_);
    if (haveModel_) OverlayPolicy(effective_, model_);
    if (haveSession_) OverlayPolicy(effective_, session_);
    ++effective_.version;
}

bool ExecutionPolicyStore::load(const std::string& modelFingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!modelFingerprint.empty())
        modelFp_ = modelFingerprint;

    haveGlobal_ = haveModel_ = haveSession_ = false;
    session_ = ExecutionPolicy{};
    global_ = ExecutionPolicy{};
    model_ = ExecutionPolicy{};

    std::string text, err;
    if (readFile(globalPath_, text)) {
        if (FromYaml(text, global_, err))
            haveGlobal_ = true;
    }

    const std::string pp = profilePath();
    text.clear();
    if (readFile(pp, text)) {
        ExecutionPolicy mp;
        if (FromYaml(text, mp, err)) {
            // Fingerprint mismatch → refuse unsafe profile apply.
            if (mp.modelFingerprint.present && !modelFp_.empty() &&
                mp.modelFingerprint.value != modelFp_ &&
                mp.modelFingerprint.value != ("sha256:" + modelFp_)) {
                // Keep haveModel_ false; profile ignored.
            } else {
                model_ = mp;
                haveModel_ = true;
            }
        }
    }

    rebuildEffective();
    return true;
}

bool ExecutionPolicyStore::saveGlobal() {
    std::lock_guard<std::mutex> lock(mu_);
    ExecutionPolicy dump = haveGlobal_ ? global_ : effective_;
    return writeFile(globalPath_, ToYaml(dump));
}

bool ExecutionPolicyStore::saveModelProfile() {
    std::lock_guard<std::mutex> lock(mu_);
    ExecutionPolicy dump = haveModel_ ? model_ : effective_;
    if (!modelFp_.empty() && !dump.modelFingerprint.present)
        dump.modelFingerprint.force(modelFp_, SettingAuthority::UserOverride,
                                    SettingMutability::Immediate);
    return writeFile(profilePath(), ToYaml(dump));
}

PolicyCommitResult ExecutionPolicyStore::apply(const ExecutionPolicy& delta,
                                               SettingAuthority authority,
                                               const std::string& reason) {
    std::unique_lock<std::mutex> lock(mu_);
    PolicyCommitResult r;
    ExecutionPolicy candidate = effective_;
    OverlayPolicy(candidate, delta);

    auto v = Validate(candidate);
    if (!v.ok) {
        r.ok = false;
        r.rejected = true;
        r.detail = "POLICY_CHANGE_REJECTED: " + v.detail;
        if (!reason.empty()) r.detail += " (" + reason + ")";
        r.version = effective_.version;
        r.policySha = PolicySha256(effective_);
        return r;
    }

    if (authority == SettingAuthority::Session ||
        authority == SettingAuthority::UserOverride ||
        authority == SettingAuthority::UserLocked) {
        OverlayPolicy(session_, delta);
        haveSession_ = true;
    } else if (authority == SettingAuthority::RuntimeLearned) {
        OverlayPolicy(model_, delta);
        haveModel_ = true;
    } else {
        OverlayPolicy(global_, delta);
        haveGlobal_ = true;
    }

    rebuildEffective();
    r.ok = true;
    r.rejected = false;
    r.version = effective_.version;
    r.policySha = PolicySha256(effective_);
    r.detail = reason.empty() ? "ok" : reason;

    if (effective_.persistRuntimeChanges.present &&
        effective_.persistRuntimeChanges.value) {
        writeFile(globalPath_, ToYaml(haveGlobal_ ? global_ : effective_));
        if (!modelFp_.empty())
            writeFile(profilePath(), ToYaml(haveModel_ ? model_ : effective_));
    }

    auto listeners = listeners_;
    auto eff = effective_;
    lock.unlock();
    for (auto& fn : listeners) {
        try { fn(eff, r); } catch (...) {}
    }
    return r;
}

PolicyCommitResult ExecutionPolicyStore::reloadFromDisk() {
    std::string fp;
    {
        std::lock_guard<std::mutex> lock(mu_);
        fp = modelFp_;
    }
    load(fp);
    PolicyCommitResult r;
    r.ok = true;
    r.version = effective_.version;
    r.policySha = PolicySha256(effective_);
    r.detail = "SETTINGS CHANGE DETECTED (reload)";
    return r;
}

void ExecutionPolicyStore::setModelFingerprint(const std::string& fp) {
    std::lock_guard<std::mutex> lock(mu_);
    modelFp_ = fp;
}

std::string ExecutionPolicyStore::modelFingerprint() const {
    std::lock_guard<std::mutex> lock(mu_);
    return modelFp_;
}

void ExecutionPolicyStore::addListener(Listener fn) {
    std::lock_guard<std::mutex> lock(mu_);
    listeners_.push_back(std::move(fn));
}

std::string ExecutionPolicyStore::ToYaml(const ExecutionPolicy& p) {
    std::ostringstream o;
    o << "# RawrXD ExecutionPolicy — user-owned execution contract\n";
    o << "# Precedence: Session > Model > Global > AutoDetect\n";
    o << "execution:\n";
    o << "  mode: ";
    switch (p.mode) {
    case UiMode::Auto: o << "auto\n"; break;
    case UiMode::Guided: o << "guided\n"; break;
    case UiMode::Expert: o << "expert\n"; break;
    }
    o << "  version: " << p.version << "\n";
    if (p.persistRuntimeChanges.present)
        o << "  persist_runtime_changes: "
          << (p.persistRuntimeChanges.value ? "true" : "false") << "\n";
    if (p.modelFingerprint.present)
        o << "  model_fingerprint: \"" << p.modelFingerprint.value << "\"\n";
    if (p.modelPath.present)
        o << "  model_path: \"" << p.modelPath.value << "\"\n";

    o << "memory:\n";
    if (p.memory.vramBudget.present)
        o << "  vram: " << FormatBytes(p.memory.vramBudget.value) << "\n";
    if (p.memory.vramCapKind.present)
        o << "  vram_cap: "
          << (p.memory.vramCapKind.value == CapKind::Hard ? "hard" : "soft")
          << "\n";
    if (p.memory.ramBudget.present)
        o << "  ram: " << FormatBytes(p.memory.ramBudget.value) << "\n";
    o << "  vram_parts:\n";
    if (p.memory.vramParts.weights.present)
        o << "    weights: " << FormatBytes(p.memory.vramParts.weights.value) << "\n";
    if (p.memory.vramParts.kv.present)
        o << "    kv: " << FormatBytes(p.memory.vramParts.kv.value) << "\n";
    if (p.memory.vramParts.activations.present)
        o << "    activations: " << FormatBytes(p.memory.vramParts.activations.value) << "\n";
    if (p.memory.vramParts.streaming.present)
        o << "    streaming: " << FormatBytes(p.memory.vramParts.streaming.value) << "\n";
    if (p.memory.vramParts.scratch.present)
        o << "    scratch: " << FormatBytes(p.memory.vramParts.scratch.value) << "\n";
    if (p.memory.vramParts.reserve.present)
        o << "    reserve: " << FormatBytes(p.memory.vramParts.reserve.value) << "\n";

    o << "placement:\n";
    if (p.placement.embeddings.present)
        o << "  embeddings: " << DeviceName(p.placement.embeddings.value) << "\n";
    if (p.placement.lmHead.present)
        o << "  lm_head: " << DeviceName(p.placement.lmHead.value) << "\n";
    if (p.placement.attentionClass.present)
        o << "  attention: " << DeviceName(p.placement.attentionClass.value) << "\n";
    if (p.placement.ffnClass.present)
        o << "  ffn: " << DeviceName(p.placement.ffnClass.value) << "\n";
    if (!p.placement.layerRanges.empty()) {
        o << "  layers:\n";
        for (const auto& lr : p.placement.layerRanges) {
            o << "    \"";
            o << lr.first.first << "-";
            if (lr.first.last < 0) o << "*";
            else o << lr.first.last;
            o << "\": " << DeviceName(lr.second) << "\n";
        }
    }
    if (!p.placement.rules.empty()) {
        o << "  tensors:\n";
        for (const auto& rule : p.placement.rules)
            o << "    \"" << rule.pattern << "\": " << DeviceName(rule.device) << "\n";
    }
    if (!p.placement.pinned.empty()) {
        o << "  pin:\n";
        for (const auto& pin : p.placement.pinned)
            o << "    - \"" << pin << "\"\n";
    }

    o << "streaming:\n";
    if (p.streaming.enabled.present)
        o << "  enabled: " << (p.streaming.enabled.value ? "true" : "false") << "\n";
    if (p.streaming.chunkSize.present)
        o << "  chunk_size: " << FormatBytes(p.streaming.chunkSize.value) << "\n";
    if (p.streaming.prefetchDepth.present)
        o << "  prefetch_depth: " << p.streaming.prefetchDepth.value << "\n";
    if (p.streaming.queueDepth.present)
        o << "  queue_depth: " << p.streaming.queueDepth.value << "\n";
    if (p.streaming.buffers.present)
        o << "  buffers: " << p.streaming.buffers.value << "\n";
    if (p.streaming.directIo.present)
        o << "  direct_io: " << (p.streaming.directIo.value ? "true" : "false") << "\n";

    o << "kv:\n";
    if (p.kv.placement.present) {
        o << "  placement: ";
        switch (p.kv.placement.value) {
        case KVPlacement::GPU: o << "gpu\n"; break;
        case KVPlacement::GPUPaged: o << "gpu_paged\n"; break;
        case KVPlacement::RAM: o << "ram\n"; break;
        case KVPlacement::Hybrid: o << "hybrid\n"; break;
        case KVPlacement::DiskPaged: o << "disk_paged\n"; break;
        }
    }
    if (p.kv.gpuBudget.present)
        o << "  gpu_budget: " << FormatBytes(p.kv.gpuBudget.value) << "\n";
    if (p.kv.quant.present)
        o << "  quant: " << p.kv.quant.value << "\n";
    if (p.kv.context.present)
        o << "  context: " << p.kv.context.value << "\n";

    o << "work_avoidance:\n";
    if (p.reuse.enabled.present)
        o << "  enabled: " << (p.reuse.enabled.value ? "true" : "false") << "\n";
    if (p.reuse.mode.present) {
        o << "  policy: ";
        switch (p.reuse.mode.value) {
        case ReuseMode::Disabled: o << "off\n"; break;
        case ReuseMode::ExactOnly: o << "exact\n"; break;
        case ReuseMode::CertifiedReuse: o << "certified\n"; break;
        }
    }
    if (p.reuse.failClosed.present)
        o << "  fail_closed: " << (p.reuse.failClosed.value ? "true" : "false") << "\n";

    o << "scheduler:\n";
    if (p.scheduler.objective.present) {
        o << "  objective: ";
        switch (p.scheduler.objective.value) {
        case OptimizationTarget::LowestMemory: o << "lowest_memory\n"; break;
        case OptimizationTarget::HighestTPS: o << "throughput\n"; break;
        case OptimizationTarget::LowestLatency: o << "latency\n"; break;
        case OptimizationTarget::LowestPower: o << "power\n"; break;
        case OptimizationTarget::Balanced: o << "balanced\n"; break;
        }
    }
    if (p.scheduler.autoTune.present)
        o << "  auto_tune: " << (p.scheduler.autoTune.value ? "true" : "false") << "\n";
    if (p.scheduler.respectOverrides.present)
        o << "  respect_overrides: "
          << (p.scheduler.respectOverrides.value ? "true" : "false") << "\n";

    o << "hotpatch:\n";
    if (p.hotpatch.enabled.present)
        o << "  enabled: " << (p.hotpatch.enabled.value ? "true" : "false") << "\n";
    if (p.hotpatch.adaptive.present)
        o << "  adaptive: " << (p.hotpatch.adaptive.value ? "true" : "false") << "\n";

    return o.str();
}

bool ExecutionPolicyStore::FromYaml(const std::string& text, ExecutionPolicy& out,
                                    std::string& err) {
    out = ExecutionPolicy{};
    err.clear();
    std::istringstream in(text);
    std::string line;
    std::string section;
    std::string subsection;
    auto auth = SettingAuthority::UserOverride;

    while (std::getline(in, line)) {
        auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        if (Trim(line).empty()) continue;

        int indent = 0;
        while (indent < (int)line.size() && line[indent] == ' ') ++indent;
        std::string body = Trim(line);

        if (indent == 0 && body.back() == ':') {
            section = body.substr(0, body.size() - 1);
            subsection.clear();
            continue;
        }
        if (indent == 2 && body.back() == ':' && body.find(' ') == std::string::npos) {
            subsection = body.substr(0, body.size() - 1);
            continue;
        }

        auto colon = body.find(':');
        if (colon == std::string::npos) {
            if (section == "placement" && subsection == "pin" &&
                body.size() > 1 && body[0] == '-') {
                out.placement.pinned.push_back(Unquote(Trim(body.substr(1))));
            }
            continue;
        }
        std::string key = Trim(body.substr(0, colon));
        std::string val = Unquote(Trim(body.substr(colon + 1)));

        Bytes b{};
        if (section == "execution") {
            if (key == "mode") {
                if (val == "auto") out.mode = UiMode::Auto;
                else if (val == "guided") out.mode = UiMode::Guided;
                else if (val == "expert") out.mode = UiMode::Expert;
            } else if (key == "persist_runtime_changes")
                out.persistRuntimeChanges.force(val == "true", auth,
                                                SettingMutability::Immediate);
            else if (key == "model_fingerprint")
                out.modelFingerprint.force(val, auth, SettingMutability::Immediate);
            else if (key == "model_path")
                out.modelPath.force(val, auth, SettingMutability::Immediate);
        } else if (section == "memory") {
            if (key == "vram" && ParseBytes(val, b))
                out.memory.vramBudget.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "ram" && ParseBytes(val, b))
                out.memory.ramBudget.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "vram_cap")
                out.memory.vramCapKind.force(
                    val == "hard" ? CapKind::Hard : CapKind::Soft, auth,
                    SettingMutability::Immediate);
            else if (key == "ram_cap")
                out.memory.ramCapKind.force(
                    val == "hard" ? CapKind::Hard : CapKind::Soft, auth,
                    SettingMutability::Immediate);
            else if (key == "disk_cache" && ParseBytes(val, b))
                out.memory.diskCacheBudget.force(b, auth, SettingMutability::Immediate);
            else if (subsection == "vram_parts" && ParseBytes(val, b)) {
                if (key == "weights")
                    out.memory.vramParts.weights.force(b, auth, SettingMutability::TokenBoundary);
                else if (key == "kv")
                    out.memory.vramParts.kv.force(b, auth, SettingMutability::TokenBoundary);
                else if (key == "activations")
                    out.memory.vramParts.activations.force(b, auth, SettingMutability::TokenBoundary);
                else if (key == "streaming")
                    out.memory.vramParts.streaming.force(b, auth, SettingMutability::TokenBoundary);
                else if (key == "scratch")
                    out.memory.vramParts.scratch.force(b, auth, SettingMutability::TokenBoundary);
                else if (key == "reserve")
                    out.memory.vramParts.reserve.force(b, auth, SettingMutability::TokenBoundary);
            }
        } else if (section == "placement") {
            if (key == "embeddings")
                out.placement.embeddings.force(ParseDevice(val), auth,
                                               SettingMutability::TokenBoundary);
            else if (key == "lm_head")
                out.placement.lmHead.force(ParseDevice(val), auth,
                                           SettingMutability::TokenBoundary);
            else if (key == "attention")
                out.placement.attentionClass.force(ParseDevice(val), auth,
                                                   SettingMutability::TokenBoundary);
            else if (key == "ffn")
                out.placement.ffnClass.force(ParseDevice(val), auth,
                                             SettingMutability::TokenBoundary);
            else if (subsection == "layers") {
                // key like "0-7"
                std::string range = Unquote(key);
                LayerRange lr;
                auto dash = range.find('-');
                if (dash == std::string::npos) {
                    lr.first = lr.last = std::atoi(range.c_str());
                } else {
                    lr.first = std::atoi(range.substr(0, dash).c_str());
                    std::string rhs = range.substr(dash + 1);
                    lr.last = (rhs == "*") ? -1 : std::atoi(rhs.c_str());
                }
                out.placement.layerRanges.emplace_back(lr, ParseDevice(val));
            } else if (subsection == "tensors") {
                PlacementRule rule;
                rule.pattern = Unquote(key);
                rule.device = ParseDevice(val);
                rule.authority = auth;
                out.placement.rules.push_back(rule);
            }
        } else if (section == "streaming") {
            if (key == "enabled")
                out.streaming.enabled.force(val == "true", auth,
                                            SettingMutability::TokenBoundary);
            else if (key == "chunk_size" && ParseBytes(val, b))
                out.streaming.chunkSize.force(b, auth, SettingMutability::Immediate);
            else if (key == "prefetch_depth")
                out.streaming.prefetchDepth.force(std::atoi(val.c_str()), auth,
                                                  SettingMutability::Immediate);
            else if (key == "queue_depth")
                out.streaming.queueDepth.force(std::atoi(val.c_str()), auth,
                                               SettingMutability::Immediate);
            else if (key == "buffers")
                out.streaming.buffers.force(std::atoi(val.c_str()), auth,
                                            SettingMutability::Immediate);
            else if (key == "direct_io")
                out.streaming.directIo.force(val == "true", auth,
                                             SettingMutability::ModelReload);
            else if (key == "prefetch") {
                PrefetchPolicy pp = PrefetchPolicy::DependencyAware;
                if (val == "off") pp = PrefetchPolicy::Off;
                else if (val == "sequential") pp = PrefetchPolicy::Sequential;
                else if (val == "predictive") pp = PrefetchPolicy::Predictive;
                else if (val == "aggressive") pp = PrefetchPolicy::Aggressive;
                else if (val == "dependency") pp = PrefetchPolicy::DependencyAware;
                out.streaming.prefetch.force(pp, auth, SettingMutability::Immediate);
            }
        } else if (section == "kv") {
            if (key == "placement") {
                KVPlacement kp = KVPlacement::Hybrid;
                if (val == "gpu") kp = KVPlacement::GPU;
                else if (val == "gpu_paged") kp = KVPlacement::GPUPaged;
                else if (val == "ram") kp = KVPlacement::RAM;
                else if (val == "disk_paged") kp = KVPlacement::DiskPaged;
                out.kv.placement.force(kp, auth, SettingMutability::SequenceBoundary);
            } else if (key == "gpu_budget" && ParseBytes(val, b))
                out.kv.gpuBudget.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "quant")
                out.kv.quant.force(val, auth, SettingMutability::SequenceBoundary);
            else if (key == "context")
                out.kv.context.force(std::atoi(val.c_str()), auth,
                                     SettingMutability::ModelReload);
        } else if (section == "work_avoidance") {
            if (key == "enabled")
                out.reuse.enabled.force(val == "true", auth,
                                        SettingMutability::TokenBoundary);
            else if (key == "policy") {
                ReuseMode m = ReuseMode::CertifiedReuse;
                if (val == "off") m = ReuseMode::Disabled;
                else if (val == "exact") m = ReuseMode::ExactOnly;
                out.reuse.mode.force(m, auth, SettingMutability::TokenBoundary);
            } else if (key == "fail_closed")
                out.reuse.failClosed.force(val == "true", auth,
                                           SettingMutability::Immediate);
        } else if (section == "scheduler") {
            if (key == "objective") {
                OptimizationTarget t = OptimizationTarget::Balanced;
                if (val == "throughput") t = OptimizationTarget::HighestTPS;
                else if (val == "latency") t = OptimizationTarget::LowestLatency;
                else if (val == "lowest_memory") t = OptimizationTarget::LowestMemory;
                else if (val == "power") t = OptimizationTarget::LowestPower;
                out.scheduler.objective.force(t, auth, SettingMutability::Immediate);
            } else if (key == "auto_tune")
                out.scheduler.autoTune.force(val == "true", auth,
                                             SettingMutability::Immediate);
            else if (key == "respect_overrides")
                out.scheduler.respectOverrides.force(val == "true", auth,
                                                     SettingMutability::Immediate);
            else if (key == "eviction") {
                EvictionPolicyKind e = EvictionPolicyKind::CostAware;
                if (val == "lru") e = EvictionPolicyKind::LRU;
                else if (val == "next_use") e = EvictionPolicyKind::NextUse;
                else if (val == "dependency") e = EvictionPolicyKind::DependencyAware;
                else if (val == "pinned") e = EvictionPolicyKind::UserPinned;
                out.scheduler.eviction.force(e, auth, SettingMutability::Immediate);
            }
        } else if (section == "compute") {
            if (key == "attention")
                out.compute.attention.force(ParseDevice(val), auth,
                                            SettingMutability::TokenBoundary);
            else if (key == "ffn")
                out.compute.ffn.force(ParseDevice(val), auth,
                                      SettingMutability::TokenBoundary);
            else if (key == "sampling")
                out.compute.sampling.force(ParseDevice(val), auth,
                                           SettingMutability::TokenBoundary);
            else if (key == "tokenizer")
                out.compute.tokenizer.force(ParseDevice(val), auth,
                                            SettingMutability::TokenBoundary);
            else if (key == "lm_head")
                out.compute.lmHead.force(ParseDevice(val), auth,
                                         SettingMutability::TokenBoundary);
        } else if (section == "ram_policy") {
            if (key == "hard_cap" && ParseBytes(val, b))
                out.memory.ram.hardCap.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "weight_cache" && ParseBytes(val, b))
                out.memory.ram.weightCache.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "kv_spill" && ParseBytes(val, b))
                out.memory.ram.kvSpill.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "staging" && ParseBytes(val, b))
                out.memory.ram.staging.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "huge_pages")
                out.memory.ram.hugePages.force(val == "true", auth, SettingMutability::ModelReload);
            else if (key == "lock_pages")
                out.memory.ram.lockPages.force(val == "true", auth, SettingMutability::ModelReload);
        } else if (section == "gpu") {
            // subsection is GPU index string ("0","1"); key is budget/weights/...
            GpuSlot slot;
            slot.index = std::atoi(subsection.c_str());
            bool found = false;
            for (auto& g : out.memory.gpus) {
                if (g.index == slot.index) {
                    slot = g;
                    found = true;
                    break;
                }
            }
            if (key == "budget" && ParseBytes(val, b))
                slot.budget.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "weights" && ParseBytes(val, b))
                slot.partition.weights.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "kv" && ParseBytes(val, b))
                slot.partition.kv.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "streaming" && ParseBytes(val, b))
                slot.partition.streaming.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "scratch" && ParseBytes(val, b))
                slot.partition.scratch.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "reserve" && ParseBytes(val, b))
                slot.partition.reserve.force(b, auth, SettingMutability::TokenBoundary);
            else if (key == "residency")
                slot.permanentResidency.force(val == "permanent", auth,
                                              SettingMutability::TokenBoundary);
            if (found) {
                for (auto& g : out.memory.gpus)
                    if (g.index == slot.index) {
                        g = slot;
                        break;
                    }
            } else {
                out.memory.gpus.push_back(slot);
            }
        } else if (section == "hotpatch") {
            if (key == "enabled")
                out.hotpatch.enabled.force(val == "true", auth,
                                           SettingMutability::Immediate);
            else if (key == "adaptive")
                out.hotpatch.adaptive.force(val == "true", auth,
                                            SettingMutability::Immediate);
        }
    }

    auto v = Validate(out);
    if (!v.ok) {
        // Empty / sparse YAML is OK — only fail if present fields conflict.
        // If out has any memory budget set and invalid, reject.
        if (out.memory.vramBudget.present || out.memory.vramParts.sum() > 0) {
            err = v.detail;
            return false;
        }
    }
    return true;
}

} // namespace Exec
} // namespace Deep2
