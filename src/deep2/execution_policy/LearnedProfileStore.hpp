// ============================================================================
// LearnedProfileStore.hpp — profiles/{hw}_{model}.yaml persistence + lookup
// ============================================================================
#pragma once

#include "LearnedProfileIo.hpp"
#include "ExecutionObservation.hpp"
#include <fstream>
#include <filesystem>
#include <mutex>

namespace Deep2 {
namespace Exec {
namespace fs = std::filesystem;

class LearnedProfileStore {
public:
    static LearnedProfileStore& Instance() {
        static LearnedProfileStore s;
        return s;
    }

    void setDir(std::string dir) { dir_ = std::move(dir); }

    std::string pathFor(const std::string& hwFp, const std::string& modelFp) const {
        return (fs::path(dir_) /
                (SanitizeFp(hwFp) + "__" + SanitizeFp(modelFp) + ".yaml"))
            .string();
    }

    bool load(const std::string& hwFp, const std::string& modelFp,
              LearnedProfile& out) {
        std::lock_guard<std::mutex> lock(mu_);
        out = LearnedProfile{};
        const std::string path = pathFor(hwFp, modelFp);
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;
        std::ostringstream ss;
        ss << in.rdbuf();
        return parse(ss.str(), out) && fingerprintOk(out, hwFp, modelFp);
    }

    bool save(const LearnedProfile& lp) {
        std::lock_guard<std::mutex> lock(mu_);
        if (lp.hardware.fingerprint.empty() || lp.modelFingerprint.empty())
            return false;
        const std::string path =
            pathFor(lp.hardware.fingerprint, lp.modelFingerprint);
        fs::create_directories(fs::path(path).parent_path());
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        const std::string y = LearnedToYaml(lp);
        out.write(y.data(), (std::streamsize)y.size());
        return true;
    }

    // INV-3/4: only validated observations; policy = actual placement.
    bool recordSuccess(const ExecutionObservation& obs) {
        const auto v = ValidateObservation(obs);
        if (!v.ok) return false;

        const std::string hwFp = obs.hardware.fingerprint.empty()
                                     ? MakeHardwareFingerprint(obs.hardware)
                                     : obs.hardware.fingerprint;
        LearnedProfile lp;
        // INV-2: exact fingerprint only — load miss ≡ PROFILE_NOT_FOUND.
        load(hwFp, obs.modelFingerprint, lp);

        lp.valid = true;
        lp.hardware = obs.hardware;
        if (lp.hardware.fingerprint.empty())
            lp.hardware.fingerprint = hwFp;
        lp.modelFingerprint = obs.modelFingerprint;
        if (!obs.modelName.empty()) lp.modelName = obs.modelName;
        if (!obs.quant.empty()) lp.quant = obs.quant;

        // INV-4: learn observed execution, never the requested plan alone.
        // INV-1: store as RuntimeLearned evidence — apply path respects locks.
        ExecutionPolicy seed = lp.policy.memory.vramBudget.present
                                   ? lp.policy
                                   : ExecutionPolicy{};
        const bool haveActual =
            !obs.actualPlacement.layerRanges.empty() ||
            !obs.actualPlacement.tensorRules.empty();
        if (haveActual)
            lp.policy = PolicyFromObservation(seed, obs);
        // else: metrics-only update; keep prior placement (do not invent)
        lp.policySha = PolicySha256(lp.policy);

        RunMetrics sample{};
        sample.tps = obs.tokensPerSecond;
        sample.ttftMs = obs.ttftMs;
        sample.peakVramBytes = obs.peakVramBytes;
        sample.peakRamBytes = obs.peakRamBytes;

        const uint32_t n = lp.metrics.runs;
        if (n == 0) {
            lp.metrics = sample;
            lp.metrics.runs = 1;
            lp.metrics.successes = 1;
        } else {
            const double a = 1.0 / (n + 1);
            lp.metrics.tps = lp.metrics.tps * (1 - a) + sample.tps * a;
            lp.metrics.ttftMs =
                lp.metrics.ttftMs * (1 - a) + sample.ttftMs * a;
            if (sample.peakVramBytes > lp.metrics.peakVramBytes)
                lp.metrics.peakVramBytes = sample.peakVramBytes;
            if (sample.peakRamBytes > lp.metrics.peakRamBytes)
                lp.metrics.peakRamBytes = sample.peakRamBytes;
            lp.metrics.runs = n + 1;
            lp.metrics.successes += 1;
            lp.metrics.lastIsoTime = sample.lastIsoTime;
        }
        return save(lp);
    }

    // Deprecated path — kept for callers; does NOT satisfy INV-4 alone.
    bool recordSuccess(const HardwareSnapshot& hw, const std::string& modelFp,
                       const std::string& modelName, const std::string& quant,
                       const RunMetrics& sample, const ExecutionPolicy& policy) {
        ExecutionObservation o;
        o.hardware = hw;
        o.modelFingerprint = modelFp;
        o.modelName = modelName;
        o.quant = quant;
        o.tokensPerSecond = sample.tps;
        o.ttftMs = sample.ttftMs;
        o.peakVramBytes = sample.peakVramBytes;
        o.peakRamBytes = sample.peakRamBytes;
        o.completed = true;
        o.outputValid = sample.tps > 0.0;
        o.fromLiveTelemetry = false;
        // Without live placement, refuse to learn placement (INV-4).
        o.actualPlacement = EffectivePlacement{};
        (void)policy;
        return recordSuccess(o);
    }

private:
    LearnedProfileStore() : dir_("profiles") {}

    static bool fingerprintOk(const LearnedProfile& lp, const std::string& hw,
                              const std::string& model) {
        if (!lp.modelFingerprint.empty() && lp.modelFingerprint != model &&
            lp.modelFingerprint != ("sha256:" + model))
            return false;
        if (!lp.hardware.fingerprint.empty() &&
            lp.hardware.fingerprint != hw &&
            SanitizeFp(lp.hardware.fingerprint) != SanitizeFp(hw))
            return false;
        return lp.valid;
    }

    static bool parse(const std::string& text, LearnedProfile& out) {
        std::string err;
        // Policy body: reuse FromYaml on full text (unknown sections ignored).
        if (!ExecutionPolicyStore::FromYaml(text, out.policy, err)) {
            // Sparse learned files may still have valid hardware/metrics.
        }
        std::istringstream in(text);
        std::string line, section;
        while (std::getline(in, line)) {
            auto hash = line.find('#');
            if (hash != std::string::npos) line = line.substr(0, hash);
            // trim
            while (!line.empty() && line.front() == ' ') line.erase(line.begin());
            while (!line.empty() && line.back() == ' ') line.pop_back();
            if (line.empty()) continue;
            if (line.back() == ':' && line.find(' ') == std::string::npos) {
                section = line.substr(0, line.size() - 1);
                continue;
            }
            auto colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            while (!val.empty() && val.front() == ' ') val.erase(val.begin());
            if (!val.empty() && val.front() == '"') {
                val = val.substr(1);
                if (!val.empty() && val.back() == '"') val.pop_back();
            }
            uint64_t b = 0;
            if (section == "hardware") {
                if (key == "fingerprint") out.hardware.fingerprint = val;
                else if (key == "ram" && ParseBytesLoose(val, b))
                    out.hardware.ramBytes = b;
                else if (key == "topology") out.hardware.topologyNote = val;
                else if (key.size() > 9 && key.compare(0, 3, "gpu") == 0) {
                    // gpu0_name / gpu0_vram
                    const int idx = key[3] - '0';
                    while ((int)out.hardware.gpus.size() <= idx)
                        out.hardware.gpus.push_back({});
                    out.hardware.gpus[idx].index = idx;
                    if (key.find("_name") != std::string::npos)
                        out.hardware.gpus[idx].name = val;
                    else if (key.find("_vram") != std::string::npos &&
                             ParseBytesLoose(val, b))
                        out.hardware.gpus[idx].vramBytes = b;
                }
            } else if (section == "model") {
                if (key == "fingerprint") out.modelFingerprint = val;
                else if (key == "name") out.modelName = val;
                else if (key == "quant") out.quant = val;
            } else if (section == "metrics") {
                if (key == "tps") out.metrics.tps = std::atof(val.c_str());
                else if (key == "ttft_ms")
                    out.metrics.ttftMs = std::atof(val.c_str());
                else if (key == "peak_vram" && ParseBytesLoose(val, b))
                    out.metrics.peakVramBytes = b;
                else if (key == "peak_ram" && ParseBytesLoose(val, b))
                    out.metrics.peakRamBytes = b;
                else if (key == "runs")
                    out.metrics.runs = (uint32_t)std::atoi(val.c_str());
                else if (key == "successes")
                    out.metrics.successes = (uint32_t)std::atoi(val.c_str());
                else if (key == "last") out.metrics.lastIsoTime = val;
                else if (key == "policy_sha") out.policySha = val;
            }
        }
        out.valid = !out.modelFingerprint.empty() ||
                    out.policy.memory.vramBudget.present;
        if (out.hardware.fingerprint.empty() && !out.hardware.gpus.empty())
            out.hardware.fingerprint = MakeHardwareFingerprint(out.hardware);
        return out.valid;
    }

    std::mutex mu_;
    std::string dir_;
};

} // namespace Exec
} // namespace Deep2
