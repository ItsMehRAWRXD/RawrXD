/*
 ATTN-CERT-001 — MHA/GQA attention path certification harness.

 Observation-only: digests from AttnCertProbe (fixed-size frames).
 Does NOT alter MHA/GQA arithmetic. Does NOT touch STREAMER sequencing.
 Does NOT promote LIFECYCLE to CERTIFIED.
*/
#include "Deep2Engine.h"
#include "AttnCertProbe.hpp"
#include "../models/ModelCatalog.hpp"

#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;

namespace {

struct Counts {
    int norm = 0, q = 0, k = 0, v = 0, ropeQ = 0, ropeK = 0;
    int kvWrite = 0, score = 0, soft = 0, attn = 0, o = 0, resid = 0, kvlen = 0;
};

Counts tally(const std::vector<Deep2::AttnCert::Frame>& frames) {
    Counts c;
    for (const auto& f : frames) {
        using S = Deep2::AttnCert::Stage;
        switch (f.stage) {
        case S::AttnNorm: c.norm++; break;
        case S::QProj: c.q++; break;
        case S::KProj: c.k++; break;
        case S::VProj: c.v++; break;
        case S::RopeQ: c.ropeQ++; break;
        case S::RopeK: c.ropeK++; break;
        case S::KvWrite: c.kvWrite++; break;
        case S::PreSoftmax: c.score++; break;
        case S::Softmax: c.soft++; break;
        case S::AttnOut: c.attn++; break;
        case S::OProj: c.o++; break;
        case S::ResidualHint: c.resid++; break;
        case S::KvLength: c.kvlen++; break;
        }
    }
    return c;
}

bool qkvDigestOk(const std::vector<Deep2::AttnCert::Frame>& frames, std::string& reason) {
    using S = Deep2::AttnCert::Stage;
    for (const auto& f : frames) {
        if (f.stage != S::QProj && f.stage != S::KProj && f.stage != S::VProj) continue;
        if (f.count == 0) {
            reason = "qkv_empty_count";
            return false;
        }
        if (f.nonfinite != 0) {
            reason = "qkv_nonfinite";
            return false;
        }
        if (!(f.l2 > 0.0)) {
            reason = "qkv_l2_nonpositive";
            return false;
        }
    }
    return true;
}

bool softmaxInvariantsOk(const std::vector<Deep2::AttnCert::Frame>& frames, std::string& reason) {
    for (const auto& f : frames) {
        if (f.stage != Deep2::AttnCert::Stage::Softmax) continue;
        if (f.count == 0) {
            reason = "softmax_empty";
            return false;
        }
        if (f.nonfinite != 0 || f.l2 < 0.0) {
            reason = "softmax_nonfinite";
            return false;
        }
        if (!std::isfinite(f.aux) || std::fabs(f.aux - 1.0) > 1.0e-3) {
            reason = "softmax_sum_not_one aux=" + std::to_string(f.aux);
            return false;
        }
        // One-key attention: softmax length 1 ⇒ mass is exactly 1 (aux already).
        if (f.count == 1 && std::fabs(f.aux - 1.0) > 1.0e-6) {
            reason = "one_key_softmax_not_one";
            return false;
        }
    }
    return true;
}

bool kvProgressionOk(const std::vector<Deep2::AttnCert::Frame>& frames,
                     size_t promptLen, size_t genTokens, std::string& reason) {
    std::vector<double> lens;
    for (const auto& f : frames) {
        if (f.stage == Deep2::AttnCert::Stage::KvLength) lens.push_back(f.aux);
    }
    if (lens.empty()) {
        reason = "no_kv_length_frames";
        return false;
    }
    for (size_t i = 1; i < lens.size(); ++i) {
        if (lens[i] + 1e-9 < lens[i - 1]) {
            reason = "kv_length_regressed";
            return false;
        }
    }
    const double last = lens.back();
    if (last + 1e-9 < static_cast<double>(promptLen)) {
        reason = "kv_length_below_prompt last=" + std::to_string(last)
                 + " prompt=" + std::to_string(promptLen);
        return false;
    }
    (void)genTokens;
    return true;
}

void dumpFrames(std::ostream& os, const std::vector<Deep2::AttnCert::Frame>& frames) {
    for (const auto& f : frames) {
        os << "stage=" << Deep2::AttnCert::stageName(f.stage)
           << " layer=" << f.layer
           << " pos=" << f.position
           << " count=" << f.count
           << " nonfinite=" << f.nonfinite
           << " min=" << f.min
           << " max=" << f.max
           << " l2=" << f.l2
           << " sum=" << f.sum
           << " sum_abs=" << f.sumAbs
           << " aux=" << f.aux
           << " hash=0x" << std::hex << f.fnv << std::dec
           << "\n";
    }
}

int fail(const char* reason, int code) {
    std::cerr << "ATTN-CERT-001=FAIL\nreason=" << reason << "\n";
    std::cout << "ATTN-CERT-001=NOT_CERTIFIED\n";
    return code;
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::string model;
        std::string prompt = "hello";
        int oneTokens = 1;
        int multiTokens = 8;
        std::string evidencePath;

        for (int i = 1; i < argc; ++i) {
            const std::string a = argv[i];
            auto value = [&](const char* flag) -> std::string {
                if (++i >= argc) throw std::runtime_error(std::string("missing value for ") + flag);
                return argv[i];
            };
            if (a == "--model") model = value("--model");
            else if (a == "--prompt") prompt = value("--prompt");
            else if (a == "--one-tokens") oneTokens = std::stoi(value("--one-tokens"));
            else if (a == "--multi-tokens") multiTokens = std::stoi(value("--multi-tokens"));
            else if (a == "--evidence") evidencePath = value("--evidence");
            else if (a == "--help" || a == "-h") {
                std::cout << "deep2_attn_cert --model spec [--prompt hello] "
                             "[--one-tokens 1] [--multi-tokens 8] [--evidence path]\n";
                return 0;
            } else {
                throw std::runtime_error("unknown argument: " + a);
            }
        }

        if (model.empty()) throw std::runtime_error("--model is required");
        if (oneTokens < 1 || oneTokens > 64) throw std::runtime_error("--one-tokens must be 1..64");
        if (multiTokens < 2 || multiTokens > 256) throw std::runtime_error("--multi-tokens must be 2..256");

        if (std::getenv("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA")) {
            return fail("refuse_RAWRXD_DEEP2_ALLOW_UNSAFE_MLA_set", 40);
        }
        if (std::getenv("RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM")) {
            return fail("refuse_RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM_set", 41);
        }

        const auto resolved = rawrxd::models::ModelCatalog::resolve(model);
        if (!resolved) return fail("model_unresolved", 2);

        const auto modelPath = resolved->path.empty()
            ? resolved->absolutePath.string()
            : resolved->path.string();

        Deep2Engine engine;
        if (!engine.loadModel(modelPath)) return fail("loadModel", 10);

        const auto& mw = engine.getModelWeights();
        if (mw.useMLA) return fail("model_is_MLA_rejected_for_ATTN_CERT", 42);
        for (size_t li = 0; li < mw.layers.size(); ++li) {
            if (mw.layers[li].hasSSM) {
                return fail("model_has_SSM_layer_rejected_for_ATTN_CERT", 43);
            }
        }
        if (mw.numHeads == 0 || mw.numKVHeads == 0 || mw.headDim == 0) {
            return fail("invalid_attention_topology", 44);
        }
        if (mw.numHeads % mw.numKVHeads != 0) {
            return fail("heads_not_divisible_by_kv_heads", 45);
        }

        EngineConfig cfg;
        cfg.hiddenDim = mw.hiddenDim;
        cfg.numLayers = mw.numLayers;
        cfg.numHeads = mw.numHeads;
        cfg.numKVHeads = mw.numKVHeads;
        cfg.headDim = mw.headDim;
        cfg.vocabSize = mw.vocabSize;
        cfg.maxSeqLen = 4096;
        cfg.useKVCache = true;
        cfg.useThreadPool = true;
        cfg.numThreads = 8;
        cfg.useMLA = false;

        if (!engine.initialize(cfg)) return fail("initialize", 15);

        std::vector<int> promptTokens = engine.tokenize(prompt);
        if (promptTokens.empty()) promptTokens.push_back(1);

        std::ofstream evidence;
        if (!evidencePath.empty()) {
            evidence.open(evidencePath, std::ios::out | std::ios::trunc);
            if (!evidence) return fail("evidence_open", 50);
            evidence << "ATTN-CERT-001 evidence dump\n"
                     << "model=" << modelPath << "\n"
                     << "prompt=" << prompt << "\n"
                     << "prompt_tokens=" << promptTokens.size() << "\n"
                     << "heads=" << mw.numHeads
                     << " kv_heads=" << mw.numKVHeads
                     << " head_dim=" << mw.headDim
                     << " hidden=" << mw.hiddenDim
                     << " layers=" << mw.numLayers << "\n"
                     << "scope=MHA_GQA_ONLY\n"
                     << "ssm_escape=REJECTED\n"
                     << "mla_escape=REJECTED\n"
                     << "streamer_touched=NO\n"
                     << "observation=digest_frames_only\n"
                     << "note=ResidencyCounters zero is a separate TELEMETRY defect\n\n";
        }

        auto runCase = [&](const char* name, int nTokens) -> int {
            Deep2::AttnCert::clear();
            Deep2::AttnCert::enable(true);

            std::vector<int> out(static_cast<size_t>(nTokens));
            const size_t generated = engine.generate(
                promptTokens.data(), promptTokens.size(),
                out.data(), static_cast<size_t>(nTokens));

            // Snapshot BEFORE disable — enable(false) must not clear frames.
            auto frames = Deep2::AttnCert::snapshot();
            Deep2::AttnCert::enable(false);
            Deep2::AttnCert::clear();

            if (generated == 0) return fail((std::string(name) + "_zero_tokens").c_str(), 20);

            const Counts c = tally(frames);
            if (c.norm < 1) return fail((std::string(name) + "_missing_attn_norm").c_str(), 31);
            if (c.q < 1 || c.k < 1 || c.v < 1) return fail((std::string(name) + "_missing_qkv").c_str(), 21);
            if (c.ropeQ < 1 || c.ropeK < 1) return fail((std::string(name) + "_missing_rope").c_str(), 22);
            if (c.kvWrite < 1) return fail((std::string(name) + "_missing_kv_write").c_str(), 32);
            if (c.score < 1) return fail((std::string(name) + "_missing_score").c_str(), 23);
            if (c.soft < 1) return fail((std::string(name) + "_missing_softmax").c_str(), 24);
            if (c.attn < 1) return fail((std::string(name) + "_missing_attn_out").c_str(), 25);
            if (c.o < 1) return fail((std::string(name) + "_missing_o_proj").c_str(), 26);
            if (c.resid < 1) return fail((std::string(name) + "_missing_residual").c_str(), 27);
            if (c.kvlen < 1) return fail((std::string(name) + "_missing_kv_length").c_str(), 28);

            std::string reason;
            if (!qkvDigestOk(frames, reason)) {
                return fail((std::string(name) + "_" + reason).c_str(), 33);
            }
            if (!softmaxInvariantsOk(frames, reason)) {
                return fail((std::string(name) + "_" + reason).c_str(), 29);
            }
            if (!kvProgressionOk(frames, promptTokens.size(), static_cast<size_t>(nTokens), reason)) {
                return fail((std::string(name) + "_" + reason).c_str(), 30);
            }

            std::cout << "case=" << name
                      << " tokens=" << generated
                      << " frames=" << frames.size()
                      << " norm=" << c.norm
                      << " q=" << c.q << " k=" << c.k << " v=" << c.v
                      << " ropeQ=" << c.ropeQ << " ropeK=" << c.ropeK
                      << " kvWrite=" << c.kvWrite
                      << " score=" << c.score << " soft=" << c.soft
                      << " attn=" << c.attn << " o=" << c.o << " resid=" << c.resid
                      << " kvlen=" << c.kvlen
                      << " PASS\n";

            if (evidence) {
                evidence << "=== case=" << name << " tokens=" << generated
                         << " frames=" << frames.size() << " ===\n";
                dumpFrames(evidence, frames);
                evidence << "\n";
            }
            return 0;
        };

        if (int rc = runCase("one_token", oneTokens)) return rc;
        if (int rc = runCase("multi_token", multiTokens)) return rc;

        std::cout
            << "model=" << modelPath << "\n"
            << "scope=MHA_GQA_ONLY\n"
            << "ssm_mla=REJECTED\n"
            << "streamer_touched=NO\n"
            << "lifecycle_status=CANDIDATE_PASS_UNCHANGED\n"
            << "telemetry_note=ResidencyCounters_zero_is_separate_TELEMETRY_defect\n"
            << "ATTN-CERT-001=CANDIDATE_PASS\n"
            << "ATTN-CERT-001_AUTHORITY=NOT_CERTIFIED\n";

        if (evidence) {
            evidence << "ATTN-CERT-001=CANDIDATE_PASS\n"
                     << "ATTN-CERT-001_AUTHORITY=NOT_CERTIFIED\n";
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "ATTN-CERT-001=FAIL\nreason=" << ex.what() << "\n";
        std::cout << "ATTN-CERT-001=NOT_CERTIFIED\n";
        return 1;
    }
}
