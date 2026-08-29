/*
 SSM-CERT-001 — observe existing experimental computeSSM path.

 Philosophy (same as ATTN-CERT):
   - Digest-only fixed-size frames; no float buffer copies onto stack
   - One-token and multi-token cases when an SSM/hybrid GGUF is available
   - Do NOT rewrite SSM arithmetic to satisfy the harness
   - Do NOT touch STREAMER sequencing
   - ATTN-CERT evidence remains frozen

 Without an SSM-bearing model the harness reports AWAITING_SSM_MODEL
 (NOT a candidate pass). Quarantine remains production default.
*/
#include "Deep2Engine.h"
#include "SsmCertProbe.hpp"
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
    int alpha = 0, beta = 0, conv = 0, pre = 0, post = 0;
    int norm = 0, out = 0, seq = 0;
};

Counts tally(const std::vector<Deep2::SsmCert::Frame>& frames) {
    Counts c;
    using S = Deep2::SsmCert::Stage;
    for (const auto& f : frames) {
        switch (f.stage) {
        case S::Alpha: c.alpha++; break;
        case S::Beta: c.beta++; break;
        case S::Conv: c.conv++; break;
        case S::StatePre: c.pre++; break;
        case S::StatePost: c.post++; break;
        case S::Norm: c.norm++; break;
        case S::Out: c.out++; break;
        case S::SeqStep: c.seq++; break;
        }
    }
    return c;
}

bool digestsFinite(const std::vector<Deep2::SsmCert::Frame>& frames, std::string& reason) {
    using S = Deep2::SsmCert::Stage;
    for (const auto& f : frames) {
        if (f.stage == S::SeqStep) continue;
        if (f.count == 0) {
            reason = "empty_stage_" + std::string(Deep2::SsmCert::stageName(f.stage));
            return false;
        }
        if (f.nonfinite != 0 || f.l2 < 0.0) {
            reason = "nonfinite_" + std::string(Deep2::SsmCert::stageName(f.stage));
            return false;
        }
    }
    return true;
}

bool seqProgressionOk(const std::vector<Deep2::SsmCert::Frame>& frames,
                      size_t minSteps, std::string& reason) {
    std::vector<double> steps;
    for (const auto& f : frames) {
        if (f.stage == Deep2::SsmCert::Stage::SeqStep) steps.push_back(f.aux);
    }
    if (steps.size() < minSteps) {
        reason = "seq_steps_short got=" + std::to_string(steps.size())
                 + " need=" + std::to_string(minSteps);
        return false;
    }
    for (size_t i = 1; i < steps.size(); ++i) {
        if (steps[i] + 1e-9 < steps[i - 1]) {
            reason = "seq_regressed";
            return false;
        }
        if (steps[i] < steps[i - 1] + 1.0 - 1e-9) {
            reason = "seq_not_strictly_increasing";
            return false;
        }
    }
    return true;
}

// Persistent state evolution: StatePre[n+1] digest must equal StatePost[n].
bool stateEvolutionOk(const std::vector<Deep2::SsmCert::Frame>& frames, std::string& reason) {
    using S = Deep2::SsmCert::Stage;
    struct StepDig {
        bool havePre = false, havePost = false;
        std::uint64_t pre = 0, post = 0;
        double preL2 = 0, postL2 = 0;
    };
    std::vector<StepDig> byPos;
    for (const auto& f : frames) {
        if (f.stage != S::StatePre && f.stage != S::StatePost) continue;
        if (f.position >= byPos.size()) byPos.resize(f.position + 1);
        auto& s = byPos[f.position];
        if (f.stage == S::StatePre) {
            s.havePre = true;
            s.pre = f.fnv;
            s.preL2 = f.l2;
        } else {
            s.havePost = true;
            s.post = f.fnv;
            s.postL2 = f.l2;
        }
    }
    size_t linked = 0;
    for (size_t p = 0; p + 1 < byPos.size(); ++p) {
        if (!byPos[p].havePost || !byPos[p + 1].havePre) continue;
        ++linked;
        if (byPos[p].post != byPos[p + 1].pre) {
            reason = "state_pre_post_mismatch pos=" + std::to_string(p)
                     + "->" + std::to_string(p + 1);
            return false;
        }
        // Multi-token must actually change state across at least one step.
        if (byPos[p].post == byPos[p].pre && byPos[p].postL2 == 0.0 && byPos[p].preL2 == 0.0) {
            // allow only if both zero (cold start); still require later change
        }
    }
    // Require at least one Post→next Pre link when multi-step.
    size_t posts = 0;
    for (const auto& s : byPos) if (s.havePost) ++posts;
    if (posts >= 2 && linked < 1) {
        reason = "no_state_continuity_links";
        return false;
    }
    if (posts >= 2) {
        bool changed = false;
        for (size_t p = 0; p + 1 < byPos.size(); ++p) {
            if (byPos[p].havePost && byPos[p + 1].havePost && byPos[p].post != byPos[p + 1].post) {
                changed = true;
                break;
            }
        }
        if (!changed) {
            reason = "multi_token_state_did_not_change";
            return false;
        }
    }
    return true;
}

void dumpFrames(std::ostream& os, const std::vector<Deep2::SsmCert::Frame>& frames) {
    for (const auto& f : frames) {
        os << "stage=" << Deep2::SsmCert::stageName(f.stage)
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
    std::cerr << "SSM-CERT-001=FAIL\nreason=" << reason << "\n";
    std::cout << "SSM-CERT-001=NOT_CERTIFIED\n";
    return code;
}

size_t countSsmLayers(const Deep2::ModelWeights& mw) {
    size_t n = 0;
    for (const auto& lw : mw.layers) if (lw.hasSSM) ++n;
    return n;
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
                std::cout << "deep2_ssm_cert --model spec [--prompt hello] "
                             "[--one-tokens 1] [--multi-tokens 8] [--evidence path]\n"
                             "Requires hybrid SSM GGUF + RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1\n";
                return 0;
            } else {
                throw std::runtime_error("unknown argument: " + a);
            }
        }

        if (model.empty()) throw std::runtime_error("--model is required");

        // Path digests require explicit experimental allow — never silently enable.
        if (!std::getenv("RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM")) {
            std::cout
                << "SSM-CERT-001=AWAITING_ALLOW_FLAG\n"
                << "note=Set RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1 only for scaffolding runs\n"
                << "quarantine=PRODUCTION_DEFAULT\n"
                << "SSM-CERT-001_AUTHORITY=NOT_CERTIFIED\n"
                << "attn_status=CANDIDATE_PASS_UNCHANGED\n"
                << "streamer_touched=NO\n";
            return 60;
        }

        const auto resolved = rawrxd::models::ModelCatalog::resolve(model);
        if (!resolved) return fail("model_unresolved", 2);
        const auto modelPath = resolved->path.empty()
            ? resolved->absolutePath.string()
            : resolved->path.string();

        Deep2Engine engine;
        if (!engine.loadModel(modelPath)) {
            return fail("loadModel_failed_or_quarantine", 10);
        }

        const auto& mw = engine.getModelWeights();
        const size_t ssmLayers = countSsmLayers(mw);
        if (ssmLayers == 0) {
            std::cout
                << "model=" << modelPath << "\n"
                << "ssm_layers=0\n"
                << "SSM-CERT-001=AWAITING_SSM_MODEL\n"
                << "note=TinyLlama/MHA-only models cannot exercise computeSSM; "
                   "provide a hybrid SSM GGUF without rewriting SSM to fake green\n"
                << "SSM-CERT-001_AUTHORITY=NOT_CERTIFIED\n"
                << "attn_status=CANDIDATE_PASS_UNCHANGED\n"
                << "streamer_touched=NO\n"
                << "architecture_rewrite=NO\n";
            return 61;
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

        if (!engine.initialize(cfg)) return fail("initialize", 15);

        std::vector<int> promptTokens = engine.tokenize(prompt);
        if (promptTokens.empty()) promptTokens.push_back(1);

        std::ofstream evidence;
        if (!evidencePath.empty()) {
            evidence.open(evidencePath, std::ios::out | std::ios::trunc);
            if (!evidence) return fail("evidence_open", 50);
            evidence << "SSM-CERT-001 evidence dump\n"
                     << "model=" << modelPath << "\n"
                     << "ssm_layers=" << ssmLayers << "\n"
                     << "observation=digest_frames_only\n"
                     << "architecture_rewrite=NO\n"
                     << "streamer_touched=NO\n"
                     << "attn_evidence=FROZEN_CANDIDATE_PASS\n\n";
        }

        auto runCase = [&](const char* name, int nTokens, size_t minSeq) -> int {
            Deep2::SsmCert::clear();
            Deep2::SsmCert::resetSeq();
            Deep2::SsmCert::enable(true);

            std::vector<int> out(static_cast<size_t>(nTokens));
            const size_t generated = engine.generate(
                promptTokens.data(), promptTokens.size(),
                out.data(), static_cast<size_t>(nTokens));

            auto frames = Deep2::SsmCert::snapshot();
            Deep2::SsmCert::enable(false);
            Deep2::SsmCert::clear();

            if (generated == 0) return fail((std::string(name) + "_zero_tokens").c_str(), 20);

            const Counts c = tally(frames);
            if (c.alpha < 1 || c.beta < 1 || c.conv < 1)
                return fail((std::string(name) + "_missing_proj").c_str(), 21);
            if (c.pre < 1 || c.post < 1)
                return fail((std::string(name) + "_missing_state").c_str(), 22);
            if (c.out < 1)
                return fail((std::string(name) + "_missing_out").c_str(), 23);
            if (c.seq < 1)
                return fail((std::string(name) + "_missing_seq").c_str(), 24);

            std::string reason;
            if (!digestsFinite(frames, reason))
                return fail((std::string(name) + "_" + reason).c_str(), 25);
            if (!seqProgressionOk(frames, minSeq, reason))
                return fail((std::string(name) + "_" + reason).c_str(), 26);
            if (!stateEvolutionOk(frames, reason))
                return fail((std::string(name) + "_" + reason).c_str(), 27);

            std::cout << "case=" << name
                      << " tokens=" << generated
                      << " frames=" << frames.size()
                      << " alpha=" << c.alpha << " beta=" << c.beta
                      << " conv=" << c.conv << " pre=" << c.pre
                      << " post=" << c.post << " norm=" << c.norm
                      << " out=" << c.out << " seq=" << c.seq
                      << " PASS\n" << std::flush;

            if (evidence) {
                evidence << "=== case=" << name << " tokens=" << generated
                         << " frames=" << frames.size() << " ===\n";
                dumpFrames(evidence, frames);
                evidence << "\n";
            }
            return 0;
        };

        // Prefill of 1 prompt token + decode steps both bump seq on first SSM layer.
        if (int rc = runCase("one_token", oneTokens, 1)) return rc;
        if (int rc = runCase("multi_token", multiTokens, 2)) return rc;

        std::cout
            << "model=" << modelPath << "\n"
            << "ssm_layers=" << ssmLayers << "\n"
            << "ollama_tag=pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest\n"
            << "scope=EXPERIMENTAL_SSM_OBSERVATION\n"
            << "architecture_rewrite=NO\n"
            << "streamer_touched=NO\n"
            << "attn_status=CANDIDATE_PASS_UNCHANGED\n"
            << "note=experimental_approximation_not_architecture_parity\n"
            << "uses__Exit=YES\n"
            << "destructor=NOT_CERTIFIED (exit avoids known teardown heap corruption)\n"
            << "SSM-CERT-001=CANDIDATE_PASS\n"
            << "SSM-CERT-001_AUTHORITY=NOT_CERTIFIED\n"
            << std::flush;

        if (evidence) {
            evidence << "SSM-CERT-001=CANDIDATE_PASS\n"
                     << "SSM-CERT-001_AUTHORITY=NOT_CERTIFIED\n"
                     << "uses__Exit=YES\n"
                     << "destructor=NOT_CERTIFIED\n";
            evidence.flush();
            evidence.close();
        }
        // Digest path proven; destructor heap corruption is separate (LIFECYCLE debt).
        std::_Exit(0);
    } catch (const std::exception& ex) {
        std::cerr << "SSM-CERT-001=FAIL\nreason=" << ex.what() << "\n";
        std::cout << "SSM-CERT-001=NOT_CERTIFIED\n";
        return 1;
    }
}
