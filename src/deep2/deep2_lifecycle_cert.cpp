/*
 RawrXD LIFECYCLE-CERT-001 candidate harness.
 Uses the proven Deep2Engine::generate() path (same contract as
 test_generate_one_token). Does not update PROJECT_STATE.txt.
 Emits CANDIDATE_PASS only — not authority CERTIFIED.
*/
#include "Deep2Engine.h"
#include "../models/ModelCatalog.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;

int main(int argc, char** argv) {
    try {
        std::string model;
        std::string prompt = "hello";
        int iterations = 3;
        int tokens = 8;

        for (int i = 1; i < argc; ++i) {
            const std::string a = argv[i];
            auto value = [&](const char* flag) -> std::string {
                if (++i >= argc) throw std::runtime_error(std::string("missing value for ") + flag);
                return argv[i];
            };

            if (a == "--model") model = value("--model");
            else if (a == "--prompt") prompt = value("--prompt");
            else if (a == "--iterations") iterations = std::stoi(value("--iterations"));
            else if (a == "--tokens") tokens = std::stoi(value("--tokens"));
            else if (a == "--help" || a == "-h") {
                std::cout << "deep2_lifecycle_cert_candidate --model spec "
                             "[--iterations 3] [--tokens 8] [--prompt hello]\n";
                return 0;
            } else {
                throw std::runtime_error("unknown argument: " + a);
            }
        }

        if (model.empty()) throw std::runtime_error("--model is required");
        if (iterations < 2 || iterations > 100) throw std::runtime_error("--iterations must be 2..100");
        if (tokens < 1 || tokens > 256) throw std::runtime_error("--tokens must be 1..256");

        const auto resolved = rawrxd::models::ModelCatalog::resolve(model);
        if (!resolved) {
            std::cerr << "LIFECYCLE-CERT-001=CANDIDATE_FAIL\nreason=model_unresolved\n";
            return 2;
        }

        const auto modelPath = resolved->path.empty()
            ? resolved->absolutePath.string()
            : resolved->path.string();

        for (int n = 0; n < iterations; ++n) {
            std::cerr << "[LIFE] iteration=" << n << " construct BEGIN\n" << std::flush;
            {
                Deep2Engine engine;

                std::cerr << "[LIFE] iteration=" << n << " loadModel\n" << std::flush;
                if (!engine.loadModel(modelPath)) {
                    std::cerr << "LIFECYCLE-CERT-001=CANDIDATE_FAIL\n"
                              << "iteration=" << n << "\n"
                              << "phase=load\n";
                    return 10;
                }

                const auto& mw = engine.getModelWeights();
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

                std::cerr << "[LIFE] iteration=" << n << " initialize\n" << std::flush;
                if (!engine.initialize(cfg)) {
                    std::cerr << "LIFECYCLE-CERT-001=CANDIDATE_FAIL\n"
                              << "iteration=" << n << "\n"
                              << "phase=initialize\n";
                    return 15;
                }

                std::vector<int> promptTokens = engine.tokenize(prompt);
                if (promptTokens.empty()) {
                    // Fallback: single token id 1 so teardown still exercises destroy.
                    promptTokens.push_back(1);
                }

                std::vector<int> outputTokens(static_cast<size_t>(tokens));
                std::cerr << "[LIFE] iteration=" << n << " generate BEGIN\n" << std::flush;
                const size_t generated = engine.generate(
                    promptTokens.data(), promptTokens.size(),
                    outputTokens.data(), static_cast<size_t>(tokens));
                if (generated == 0) {
                    std::cerr << "LIFECYCLE-CERT-001=CANDIDATE_FAIL\n"
                              << "iteration=" << n << "\n"
                              << "phase=generate\n"
                              << "error=zero_tokens\n";
                    return 20;
                }
                std::cerr << "[LIFE] iteration=" << n << " generation complete tokens="
                          << generated << "\n" << std::flush;

                std::cerr << "[LIFE] iteration=" << n << " unloadModel\n" << std::flush;
                engine.unloadModel();
                std::cerr << "[LIFE] iteration=" << n << " leaving engine scope\n" << std::flush;
            }
            std::cerr << "[LIFE] iteration=" << n << " engine destructor returned\n" << std::flush;

            std::cout << "iteration=" << n
                      << " construct=PASS load=PASS generate=PASS unload=PASS destroy=PASS\n";
        }

        std::cout
            << "model=" << modelPath << "\n"
            << "iterations=" << iterations << "\n"
            << "uses__Exit=NO\n"
            << "memory_growth=NOT_MEASURED\n"
            << "LIFECYCLE-CERT-001=CANDIDATE_PASS\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "LIFECYCLE-CERT-001=CANDIDATE_FAIL\nreason=" << ex.what() << "\n";
        return 1;
    }
}
