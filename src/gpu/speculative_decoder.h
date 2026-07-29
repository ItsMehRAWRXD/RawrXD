#ifndef SPECULATIVE_DECODER_H
#define SPECULATIVE_DECODER_H

<<<<<<< HEAD
#include <string>
#include <vector>
#include <cstdio>
#include <random>

// Speculative decoding – draft with TinyLlama, verify with Phi-3 → 1.8× tokens/sec boost on RX 7800 XT.
class SpeculativeDecoder
=======
#include <vector>
#include <string>
#include <memory>
#include "../cpu_inference_engine.h"

class SpeculativeDecoder 
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
public:
    explicit SpeculativeDecoder();
    ~SpeculativeDecoder();

    // Set draft model (smaller, faster model for speculation)
    void setDraftModel(const std::string &modelPath);
<<<<<<< HEAD

    // Set target model (larger, more accurate model for verification)
    void setTargetModel(const std::string &modelPath);

=======
    
    // Set target model (larger, more accurate model for verification)
    void setTargetModel(const std::string &modelPath);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    // Generate tokens using speculative decoding
    // Returns verified tokens from target model
    std::vector<int> generateTokens(const std::string &prompt, int maxTokens);

<<<<<<< HEAD
    // Callback hooks (replacing Qt signals)
    void (*onTokensGenerated)(const std::vector<int>& tokens) = nullptr;
    void (*onAcceptanceRateChanged)(float rate) = nullptr;
=======
    void tokensGenerated(const std::vector<int> &tokens);
    void acceptanceRateChanged(float rate);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

private:
    std::vector<int> generateDraftTokens(const std::string &prompt, int maxTokens);
    std::vector<int> verifyTokens(const std::string &prompt, const std::vector<int> &draftTokens);

    std::string m_draftModelPath;
    std::string m_targetModelPath;
<<<<<<< HEAD
    bool m_gpuAccelerated;
    bool m_draftModelLoaded;
    bool m_targetModelLoaded;

    // RNG for draft token generation
    std::mt19937 m_rng;
};

=======
    
    // Engines
    std::unique_ptr<RawrXD::CPUInferenceEngine> m_draftEngine;
    std::unique_ptr<RawrXD::CPUInferenceEngine> m_targetEngine;

    bool m_gpuAccelerated;
    bool m_draftModelLoaded;
    bool m_targetModelLoaded;
};


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#endif // SPECULATIVE_DECODER_H

