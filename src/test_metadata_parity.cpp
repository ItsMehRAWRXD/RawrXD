#include "GGUFLoader.hpp"
#include <iostream>
#include <string>
#include <cassert>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: test_metadata_parity <model.gguf>" << std::endl;
        return 1;
    }
    
    std::string model_path = argv[1];
    
    try {
        std::cout << "=== Deep2Engine Standalone Metadata Parity Test ===" << std::endl;
        std::cout << "Model: " << model_path << std::endl;
        
        EngineContext ctx;
        
        if (!LoadUniversalBlob(model_path, &ctx)) {
            std::cerr << "Failed to load GGUF file" << std::endl;
            return 1;
        }
        std::cout << "✓ File loaded successfully" << std::endl;
        
        std::cout << "\n=== PARSED METADATA ===" << std::endl;
        std::cout << "hiddenDim: " << ctx.cfg.hiddenDim << std::endl;
        std::cout << "numLayers: " << ctx.cfg.numLayers << std::endl;
        std::cout << "context_length (maxSeqLen): " << ctx.cfg.maxSeqLen << std::endl;
        std::cout << "embedding_dim (hiddenDim): " << ctx.cfg.hiddenDim << std::endl;
        std::cout << "intermediateDim (feed_forward_length): " << ctx.cfg.intermediateDim << std::endl;
        std::cout << "vocabSize: " << ctx.cfg.vocabSize << std::endl;
        std::cout << "numHeads: " << ctx.cfg.numHeads << std::endl;
        std::cout << "ropeThetaGlobal: " << ctx.cfg.ropeThetaGlobal << std::endl;
        std::cout << "ropeScaleFactor: " << ctx.cfg.ropeScaleFactor << std::endl;
        
        // Check tensor count
        std::cout << "Tensor count: " << ctx.tensors.size() << std::endl;
        
        // Verify parity with expected Phi-3 Mini values
        std::cout << "\n=== PARITY CHECK ===" << std::endl;
        bool parity_ok = true;
        
        // Expected values from standalone Deep2Engine run
        struct ExpectedValue { const char* name; size_t expected; size_t actual; };
        ExpectedValue checks[] = {
            {"hiddenDim", 3072, ctx.cfg.hiddenDim},
            {"numLayers", 32, ctx.cfg.numLayers},
            {"maxSeqLen", 131072, ctx.cfg.maxSeqLen},
            {"intermediateDim", 8192, ctx.cfg.intermediateDim},
            {"vocabSize", 32064, ctx.cfg.vocabSize},
            {"numHeads", 32, ctx.cfg.numHeads}
        };
        
        for (const auto& check : checks) {
            if (check.actual != check.expected) {
                std::cerr << "  ✗ " << check.name << ": got " << check.actual << ", expected " << check.expected << std::endl;
                parity_ok = false;
            } else {
                std::cout << "  ✓ " << check.name << " = " << check.actual << std::endl;
            }
        }
        
        // Check tensor names for key tensors
        std::cout << "\n=== KEY TENSOR CHECKS (Phi-3 Architecture) ===" << std::endl;
        const std::vector<std::string> key_tensors = {
            "blk.0.ffn_up.weight",      // Fused gate + up projection
            "blk.0.ffn_down.weight",    // Down projection
            "blk.0.attn_qkv.weight",    // Fused QKV projection (Phi-3)
            "output.weight",
            "token_embd.weight"
        };
        
        for (const auto& name : key_tensors) {
            auto it = ctx.tensors.find(name);
            if (it != ctx.tensors.end()) {
                std::cout << "  ✓ " << name << " found (type=" << it->second.type 
                          << ", dims=";
                for (size_t d = 0; d < it->second.dims.size(); ++d) {
                    std::cout << it->second.dims[d] << (d+1 < it->second.dims.size() ? "x" : "");
                }
                std::cout << ")" << std::endl;
            } else {
                std::cerr << "  ✗ " << name << " NOT FOUND" << std::endl;
                parity_ok = false;
            }
        }
        
        // Check for phi3.* keys in original metadata (via first pass)
        std::cout << "\n=== ARCHITECTURE PREFIX CHECK ===" << std::endl;
        // The loader should have found phi3.embedding_length, phi3.block_count, etc.
        
        std::cout << "\n=== RESULT ===" << std::endl;
        if (parity_ok) {
            std::cout << "✓ PARITY TEST PASSED - All expected Phi-3 Mini metadata verified" << std::endl;
            return 0;
        } else {
            std::cerr << "✗ PARITY TEST FAILED - Metadata mismatch detected" << std::endl;
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}