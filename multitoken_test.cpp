#include "rawrxd_modelgenie_ir_executor.cpp"

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <gguf_path> <evidence_dir>\n", argv[0]);
        return 1;
    }
    
    std::string ggufPath = argv[1];
    std::string evidenceDir = argv[2];
    
    std::fprintf(stderr, "=============================================================================\n");
    std::fprintf(stderr, "RAWRXD_MODELGENIE_MULTITOKEN_DECODE_TEST\n");
    std::fprintf(stderr, "=============================================================================\n\n");
    
    // Load ModelGenome from evidence
    MG::ModelGenome genome;
    if (!LoadModelGenomeFromEvidence(evidenceDir, genome)) {
        std::fprintf(stderr, "ERROR: Failed to load ModelGenome\n");
        return 1;
    }
    
    std::string originalHash = genome.computeCanonicalHash();
    std::fprintf(stderr, "Original canonical hash: %s\n", originalHash.c_str());
    
    // Create executor with KV cache
    IRExecutor executor(ggufPath, 1); // First token is 1
    
    // Token sequence to decode: start with token 1, then decode subsequent tokens
    // For teacher-forced testing, we use a known sequence
    // But for autonomous generation, we sample from logits
    std::vector<uint32_t> tokens = {1}; // Start with token 1
    const int max_tokens = 16;
    
    std::fprintf(stderr, "\n=== Multi-token decode (autonomous) ===\n");
    
    for (int step = 0; step < max_tokens; ++step) {
        uint32_t input_token = tokens.back();
        
        // Update executor's token ID for this step
        executor.tokenId_ = input_token;
        executor.tokenStorage_ = static_cast<float>(input_token);
        
        // Clear arena but keep KV cache
        executor.arena_.Clear();
        
        std::fprintf(stderr, "\n--- Step %d (position %zu), input token: %u ---\n", 
                     step, executor.Position(), input_token);
        
        bool success = executor.Execute();
        
        uint32_t predictedToken = executor.SampleToken();
        const std::vector<float>* logits = executor.GetLogits();
        bool logitsFinite = true;
        if (logits) {
            for (float v : *logits) {
                if (!std::isfinite(v)) { logitsFinite = false; break; }
            }
        } else {
            logitsFinite = false;
        }
        
        std::fprintf(stderr, "Predicted token: %u, Logits finite: %d, Ops: %u/%u\n",
                     predictedToken, logitsFinite ? 1 : 0, executor.Dispatched(), executor.Visited());
        
        if (!success || !logitsFinite) {
            std::fprintf(stderr, "ERROR: Execution failed at step %d\n", step);
            return 1;
        }
        
        tokens.push_back(predictedToken);
        
        // Advance position for next step
        executor.AdvancePosition();
    }
    
    std::fprintf(stderr, "\n=== Generated token sequence ===\n");
    for (size_t i = 0; i < tokens.size(); ++i) {
        std::fprintf(stderr, "  Position %zu: token %u\n", i, tokens[i]);
    }
    
    std::fprintf(stderr, "\n=============================================================================\n");
    std::fprintf(stderr, "MULTITOKEN_DECODE_TEST=PASS\n");
    std::fprintf(stderr, "TOKENS_GENERATED=%zu\n", tokens.size());
    std::fprintf(stderr, "=============================================================================\n");
    
    return 0;
}