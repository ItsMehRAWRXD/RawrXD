#include "rawrxd_modelgenie_ir_executor.cpp"

int main(int argc, char* argv[])
{
    if (argc < 4) {
        std::fprintf(stderr, "Usage: %s <gguf_path> <evidence_dir> <tokens...>\n", argv[0]);
        return 1;
    }
    
    std::string ggufPath = argv[1];
    std::string evidenceDir = argv[2];
    
    std::vector<uint32_t> tokens;
    for (int i = 3; i < argc; ++i) {
        tokens.push_back(static_cast<uint32_t>(std::stoul(argv[i])));
    }
    
    if (tokens.empty()) {
        std::fprintf(stderr, "No tokens provided\n");
        return 1;
    }
    
    std::fprintf(stderr, "=============================================================================\n");
    std::fprintf(stderr, "RAWRXD_MODELGENIE_TEACHER_FORCED_DECODE\n");
    std::fprintf(stderr, "=============================================================================\n\n");
    
    // Load ModelGenome from evidence
    MG::ModelGenome genome;
    if (!LoadModelGenomeFromEvidence(evidenceDir, genome)) {
        std::fprintf(stderr, "ERROR: Failed to load ModelGenome\n");
        return 1;
    }
    
    std::string originalHash = genome.computeCanonicalHash();
    std::fprintf(stderr, "Original canonical hash: %s\n", originalHash.c_str());
    
    std::fprintf(stderr, "\n=== Teacher-forced decode (%zu tokens) ===\n", tokens.size());
    std::fprintf(stderr, "Input history: ");
    for (auto t : tokens) std::fprintf(stderr, "%u ", t);
    std::fprintf(stderr, "\n\n");
    
    IRExecutor executor(ggufPath, tokens[0]);
    
    for (size_t step = 0; step < tokens.size(); ++step) {
        uint32_t input_token = tokens[step];
        executor.SetTokenId(input_token);
        executor.ClearArena();
        
        std::fprintf(stderr, "\n--- Step %zu (position %zu), input token: %u ---\n", 
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
            std::fprintf(stderr, "ERROR: Execution failed at step %zu\n", step);
            return 1;
        }
        
        // Save logits for comparison
        char fname[512];
        sprintf_s(fname, "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\native_tf_logits_pos%zu.bin", step);
        if (logits && !logits->empty()) {
            std::ofstream f(fname, std::ios::binary);
            f.write(reinterpret_cast<const char*>(logits->data()), logits->size() * sizeof(float));
            f.close();
            std::fprintf(stderr, "Saved logits to %s\n", fname);
        }
        
        executor.AdvancePosition();
    }
    
    std::fprintf(stderr, "\n=============================================================================\n");
    std::fprintf(stderr, "TEACHER_FORCED_DECODE=PASS\n");
    std::fprintf(stderr, "TOKENS_PROCESSED=%zu\n", tokens.size());
    std::fprintf(stderr, "=============================================================================\n");
    
    return 0;
}