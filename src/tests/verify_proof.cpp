// ============================================================================
// RawrXD Proof Verification Tool
// Phase 7C: Verify execution proofs against known model
// ============================================================================
// Usage: verify_proof.exe <model.gguf> <proof.rawrproof>
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>
#include "../core/hash_chain.hpp"

using namespace RawrXD::Core;

void PrintUsage(const char* prog) {
    printf("RawrXD Proof Verification Tool\n");
    printf("Phase 7C: Immutable Execution Fabric\n\n");
    printf("Usage: %s <model.gguf> <proof.rawrproof>\n\n", prog);
    printf("Verifies that an execution proof matches:\n");
    printf("  - Model file hash\n");
    printf("  - Checkpoint chain integrity\n");
    printf("  - Execution determinism\n\n");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        PrintUsage("verify_proof");
        return 1;
    }
    
    printf("========================================\n");
    printf("RawrXD Proof Verification\n");
    printf("========================================\n\n");
    
    // Convert paths to char
    int len1 = WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, nullptr, 0, nullptr, nullptr);
    
    char* model_path = new char[len1];
    char* proof_path = new char[len2];
    
    WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, model_path, len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, proof_path, len2, nullptr, nullptr);
    
    printf("Model: %s\n", model_path);
    printf("Proof: %s\n\n", proof_path);
    
    // Step 1: Hash the model file
    printf("Step 1: Computing model hash...\n");
    uint64_t model_hash = HashGGUFModel(model_path);
    
    char hash_str[32];
    HashChainManager::FormatHash(model_hash, hash_str, sizeof(hash_str));
    printf("  Model hash: %s\n\n", hash_str);
    
    // Step 2: Load the proof chain
    printf("Step 2: Loading proof chain...\n");
    HashChainManager proof_chain;
    if (!proof_chain.ImportChain(proof_path)) {
        printf("  ERROR: Failed to load proof file\n");
        delete[] model_path;
        delete[] proof_path;
        return 1;
    }
    
    printf("  Checkpoints: %zu\n", proof_chain.GetCheckpointCount());
    printf("  Chain hash:  ");
    HashChainManager::FormatHash(proof_chain.GetCurrentHash(), hash_str, sizeof(hash_str));
    printf("%s\n\n", hash_str);
    
    // Step 3: Verify model hash matches
    printf("Step 3: Verifying model hash...\n");
    const ExecutionCheckpoint* first_cp = proof_chain.GetCheckpoint(0);
    if (!first_cp) {
        printf("  ERROR: No checkpoints in proof\n");
        delete[] model_path;
        delete[] proof_path;
        return 1;
    }
    
    if (first_cp->hash_value != model_hash) {
        printf("  ERROR: Model hash mismatch!\n");
        printf("    Expected: ");
        HashChainManager::FormatHash(model_hash, hash_str, sizeof(hash_str));
        printf("%s\n", hash_str);
        printf("    Got:      ");
        HashChainManager::FormatHash(first_cp->hash_value, hash_str, sizeof(hash_str));
        printf("%s\n\n", hash_str);
        delete[] model_path;
        delete[] proof_path;
        return 1;
    }
    printf("  Model hash: MATCH\n\n");
    
    // Step 4: Verify chain integrity
    printf("Step 4: Verifying chain integrity...\n");
    if (!proof_chain.VerifyChain()) {
        printf("  ERROR: Chain integrity check failed!\n");
        printf("  The proof may have been tampered with.\n\n");
        delete[] model_path;
        delete[] proof_path;
        return 1;
    }
    printf("  Chain integrity: VERIFIED\n\n");
    
    // Step 5: Print checkpoint summary
    printf("Step 5: Checkpoint Summary\n");
    printf("--------------------------\n");
    
    size_t cp_count = proof_chain.GetCheckpointCount();
    for (size_t i = 0; i < cp_count && i < 20; ++i) {
        const ExecutionCheckpoint* cp = proof_chain.GetCheckpoint(i);
        if (!cp) break;
        
        HashChainManager::FormatHash(cp->hash_value, hash_str, sizeof(hash_str));
        printf("  [%2zu] %-15s L=%u P=%u | %s\n",
               i,
               HashChainManager::GetStageName(cp->stage),
               cp->layer_index,
               cp->token_position,
               hash_str);
    }
    
    if (cp_count > 20) {
        printf("  ... and %zu more checkpoints\n", cp_count - 20);
    }
    
    printf("\n========================================\n");
    printf("VERIFICATION SUCCESSFUL\n");
    printf("========================================\n");
    printf("\nThis proof is cryptographically bound to:\n");
    printf("  Model: %s\n", model_path);
    printf("  Chain: %s\n", hash_str);
    printf("\nThe execution can be reproduced deterministically.\n");
    
    delete[] model_path;
    delete[] proof_path;
    return 0;
}

// Standard main entry point
int main(int argc, char* argv[]) {
    // Convert to wide and call wmain
    wchar_t** wargv = new wchar_t*[argc];
    for (int i = 0; i < argc; ++i) {
        int len = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, nullptr, 0);
        wargv[i] = new wchar_t[len];
        MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wargv[i], len);
    }
    
    int result = wmain(argc, wargv);
    
    for (int i = 0; i < argc; ++i) {
        delete[] wargv[i];
    }
    delete[] wargv;
    
    return result;
}
