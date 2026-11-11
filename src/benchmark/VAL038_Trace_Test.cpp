// ═══════════════════════════════════════════════════════════════════════════════
// VAL-038: Trace Test - Find where the hang occurs
// ═══════════════════════════════════════════════════════════════════════════════

#include <cstdio>
#include <cstdint>
#include <vector>

// Debug markers from assembly
extern "C" {
    extern uint64_t debug_marker_1;   // Entry
    extern uint64_t debug_marker_2;   // After prologue
    extern uint64_t debug_marker_3;   // After param load
    extern uint64_t debug_marker_4;   // Before outer loop
    extern uint64_t debug_marker_5;   // In outer loop
    extern uint64_t debug_marker_6;   // Before inner loop
    extern uint64_t debug_marker_7;   // In inner loop
    extern uint64_t debug_marker_8;   // After inner loop
    extern uint64_t debug_marker_9;   // After outer loop
    extern uint64_t debug_marker_10;  // Before epilogue
    extern uint64_t debug_marker_11;  // Exit
    
    void TreeAttention_Fused_VAL038(
        float* output,
        const float* Q,
        const float* K,
        const float* V,
        uint32_t num_q,
        uint32_t num_k,
        const uint8_t* tree_mask
    );
}

void print_markers() {
    printf("Debug markers:\n");
    printf("  marker_1 (entry):          %s\n", debug_marker_1 ? "HIT" : "---");
    printf("  marker_2 (after prologue): %s\n", debug_marker_2 ? "HIT" : "---");
    printf("  marker_3 (after params):   %s\n", debug_marker_3 ? "HIT" : "---");
    printf("  marker_4 (before outer):   %s\n", debug_marker_4 ? "HIT" : "---");
    printf("  marker_5 (in outer loop):  %s\n", debug_marker_5 ? "HIT" : "---");
    printf("  marker_6 (before inner):   %s\n", debug_marker_6 ? "HIT" : "---");
    printf("  marker_7 (in inner loop):  %s\n", debug_marker_7 ? "HIT" : "---");
    printf("  marker_8 (after inner):    %s\n", debug_marker_8 ? "HIT" : "---");
    printf("  marker_9 (after outer):    %s\n", debug_marker_9 ? "HIT" : "---");
    printf("  marker_10 (before epilog): %s\n", debug_marker_10 ? "HIT" : "---");
    printf("  marker_11 (exit):          %s\n", debug_marker_11 ? "HIT" : "---");
}

int main() {
    printf("=== VAL-038 Trace Test ===\n\n");
    
    // Zero all markers first
    debug_marker_1 = debug_marker_2 = debug_marker_3 = debug_marker_4 = debug_marker_5 = 0;
    debug_marker_6 = debug_marker_7 = debug_marker_8 = debug_marker_9 = debug_marker_10 = debug_marker_11 = 0;
    
    constexpr uint32_t NUM_Q = 2;
    constexpr uint32_t NUM_K = 2;
    constexpr uint32_t HEAD_DIM = 64;
    
    std::vector<float> output(NUM_Q * HEAD_DIM, 0.0f);
    std::vector<float> Q(NUM_Q * HEAD_DIM, 0.1f);
    std::vector<float> K(NUM_K * HEAD_DIM, 0.1f);
    std::vector<float> V(NUM_K * HEAD_DIM, 0.1f);
    std::vector<uint8_t> treeMask(NUM_Q * NUM_K, 1);
    
    printf("Before kernel call:\n");
    print_markers();
    
    printf("\nCalling kernel with num_q=%u, num_k=%u...\n", NUM_Q, NUM_K);
    
    // Set a timeout by using a simple counter
    TreeAttention_Fused_VAL038(
        output.data(),
        Q.data(),
        K.data(),
        V.data(),
        NUM_Q,
        NUM_K,
        treeMask.data()
    );
    
    printf("\nAfter kernel call:\n");
    print_markers();
    
    // Check results
    printf("\n=== Analysis ===\n");
    if (!debug_marker_1) {
        printf("ERROR: Never entered kernel!\n");
        return 1;
    }
    if (!debug_marker_11) {
        printf("HANG DETECTED: Kernel did not reach exit!\n");
        if (debug_marker_7 && !debug_marker_8) {
            printf("  -> Stuck in inner loop\n");
        } else if (debug_marker_5 && !debug_marker_9) {
            printf("  -> Stuck in outer loop\n");
        } else if (debug_marker_4 && !debug_marker_5) {
            printf("  -> Stuck before outer loop\n");
        }
        return 1;
    }
    
    printf("SUCCESS: Kernel completed normally!\n");
    return 0;
}
