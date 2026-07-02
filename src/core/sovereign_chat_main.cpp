// =============================================================================
// sovereign_chat_main.cpp
// C wrapper for pure MASM chat loop and detokenizer
// Links against kernel32.lib only
// =============================================================================

#include <windows.h>
#include <cstdint>

// MASM exports
extern "C" {
    // Detokenizer
    int SovereignDetokenizer_Init(
        const char* vocab_data,
        uint64_t vocab_size,
        const uint64_t* vocab_lengths,
        const uint64_t* special_ids
    );
    
    uint64_t SovereignDetokenizer_Detokenize(
        const uint32_t* token_ids,
        uint64_t token_count,
        char* output_buffer,
        uint64_t output_capacity,
        uint8_t strip_special,
        uint8_t render_space
    );
    
    void SovereignDetokenizer_Cleanup();
    
    // Chat loop
    typedef uint64_t (*InferenceCallback)(
        void* context,
        const char* input,
        uint64_t input_len,
        char* output,
        uint64_t output_capacity
    );
    
    void ChatLoop_Run(InferenceCallback callback, void* context);
}

// Simple stub inference that echoes back with token IDs
uint64_t __cdecl StubInference(
    void* context,
    const char* input,
    uint64_t input_len,
    char* output,
    uint64_t output_capacity
) {
    // Simple response: echo input with prefix
    const char* prefix = "Echo: ";
    size_t prefix_len = 6;
    
    if (prefix_len + input_len + 1 > output_capacity) {
        input_len = output_capacity - prefix_len - 1;
    }
    
    memcpy(output, prefix, prefix_len);
    memcpy(output + prefix_len, input, input_len);
    output[prefix_len + input_len] = 0;
    
    return prefix_len + input_len;
}

// =============================================================================
// Entry Point
// =============================================================================
int main() {
    // Initialize detokenizer with stub vocab
    // In production, load from GGUF
    const char* vocab_data = "test vocab";
    uint64_t vocab_lengths[] = {4, 5};
    uint64_t special_ids[] = {0, 1, 2};  // bos, eos, unk
    
    SovereignDetokenizer_Init(vocab_data, 2, vocab_lengths, special_ids);
    
    // Run chat loop
    ChatLoop_Run(StubInference, nullptr);
    
    // Cleanup
    SovereignDetokenizer_Cleanup();
    
    return 0;
}