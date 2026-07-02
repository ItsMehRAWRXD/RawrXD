// =============================================================================
// sovereign_detokenizer.h
// Token ID to text conversion using GGUF vocabulary
// =============================================================================

#ifndef SOVEREIGN_DETOKENIZER_H
#define SOVEREIGN_DETOKENIZER_H

#include <cstdint>
#include <string>
#include <vector>
#include <string>

namespace Sovereign {

// =============================================================================
// Simple Detokenizer
// Converts token IDs to human-readable text
// =============================================================================
class Detokenizer {
public:
    Detokenizer();
    ~Detokenizer();
    
    // Initialize with vocabulary from GGUF loader
    bool Initialize(const std::vector<std::string>& vocab);
    
    // Detokenize a single token ID
    std::string Detokenize(uint32_t token_id) const;
    
    // Detokenize a sequence of token IDs
    std::string DetokenizeSequence(const std::vector<uint32_t>& tokens) const;
    
    // Check if initialized
    bool IsInitialized() const { return !vocab_.empty(); }
    
    // Get vocab size
    size_t GetVocabSize() const { return vocab_.size(); }
    
private:
    std::vector<std::string> vocab_;
    
    // Clean up BPE artifacts (e.g., "Ġ" -> " ")
    std::string CleanToken(const std::string& token) const;
};

} // namespace Sovereign

#endif // SOVEREIGN_DETOKENIZER_H