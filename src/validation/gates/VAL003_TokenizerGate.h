// ============================================================================
// VAL-003: Tokenizer Validation Gate
// ============================================================================
// Validates tokenizer functionality:
// - BPE tokenization
// - SentencePiece/Unigram tokenization
// - Special token handling
// - Encoding/decoding round-trip
// - Vocabulary lookup
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL003_TokenizerGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-003"; }
    std::string GetName() const override { return "Tokenizer"; }
    std::string GetDescription() const override {
        return "Validates BPE/SentencePiece tokenization, special token handling, "
               "encoding/decoding round-trip, and vocabulary operations";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
    
private:
    bool ValidateBPETokenization();
    bool ValidateSentencePiece();
    bool ValidateSpecialTokens();
    bool ValidateRoundTrip();
    bool ValidateVocabularyLookup();
};

} // namespace Validation
} // namespace RawrXD
