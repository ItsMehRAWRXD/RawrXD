// ============================================================================
// Blocker #22: EOS Short-Circuit Hook
// Unstubs the EOS (End of Sequence) detection in Deep2Engine::generate
// to properly terminate generation when EOS token is sampled.
// ============================================================================
#pragma once
#include <cstdint>
#include <functional>
#include <atomic>

namespace Deep2 {

// EOS detection strategy
enum class EOSMode {
    STANDARD,       // Standard EOS token detection
    EARLY_STOP,     // Stop at EOS + ignore padding
    FORCE_LENGTH,   // Generate exact maxOutputLen tokens
    CUSTOM_HOOK     // User-provided callback decides
};

class EOSShortCircuit {
public:
    EOSShortCircuit() : eosTokenId_(2), mode_(EOSMode::STANDARD), enabled_(true) {}

    void SetEOSToken(int tokenId) { eosTokenId_ = tokenId; }
    void SetMode(EOSMode mode) { mode_ = mode; }
    void SetEnabled(bool enabled) { enabled_ = enabled; }
    void SetCustomHook(std::function<bool(int)> hook) { customHook_ = hook; }

    // Check if generation should stop
    bool ShouldStop(int tokenId, size_t currentLen, size_t maxLen) const {
        if (!enabled_) return false;
        if (currentLen >= maxLen) return true;
        
        switch (mode_) {
            case EOSMode::STANDARD:
            case EOSMode::EARLY_STOP:
                return tokenId == eosTokenId_;
            case EOSMode::FORCE_LENGTH:
                return currentLen >= maxLen;
            case EOSMode::CUSTOM_HOOK:
                if (customHook_) return customHook_(tokenId);
                return tokenId == eosTokenId_;
        }
        return false;
    }

    // Get the EOS token ID
    int GetEOSToken() const { return eosTokenId_; }

    // Check if a token is the EOS token
    bool IsEOS(int tokenId) const {
        return tokenId == eosTokenId_;
    }

private:
    int eosTokenId_;
    EOSMode mode_;
    std::atomic<bool> enabled_;
    std::function<bool(int)> customHook_;
};

} // namespace Deep2
