#pragma once

#include "runtime/CoreTypes.hpp"
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD {

// GenerationConfig now in CoreTypes.hpp — using canonical definition

class INativeInferenceBackend {
public:
    virtual ~INativeInferenceBackend() = default;
    virtual bool SubmitInference(const std::vector<int>& prompt_tokens, const GenerationConfig& config) = 0;
    virtual bool GetResult(std::string& out_text, bool& out_done) = 0;
    virtual bool IsAvailable() const = 0;
    virtual void Cancel() = 0;
};

class BackendRegistry {
public:
    static void SetBackend(std::unique_ptr<INativeInferenceBackend> backend);
    static INativeInferenceBackend* GetBackend();

private:
    static std::unique_ptr<INativeInferenceBackend> backend_;
    static std::mutex mutex_;
};

// Idempotent registration hook for chat backend availability.
bool InitializeAgenticChatBackend();

}  // namespace RawrXD
