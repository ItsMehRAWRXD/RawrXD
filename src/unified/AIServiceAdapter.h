#pragma once

//==============================================================================
// AIServiceAdapter.h - Bridge between AIProvider and IAIService
// Phase 15: Complete System Unification
//
// This adapter connects the new AIProvider interface (src/core/AIProvider.h)
// to the existing IAIService interface in RawrXDHost.h
//==============================================================================

#include "RawrXDHost.h"
#include "../core/AIProvider.h"
#include "../deep2/Deep2Provider.h"
#include <memory>

namespace RawrXD {
namespace Unified {

//==============================================================================
// AI Service Adapter
// Implements IAIService using AIProvider backend
//==============================================================================
class AIServiceAdapter : public IAIService {
public:
    AIServiceAdapter();
    ~AIServiceAdapter() override;

    // Initialize with model path
    bool Initialize(const std::string& modelPath) override;
    void Shutdown() override;

    // Completion API
    CompletionResponse Complete(const CompletionRequest& req) override;
    void CompleteStreaming(const CompletionRequest& req, TokenCallback callback) override;

    // Chat API
    std::string Chat(const ChatRequest& req) override;

    // Status
    bool IsModelLoaded() const override;
    std::string GetModelName() const override;

    // Access to underlying provider
    AIProvider* GetProvider() const { return provider_.get(); }

private:
    // Convert IAIService request to AIProvider request
    AIRequest ConvertCompletionRequest(const CompletionRequest& req);
    AIRequest ConvertChatRequest(const ChatRequest& req);
    
    // Convert AIProvider response to IAIService response
    CompletionResponse ConvertCompletionResponse(const AIResponse& resp);

    std::unique_ptr<AIProvider> provider_;
    bool initialized_ = false;
    std::string modelPath_;
};

} // namespace Unified
} // namespace RawrXD
