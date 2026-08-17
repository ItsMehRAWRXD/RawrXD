#include "AIServiceAdapter.h"
#include <iostream>
#include <sstream>

namespace RawrXD {
namespace Unified {

AIServiceAdapter::AIServiceAdapter() = default;

AIServiceAdapter::~AIServiceAdapter() {
    Shutdown();
}

bool AIServiceAdapter::Initialize(const std::string& modelPath) {
    modelPath_ = modelPath;
    
    // Create Deep2Provider as the backend
    provider_ = std::make_unique<Deep2Provider>();
    
    if (!provider_->Initialize(modelPath)) {
        std::cerr << "AIServiceAdapter: Failed to initialize Deep2Provider with model: " << modelPath << std::endl;
        provider_.reset();
        return false;
    }
    
    initialized_ = true;
    std::cout << "AIServiceAdapter: Initialized with model: " << modelPath << std::endl;
    return true;
}

void AIServiceAdapter::Shutdown() {
    if (provider_) {
        provider_->Shutdown();
        provider_.reset();
    }
    initialized_ = false;
}

bool AIServiceAdapter::IsModelLoaded() const {
    return initialized_ && provider_ && provider_->IsReady();
}

std::string AIServiceAdapter::GetModelName() const {
    if (provider_ && initialized_) {
        return provider_->GetModelName();
    }
    return "";
}

AIRequest AIServiceAdapter::ConvertCompletionRequest(const IAIService::CompletionRequest& req) {
    AIRequest aiReq;
    aiReq.type = AIRequestType::Completion;
    aiReq.prompt = req.prefix;
    aiReq.context = req.suffix;
    aiReq.language = req.language;
    aiReq.maxTokens = req.maxTokens;
    aiReq.temperature = req.temperature;
    aiReq.topP = 0.9f;
    return aiReq;
}

AIRequest AIServiceAdapter::ConvertChatRequest(const IAIService::ChatRequest& req) {
    AIRequest aiReq;
    aiReq.type = AIRequestType::Chat;
    
    // Convert chat messages to a single prompt
    std::ostringstream oss;
    for (const auto& msg : req.messages) {
        if (msg.role == "system") {
            oss << "<|system|>\n" << msg.content << "\n";
        } else if (msg.role == "user") {
            oss << "<|user|>\n" << msg.content << "\n";
        } else if (msg.role == "assistant") {
            oss << "<|assistant|>\n" << msg.content << "\n";
        }
    }
    oss << "<|assistant|>\n";
    
    aiReq.prompt = oss.str();
    aiReq.maxTokens = req.maxTokens;
    aiReq.temperature = req.temperature;
    aiReq.topP = 0.9f;
    return aiReq;
}

IAIService::CompletionResponse AIServiceAdapter::ConvertCompletionResponse(const AIResponse& resp) {
    IAIService::CompletionResponse compResp;
    compResp.text = resp.text;
    compResp.finished = resp.success;
    compResp.confidence = resp.success ? 1.0f : 0.0f;
    return compResp;
}

IAIService::CompletionResponse AIServiceAdapter::Complete(const IAIService::CompletionRequest& req) {
    if (!initialized_ || !provider_) {
        IAIService::CompletionResponse empty;
        empty.finished = true;
        return empty;
    }
    
    AIRequest aiReq = ConvertCompletionRequest(req);
    AIResponse aiResp = provider_->Execute(aiReq);
    
    return ConvertCompletionResponse(aiResp);
}

void AIServiceAdapter::CompleteStreaming(const IAIService::CompletionRequest& req, IAIService::TokenCallback callback) {
    if (!initialized_ || !provider_) {
        return;
    }
    
    AIRequest aiReq = ConvertCompletionRequest(req);
    
    provider_->ExecuteStream(aiReq, [callback](const std::string& token) {
        callback(token, false); // token, not finished
    });
    
    // Signal completion
    callback("", true);
}

std::string AIServiceAdapter::Chat(const IAIService::ChatRequest& req) {
    if (!initialized_ || !provider_) {
        return "";
    }
    
    AIRequest aiReq = ConvertChatRequest(req);
    AIResponse aiResp = provider_->Execute(aiReq);
    
    return aiResp.text;
}

} // namespace Unified
} // namespace RawrXD
