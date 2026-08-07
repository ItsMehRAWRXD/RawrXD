#include "InferenceTask.hpp"
#include <atomic>

namespace RawrXD {
namespace Agentic {

AgenticTask InferenceTaskFactory::Create(const InferenceRequest& req, Deep2Engine* engine) {
    AgenticTask task;
    task.name = "Inference_" + req.prompt.substr(0, 20);
    task.priority = TaskPriority::HIGH;
    task.requiresCheckpoint = true;
    task.estimatedMemoryMB = 4096;
    
    auto prompt = req.prompt;
    auto maxTokens = req.maxTokens;
    auto temp = req.temperature;
    auto onToken = req.onToken;
    auto onComplete = req.onComplete;
    
    task.execute = [engine, prompt, maxTokens, temp, onToken, onComplete]() -> bool {
        if (!engine || !engine->IsModelLoaded()) {
            return false;
        }
        
        g_is_generating.store(true, std::memory_order_release);
        
        std::string accumulated;
        accumulated.reserve(prompt.size() + maxTokens * 6);
        accumulated = prompt;
        
        for (size_t i = 0; i < maxTokens; ++i) {
            if (g_interrupt_flag.load(std::memory_order_acquire)) {
                g_interrupt_flag.store(false, std::memory_order_release);
                break;
            }
            
            int nextToken = engine->GenerateNextToken(accumulated, temp);
            if (nextToken < 0 || nextToken == engine->GetEosToken()) {
                break;
            }
            
            std::string piece = engine->Detokenize(nextToken);
            accumulated += piece;
            
            if (onToken) {
                onToken(piece);
            }
        }
        
        g_is_generating.store(false, std::memory_order_release);
        
        if (onComplete) {
            onComplete(accumulated);
        }
        return true;
    };
    
    return task;
}

} // namespace Agentic
} // namespace RawrXD
