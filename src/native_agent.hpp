#pragma once
#include "cpu_inference_engine.h"
#include "advanced_agent_features.hpp"
#include "IDELogger.h"
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <regex>
#include <thread>
#include <chrono>
#include <atomic>

namespace RawrXD {

class NativeAgent {
public:
    using OutputCallback = std::function<void(const std::string&)>;

    NativeAgent(RawrXD::CPUInferenceEngine* engine) : m_engine(engine), m_nextRequestId(1) {}

    void SetOutputCallback(OutputCallback cb) { m_callback = cb; }
    void SetDeepThink(bool enabled) { m_deepThink = enabled; }
    void SetDeepResearch(bool enabled) { m_deepResearch = enabled; }
    void SetNoRefusal(bool enabled) { m_noRefusal = enabled; }
    void SetMaxMode(bool enabled) { m_maxMode = enabled; if(m_engine) m_engine->SetThreadCount(enabled ? std::thread::hardware_concurrency() : 4); }

    // Generate a new request ID and mark it as the current active request
    uint64_t StartRequest() {
        uint64_t id = m_nextRequestId.fetch_add(1, std::memory_order_relaxed);
        m_activeRequest.store(id, std::memory_order_release);
        m_cancelRequested.store(false, std::memory_order_release);
        LOG_INFO("NativeAgent: started request id=" + std::to_string(id));
        return id;
    }

    // Request cancellation - returns true if cancellation was already pending
    bool CancelRequest() {
        bool was_cancelled = m_cancelRequested.exchange(true, std::memory_order_acq_rel);
        LOG_INFO("NativeAgent: cancel_requested id=" + std::to_string(m_activeRequest.load(std::memory_order_acquire)) 
                 + " was_cancelled=" + std::to_string(was_cancelled));
        return was_cancelled;
    }

    // Check if cancellation has been acknowledged/completed (no more output will come)
    bool IsCancelled() const {
        return m_cancelRequested.load(std::memory_order_acquire) && 
               m_activeRequest.load(std::memory_order_acquire) == 0;
    }

    // Reset cancellation state for a new request
    void ResetCancellation() {
        m_cancelRequested.store(false, std::memory_order_release);
        // Do NOT reset m_activeRequest here - the new request will set its own ID
    }

    // Get the currently active request ID (0 if none)
    uint64_t GetActiveRequestId() const {
        return m_activeRequest.load(std::memory_order_acquire);
    }

    // Cancel any active generation
    void Cancel() {
        m_cancelRequested.store(true, std::memory_order_release);
        LOG_INFO("NativeAgent: cancel requested");
    }

    bool Ask(const std::string& query) {
        if (!m_engine || !m_engine->IsModelLoaded()) {
            Print("[Agent] No model loaded. Use /load <path> first.\n");
            return false;
        }

        uint64_t requestId = StartRequest();
        LOG_INFO("NativeAgent: Ask requestId=" + std::to_string(requestId));

        std::string fullPrompt = BuildPrompt(query);
        Print("[Agent] Generating response...\n");

        // Streaming generation with cancellation-aware callback
        std::vector<int32_t> input_ids = m_engine->Tokenize(fullPrompt);
        
        int tokensGenerated = 0;
        bool inThought = false;

        m_engine->GenerateStreaming(input_ids, 2048, 
            [&](const std::string& token) {
                // Check if this token belongs to a newer request - if so, reject it
                if (m_activeRequest.load(std::memory_order_acquire) != requestId) {
                    LOG_INFO("NativeAgent: stale token rejected for request id=" + std::to_string(requestId) 
                             + " current active id=" + std::to_string(m_activeRequest.load(std::memory_order_acquire)));
                    return; // Stale token from canceled/older request
                }
                
                // Handling <thought> visibility
                if (token.find("<thought>") != std::string::npos) inThought = true;
                
                if (inThought) {
                    Print(token); // GUI might handle color, or we strip codes
                } else {
                    Print(token);
                }
                
                if (token.find("</thought>") != std::string::npos) {
                    inThought = false;
                    Print("\n");
                }
                tokensGenerated++;
            },
            [&]() {
                // Check if we were cancelled before completion, and ensure this
                // completion belongs to the current active request (not a newer one).
                uint64_t currentActiveId = m_activeRequest.load(std::memory_order_acquire);
                bool is_cancelled = m_cancelRequested.load(std::memory_order_acquire);
                bool is_stale = (currentActiveId != requestId && currentActiveId > 0);
                
                if (is_stale) {
                    LOG_INFO("NativeAgent: completion callback stale for request id=" + std::to_string(requestId) 
                             + " current active id=" + std::to_string(currentActiveId));
                    // Don't print anything - the new request will produce its own output
                } else if (is_cancelled) {
                    LOG_INFO("NativeAgent: generation completed with cancellation for request id=" + std::to_string(requestId));
                    Print("\n[Cancelled]\n");
                } else {
                    Print("\n[Done]\n");
                }
            }
        );
        return true;
    }

    void CreateReactServerPlan() {
         Ask("Generate a comprehensive plan to create a React Server Component architecture from scratch in C++. detailed file list and logic.");
    }

    void Edit(const std::string& filePath, const std::string& instructions) {
        std::string content = ReadFile(filePath);
        if (content.empty()) return;
        std::string prompt = "Original Code:\n" + content + "\n\nInstructions: " + instructions + "\n\nProvide the complete edited code with changes applied.";
        Ask(prompt);
    }

    void BugReport(const std::string& filePath) {
        std::string content = ReadFile(filePath);
        if (content.empty()) return;
        std::string prompt = "Analyze the following code for bugs, security vulnerabilities, and logic errors.\n\nCode:\n" + content;
        Ask(prompt);
    }
    
    void Suggest(const std::string& filePath) {
        std::string content = ReadFile(filePath);
        if (content.empty()) return;
        std::string prompt = "Provide suggestions to improve the following code (performance, readability, style).\n\nCode:\n" + content;
        Ask(prompt);
    }
    
    void Plan(const std::string& task) {
        std::string prompt = "Create a detailed execution plan for the following task:\n" + task;
        Ask(prompt);
    }


    void HotPatch(const std::string& filePath) {
        std::string content = ReadFile(filePath);
        if (content.empty()) return;
        // Simulating the "AgentHotPatcher" behavior natively
        std::string prompt = "Review the following code for hallucinations, invalid paths, and logical contradictions. Rewrite the code to fix these issues immediately.\n\nCode:\n" + content;
        Ask(prompt);
    }

    // Clear pending state - only affects the currently active request
    void ClearPendingState() {
        uint64_t currentId = m_activeRequest.load(std::memory_order_acquire);
        if (currentId > 0) {
            LOG_INFO("NativeAgent: clearing pending state for request id=" + std::to_string(currentId));
            // Reset cancellation for this request id
            m_cancelRequested.store(false, std::memory_order_release);
            // Mark as no longer active (will be replaced by new request)
            m_activeRequest.store(0, std::memory_order_release);
        }
    }

private:
    RawrXD::CPUInferenceEngine* m_engine;
    OutputCallback m_callback;
    bool m_deepThink = false;
    bool m_deepResearch = false;
    bool m_noRefusal = false;
    bool m_maxMode = false;
    
    // Request ID tracking - monotonically increasing
    std::atomic<uint64_t> m_nextRequestId;
    
    // Currently active request ID (0 if no active request)
    std::atomic<uint64_t> m_activeRequest;
    
    // Cancellation state for the current request
    std::atomic<bool> m_cancelRequested;

    void Print(const std::string& s) {
        if (m_callback) m_callback(s);
        else std::cout << s; // Fallback for CLI
    }

    std::string ReadFile(const std::string& path) {
        std::ifstream f(path);
        if (!f) {
            Print("[Error] Could not read file: " + path + "\n");
            return "";
        }
        std::stringstream buffer;
        buffer << f.rdbuf();
        return buffer.str();
    }

    std::string BuildPrompt(const std::string& userQuery) {
        // If Deep Research is on, let AdvancedFeatures handle the full construction including context
        if (m_deepResearch) {
             return ::AdvancedFeatures::DeepResearch(userQuery);
        }

        std::string modifiedQuery = userQuery;
        
        if (m_noRefusal) {
             modifiedQuery = ::AdvancedFeatures::NoRefusal(modifiedQuery);
        }
        
        if (m_deepThink) {
             modifiedQuery = ::AdvancedFeatures::ChainOfThought(modifiedQuery);
        }
        
        // Fallback to standard templating if not using the Research override which returns a full blob
        std::string sys = "You are RawrXD, an expert AI programming assistant.";
        
        std::string prompt = "<|system|>\n" + sys + "\n";
        prompt += "<|user|>\n" + modifiedQuery + "\n"; // Inject the modified query (CoT / NoRefusal)
        prompt += "<|assistant|>\n";
        
        if (m_deepThink) prompt += "Here is my thought process:\n";
        
        return prompt;
    }

    std::string PerformResearch(const std::string& query) { return ""; }
};

}
