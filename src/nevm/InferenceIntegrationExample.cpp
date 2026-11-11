//=============================================================================
// InferenceIntegrationExample.cpp - Complete wiring demonstration
// Shows how AgenticSupervisor + InferenceTask + GhostTextOverlay work together
//=============================================================================

#include "AgenticSupervisor.hpp"
#include "InferenceTask.hpp"
#include "../ui/GhostTextOverlay.hpp"
#include "Deep2Engine.hpp"
#include <windows.h>
#include <stdio>

using namespace RawrXD;

//=============================================================================
// Example: IDE Completion with Streaming Ghost Text
//=============================================================================
class IDECompletionController {
public:
    IDECompletionController(Deep2Engine* engine, UI::GhostTextOverlay* overlay)
        : engine_(engine)
        , overlay_(overlay)
    {
        // Set up overlay callbacks
        overlay->SetAcceptCallback([this](const std::string& text) {
            printf("[IDE] Accepted completion: %s\n", text.c_str());
            // Insert text into editor at cursor position
            InsertTextIntoEditor(text);
        });
        
        overlay->SetDismissCallback([this]() {
            printf("[IDE] Dismissed completion\n");
        });
    }
    
    void TriggerCompletion(const std::string& prefix, int line, int column) {
        // Don't trigger if already generating
        if (Agentic::g_is_generating.load()) {
            printf("[IDE] Already generating, ignoring trigger\n");
            return;
        }
        
        // Build the inference request
        Agentic::InferenceRequest req;
        req.prompt = BuildPrompt(prefix);
        req.maxTokens = 64;
        req.temperature = 0.4f;
        
        // Streaming callback - fires per token
        req.onToken = [this, line, column](const std::string& token) {
            // This runs on the worker thread - marshal to UI thread
            PostUIUpdate([this, token, line, column]() {
                if (!overlay_>IsVisible()) {
                    overlay_>ShowAt(line, column, token);
                } else {
                    overlay_>AppendText(token);
                }
            });
        };
        
        // Completion callback
        req.onComplete = [this](const std::string& fullText) {
            printf("[IDE] Generation complete: %zu tokens\n", fullText.size());
        };
        
        // Create the task and submit to Supervisor
        auto task = Agentic::InferenceTaskFactory::Create(req, engine_);
        std::string taskId = Agentic::AgenticSupervisor::Instance().SubmitTask(std::move(task));
        
        printf("[IDE] Submitted completion task: %s\n", taskId.c_str());
    }
    
    void CancelCurrentCompletion() {
        if (Agentic::g_is_generating.load()) {
            printf("[IDE] Sending interrupt signal\n");
            Agentic::g_interrupt_flag.store(true);
            overlay_>Dismiss();
        }
    }
    
    bool IsGenerating() const {
        return Agentic::g_is_generating.load();
    }
    
    std::string GetHealthStatus() const {
        return Agentic::AgenticSupervisor::Instance().GetHealthReport();
    }

private:
    std::string BuildPrompt(const std::string& prefix) {
        // Add context/prefix to guide the model
        return "// Complete the following code:\n" + prefix;
    }
    
    void InsertTextIntoEditor(const std::string& text) {
        // Actual editor insertion would go here
        // For now, just log
        printf("[IDE] Inserting %zu chars into editor\n", text.size());
    }
    
    void PostUIUpdate(std::function<void()> update) {
        // In real implementation, use PostMessage to marshal to UI thread
        // For now, call directly (not thread-safe but works for demo)
        update();
    }
    
    Deep2Engine* engine_;
    UI::GhostTextOverlay* overlay_;
};

//=============================================================================
// Example: Main Application Setup
//=============================================================================
void SetupInferenceSystem() {
    printf("========================================\n");
    printf("  RawrXD Inference System Setup        \n");
    printf("========================================\n\n");
    
    // 1. Initialize the AgenticSupervisor (Level 4 orchestration)
    Agentic::AgenticSupervisor::Config supConfig;
    supConfig.maxConcurrentTasks = 2;  // Limit concurrent inference
    supConfig.enableSelfHealing = true;
    supConfig.targetSuccessRate = 0.95;
    
    bool ok = Agentic::AgenticSupervisor::Instance().Initialize(supConfig);
    printf("[Setup] AgenticSupervisor initialized: %s\n", ok ? "OK" : "FAILED");
    
    // 2. Initialize Deep2Engine (the inference engine)
    Deep2Engine* engine = new Deep2Engine();
    // ... configure and load model ...
    printf("[Setup] Deep2Engine ready\n");
    
    // 3. Initialize GhostTextOverlay (the UI)
    UI::GhostTextOverlay* overlay = new UI::GhostTextOverlay();
    // overlay->Initialize(hwndParent);  // Requires actual HWND
    printf("[Setup] GhostTextOverlay ready\n");
    
    // 4. Create the completion controller
    IDECompletionController controller(engine, overlay);
    
    printf("\n[Setup] System ready for inference\n");
    printf("[Setup] Health:\n%s\n", controller.GetHealthStatus().c_str());
    
    // Example usage:
    // controller.TriggerCompletion("void ProcessData(", 10, 17);
}

//=============================================================================
// Example: Direct Task Submission (without GhostTextOverlay)
//=============================================================================
void SubmitDirectInference(Deep2Engine* engine, const std::string& prompt) {
    Agentic::InferenceRequest req;
    req.prompt = prompt;
    req.maxTokens = 128;
    req.temperature = 0.7f;
    
    // Collect all tokens at end (no streaming)
    std::string fullResult;
    req.onToken = [&fullResult](const std::string& token) {
        fullResult += token;
    };
    
    req.onComplete = [](const std::string& text) {
        printf("[Direct] Inference complete: %zu chars\n", text.size());
    };
    
    auto task = Agentic::InferenceTaskFactory::Create(req, engine);
    std::string taskId = Agentic::AgenticSupervisor::Instance().SubmitTask(std::move(task));
    
    printf("[Direct] Submitted task: %s\n", taskId.c_str());
    
    // Wait for completion (blocking)
    while (true) {
        auto status = Agentic::AgenticSupervisor::Instance().GetTaskStatus(taskId);
        if (status.status == Agentic::TaskStatus::COMPLETED) {
            printf("[Direct] Task completed successfully\n");
            break;
        }
        if (status.status == Agentic::TaskStatus::FAILED) {
            printf("[Direct] Task failed\n");
            break;
        }
        Sleep(10);
    }
}

//=============================================================================
// Example: Batch Inference with Checkpointing
//=============================================================================
void SubmitBatchInference(Deep2Engine* engine, const std::vector<std::string>& prompts) {
    printf("[Batch] Submitting %zu prompts...\n", prompts.size());
    
    std::vector<std::string> taskIds;
    
    for (const auto& prompt : prompts) {
        Agentic::InferenceRequest req;
        req.prompt = prompt;
        req.maxTokens = 64;
        req.temperature = 0.5f;
        
        auto task = Agentic::InferenceTaskFactory::Create(req, engine);
        taskIds.push_back(Agentic::AgenticSupervisor::Instance().SubmitTask(std::move(task)));
    }
    
    // Wait for all to complete
    size_t completed = 0;
    while (completed < taskIds.size()) {
        completed = 0;
        for (const auto& id : taskIds) {
            auto status = Agentic::AgenticSupervisor::Instance().GetTaskStatus(id);
            if (status.status == Agentic::TaskStatus::COMPLETED ||
                status.status == Agentic::TaskStatus::FAILED) {
                completed++;
            }
        }
        Sleep(100);
    }
    
    printf("[Batch] All %zu tasks completed\n", completed);
}

//=============================================================================
// Main Entry Point (for standalone testing)
//=============================================================================
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    SetupInferenceSystem();
    
    printf("\n========================================\n");
    printf("  Integration Examples Complete        \n");
    printf("========================================\n");
    
    return 0;
}
