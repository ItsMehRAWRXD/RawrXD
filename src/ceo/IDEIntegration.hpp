// ============================================================================
// IDEIntegration.hpp — Bridge between CEO Agent and RawrXD IDE
// ============================================================================
#pragma once

#include "CEOAgent.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <functional>
#include <memory>

namespace RawrXD {
namespace CEO {

// Forward declaration
class CEOAgent;

// ============================================================================
// IDE Integration
// Connects CEO Agent to the IDE UI
// ============================================================================
class IDEIntegration {
public:
    IDEIntegration();
    ~IDEIntegration();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // CEO Agent access
    void SetCEOAgent(std::shared_ptr<CEOAgent> agent);
    std::shared_ptr<CEOAgent> GetCEOAgent() const;
    
    // IDE Commands
    void StartAutonomousSession(const std::string& goal);
    void ContinueSession();
    void PauseSession();
    void CancelSession();
    
    // UI Updates
    void UpdateProgressBar(float percent, const std::string& message);
    void UpdateTaskList(const std::vector<Task>& tasks);
    void ShowCompletionPanel(const std::string& content);
    void ShowDiffView(const std::string& original, const std::string& modified);
    void ShowAgentChat(const std::string& message);
    
    // Notifications
    void NotifyTaskComplete(const Task& task);
    void NotifyGoalComplete(const Goal& goal, bool success);
    void NotifyError(const std::string& error);
    
    // Callbacks for IDE events
    using FileOpenCallback = std::function<void(const std::string& path)>;
    using FileEditCallback = std::function<void(const std::string& path, const std::string& content)>;
    using BuildRequestCallback = std::function<void()>;
    using TestRequestCallback = std::function<void()>;
    
    void SetFileOpenCallback(FileOpenCallback cb) { m_fileOpenCb = cb; }
    void SetFileEditCallback(FileEditCallback cb) { m_fileEditCb = cb; }
    void SetBuildRequestCallback(BuildRequestCallback cb) { m_buildCb = cb; }
    void SetTestRequestCallback(TestRequestCallback cb) { m_testCb = cb; }
    
    // Export current state for IDE
    json GetStateForIDE() const;
    
private:
    void OnCEOProgress(const std::string& stage, const std::string& message, float percent);
    void OnCEOTask(const Task& task);
    void OnCEOComplete(const Goal& goal, bool success);
    
private:
    std::shared_ptr<CEOAgent> m_agent;
    
    FileOpenCallback m_fileOpenCb;
    FileEditCallback m_fileEditCb;
    BuildRequestCallback m_buildCb;
    TestRequestCallback m_testCb;
    
    bool m_initialized = false;
};

} // namespace CEO
} // namespace RawrXD
