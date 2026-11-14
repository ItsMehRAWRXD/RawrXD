// Win32IDE_Issue49CliWire.cpp — Issue #49 landable AgenticLoopBridge useCliAgent
// Private-cand wire only. PROMOTE=0 TIP_CLIMB=HOLD. tip 6754616E untouched.
#include "Win32IDE.h"
#include "Win32IDE_AgenticLoopBridge.h"
#include "IDELogger.h"
#include <cstdlib>
#include <string>

void Win32IDE::initializeAgenticLoopBridge()
{
    if (m_agenticLoopBridge)
        return;
    m_agenticLoopBridge = std::make_unique<AgenticLoopBridge>(this);
    LOG_INFO("AgenticLoopBridge initialized (Issue#49 useCliAgent lane)");
}

bool Win32IDE::launchCliAgentIssue49Task(const std::string& taskIn)
{
    initializeAgenticLoopBridge();
    if (!m_agenticLoopBridge) {
        MessageBoxA(m_hwndMain, "AgenticLoopBridge unavailable", "Agent Error",
                    MB_OK | MB_ICONERROR);
        return false;
    }
    if (m_agenticLoopBridge->IsRunning()) {
        appendToOutput("AgenticLoopBridge already running\n", "Output",
                       OutputSeverity::Warning);
        return false;
    }
    std::string task = taskIn;
    if (task.empty()) {
        if (const char* envTask = std::getenv("RAWRXD_AGENT_TASK"))
            task = envTask;
    }
    if (task.empty())
        task = "Read note.txt and bug.cpp; patch bug.cpp to print AGENT_RESULT=5; build and run.";
    AgenticLoopBridge::TaskConfig cfg;
    cfg.useCliAgent = true;
    cfg.approveMutations = true;
    cfg.readOnly = false;
    cfg.provider = "local";
    if (const char* m = std::getenv("RAWRXD_MODEL"))
        cfg.modelPath = m;
    else
        cfg.modelPath = "tinyllama.gguf";
    if (!m_projectRoot.empty())
        cfg.workDir = m_projectRoot;
    else if (!m_explorerRootPath.empty())
        cfg.workDir = m_explorerRootPath;
    else if (!m_currentDirectory.empty())
        cfg.workDir = m_currentDirectory;
    else
        cfg.workDir = ".";
    cfg.task = task;
    cfg.targetFile = "bug.cpp";
    cfg.maxSteps = 8;
    cfg.maxWallTimeSec = 180;
    appendToOutput("Issue#49 useCliAgent StartTask: " + task.substr(0, 160) + "\n",
                   "Output", OutputSeverity::Info);
    return m_agenticLoopBridge->StartTask(
        cfg,
        [this](const std::string& msg) {
            appendToOutput("[AgenticLoop] " + msg + "\n", "Output", OutputSeverity::Info);
        },
        [this](const AgenticLoopBridge::ToolResult& tr) {
            appendToOutput(std::string("[Tool] ") + tr.toolName + " ok=" +
                               (tr.success ? "1" : "0") + "\n",
                           "Output", OutputSeverity::Info);
        },
        [this](bool ok, const std::string& summary) {
            appendToOutput(std::string("[AgenticLoop] complete ok=") +
                               (ok ? "1" : "0") + "\n" + summary.substr(0, 1500) + "\n",
                           "Output", ok ? OutputSeverity::Info : OutputSeverity::Error);
        });
}

void Win32IDE::onAgenticLoopRunTask()
{
    char buf[2048] = {0};
    if (m_hwndCopilotChatInput)
        GetWindowTextA(m_hwndCopilotChatInput, buf, sizeof(buf));
    launchCliAgentIssue49Task(buf);
}

void Win32IDE::onAgenticLoopCancel()
{
    if (m_agenticLoopBridge)
        m_agenticLoopBridge->Cancel();
}

void Win32IDE::onAgenticLoopStatus()
{
    const std::string st =
        m_agenticLoopBridge ? m_agenticLoopBridge->GetStatus() : "bridge=ABSENT";
    appendToOutput("AgenticLoop status: " + st + "\n", "Output", OutputSeverity::Info);
}

LRESULT Win32IDE::handleAgenticLoopProgress(WPARAM, LPARAM lParam)
{
    auto* msg = reinterpret_cast<std::string*>(lParam);
    if (msg) {
        appendToOutput("[AgenticLoop] " + *msg + "\n", "Output", OutputSeverity::Info);
        delete msg;
    }
    return 0;
}

LRESULT Win32IDE::handleAgenticLoopToolResult(WPARAM, LPARAM lParam)
{
    auto* tr = reinterpret_cast<AgenticLoopBridge::ToolResult*>(lParam);
    if (tr) {
        appendToOutput(std::string("[Tool] ") + tr->toolName + "\n", "Output",
                       OutputSeverity::Info);
        delete tr;
    }
    return 0;
}

LRESULT Win32IDE::handleAgenticLoopComplete(WPARAM wParam, LPARAM lParam)
{
    auto* summary = reinterpret_cast<std::string*>(lParam);
    appendToOutput(std::string("[AgenticLoop] done ok=") +
                       (wParam ? "1" : "0") + "\n" +
                       (summary ? summary->substr(0, 1500) : "") + "\n",
                   "Output", wParam ? OutputSeverity::Info : OutputSeverity::Error);
    delete summary;
    return 0;
}
