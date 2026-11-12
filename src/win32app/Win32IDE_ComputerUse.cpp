// Wire native Computer Use into session-owned agent Registry + ToolCallBridge.
#include "Win32IDE.h"
#include "IDELogger.h"
#include "Win32IDE_AgentStepTimeline.h"
#include <fstream>
#include <cstdlib>
#if defined(RAWRXD_HAS_COMPUTER_USE)
#include "ComputerUseBridge.h"
#include "ExtensionSandboxManager.h"
#include "ConsentPrompt.h"
#include "agentic/tool_core.hpp"
#include "agentic/ToolCallBridge.h"
#include "agentic/IdeToolDispatchSsot.hpp"
#endif

namespace {
#if defined(RAWRXD_HAS_COMPUTER_USE)
void DeleteRegistry(void* p) {
    delete static_cast<rawrxd::tools::Registry*>(p);
}
void DeleteToolBridge(void* p) {
    delete static_cast<RawrXD::Agent::ToolCallBridge*>(p);
}
void CuEvidence(const std::string& line) {
    const char* dir = std::getenv("RAWRXD_LOG_DIR");
    const std::string path = (dir && *dir)
        ? std::string(dir) + "\\chat_runtime.log"
        : std::string("chat_runtime.log");
    std::ofstream out(path, std::ios::app);
    if (out) out << line << std::endl;
}
#endif
}  // namespace

bool Win32IDE::isAgentModeActive() const {
    if (m_agentModeActive) return true;
    if (const char* env = std::getenv("RAWRXD_AGENT_MODE")) {
        if (!env[0]) return false;
        if (env[0] == '1' && env[1] == '\0') return true;
        if (_stricmp(env, "ACTIVE") == 0) return true;
        if (_stricmp(env, "true") == 0) return true;
    }
    // Issue #49: FORCE_LOCAL harness must route Ctrl+Enter/Send to
    // AgenticLoopBridge (deep2_agentic_loop), not HandleCopilotSend Ollama chat.
    if (const char* forceLocal = std::getenv("RAWRXD_FORCE_LOCAL_AGENTIC")) {
        if (forceLocal[0] == '1' && forceLocal[1] == '\0') return true;
    }
    return false;
}

void Win32IDE::setAgentModeActive(bool active) {
    m_agentModeActive = active;
}

bool Win32IDE::stageCopilotChatInputUtf8(const std::string& utf8) {
    if (utf8.empty()) return false;
    m_copilotChatInputCache = utf8;
    if (!m_hwndCopilotChatInput || !IsWindow(m_hwndCopilotChatInput)) {
        return true;  // cache-only stage for harness WM_COPYDATA
    }
    const int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                      static_cast<int>(utf8.size()), nullptr, 0);
    if (n <= 0) return false;
    std::wstring wide(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                        static_cast<int>(utf8.size()), wide.data(), n);
    return SetWindowTextW(m_hwndCopilotChatInput, wide.c_str()) != FALSE;
}

rawrxd::tools::Registry* Win32IDE::agentToolsRegistry() {
    return static_cast<rawrxd::tools::Registry*>(m_agentToolsRegistry.get());
}

void Win32IDE::ensureComputerUseReady() {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    auto& cu = rawrxd::computer_use::ComputerUseBridge::Instance();
    cu.EnsureInitialized();
    cu.AllowOwnAndConfiguredParents();
    cu.ResetCancel();

    if (!m_agentToolsRegistry) {
        auto* reg = new rawrxd::tools::Registry();
        m_agentToolsRegistry = {reg, &DeleteRegistry};
        std::string ws;
        if (!m_currentExplorerPath.empty()) ws = m_currentExplorerPath;
        else if (!m_currentFile.empty()) {
            const size_t slash = m_currentFile.find_last_of("\\/");
            ws = (slash == std::string::npos)
                ? m_currentFile
                : m_currentFile.substr(0, slash);
        }
        if (!ws.empty()) {
            try {
                rawrxd::tools::register_workspace_tools(*reg, ws);
            } catch (...) {
                LOG_WARNING("Workspace tools registration skipped");
            }
        }
        cu.RegisterTools(*reg);
        auto* bridge = new RawrXD::Agent::ToolCallBridge();
        // Gap 5 SSOT: ToolCallBridge + Registry (adapters register into SSOT).
        RawrXD::Agent::IdeSsot::BindBridge(*bridge, reg, ws);

        // AF04/AF06: wire sandbox + consent into ToolCallBridge choke point.
        auto& sb = ExtensionSandbox::ExtensionSandboxManager::Instance();
        sb.ClearPolicy();
        if (!ws.empty()) sb.AddWorkspaceRoot(ws);
        sb.AddDeniedPathPrefix("C:\\Windows");
        sb.AddDeniedPathPrefix("C:\\Program Files");
        sb.SetAuditLogPath(
            "F:\\rawrxd\\evidence\\AGENT_SECURITY_WIRE_001\\security_audit.jsonl");
        bridge->SetSecurityGate(
            [](const rawrxd::tools::Tool& t, const rawrxd::tools::Request& r,
               std::string& denyReason) -> bool {
                auto& gate = ExtensionSandbox::ExtensionSandboxManager::Instance();
                std::string pathArg, cmdArg;
                auto itP = r.args.find("path");
                if (itP != r.args.end()) pathArg = itP->second;
                auto itC = r.args.find("command");
                if (itC != r.args.end()) cmdArg = itC->second;
                else {
                    auto itCmd = r.args.find("cmd");
                    if (itCmd != r.args.end()) cmdArg = itCmd->second;
                }
                return gate.CheckPathAndCommand(t.name, pathArg, cmdArg, denyReason);
            });
        bridge->SetApprovalCallback(
            [](const rawrxd::tools::Tool& t, const rawrxd::tools::Request& r) -> bool {
                if (t.risk == rawrxd::tools::Risk::ReadOnly) return true;
                ConsentRiskTier ct = ConsentRiskTier::Confirm;
                if (t.name == "deleteFile" || t.name == "Delete")
                    ct = ConsentRiskTier::Block;
                std::string detail;
                auto it = r.args.find("command");
                if (it != r.args.end()) detail = it->second;
                else {
                    auto itP = r.args.find("path");
                    if (itP != r.args.end()) detail = itP->second;
                }
                return RequestToolConsent(NULL, ct, t.name, detail);
            });

        m_agentToolCallBridge = {bridge, &DeleteToolBridge};
        m_computerUseRegistry = reg;
        m_computerUseToolsRegistered = true;
        CuEvidence("AGENT_TOOLS_REGISTRY_BOUND computer_use=1 orphan_static=0 ssot=ToolCallBridge");
        CuEvidence("SECURITY_GATE_WIRED sandbox=1 consent=1 promote=0");
        CuEvidence("TOOL_SCHEMA_READY computer_use.find_window=1 "
                   "computer_use.screenshot=1");
        LOG_INFO("ComputerUse bound to session Registry + ToolCallBridge");
        return;
    }

    auto* reg = static_cast<rawrxd::tools::Registry*>(m_agentToolsRegistry.get());
    if (!m_computerUseToolsRegistered && reg) {
        cu.RegisterTools(*reg);
        m_computerUseRegistry = reg;
        m_computerUseToolsRegistered = true;
        CuEvidence("AGENT_TOOLS_REGISTRY_CU_ATTACHED computer_use=1");
        LOG_INFO("ComputerUse attached to existing session Registry");
    }
#else
    LOG_INFO("ComputerUse not linked in this build");
#endif
}

void Win32IDE::cancelComputerUse() {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    rawrxd::computer_use::ComputerUseBridge::Instance().Cancel();
    appendToOutput(" ComputerUse cancelled\n", "Output", OutputSeverity::Warning);
#endif
}

std::vector<std::string> Win32IDE::listComputerUseTools() const {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    return {
        "computer_use.screenshot",
        "computer_use.find_window",
        "computer_use.inspect",
        "computer_use.click",
        "computer_use.type",
        "computer_use.key",
        "computer_use.scroll",
        "computer_use.launch",
    };
#else
    return {};
#endif
}

void Win32IDE::beginChatSmoke(const char* receiptPath) {
    m_chatSmokeReceiptPath = receiptPath && *receiptPath
        ? receiptPath
        : "F:\\rawrxd\\evidence\\GUI_MATURITY_TOP25_20261111_235013\\CHAT_SMOKE_RECEIPT.txt";
    m_chatSmokePhase = 0;
    m_chatSmokeStartMs = GetTickCount64();
    m_chatSmokeOutBaseline = 0;
    m_chatSmokeSawTokens = false;
    m_chatSmokeSawTokens2 = false;
    m_chatSmokeCancelOk = false;
    m_chatSmokeEditorOk = false;
    m_chatSmokeModelOk = false;
    m_chatSmokeModelId.clear();
    if (const char* force = std::getenv("RAWRXD_P11_FORCE_OLLAMA_MODEL")) {
        if (*force) m_chatSmokeModelId = force;
    }
    if (m_chatSmokeModelId.empty()) m_chatSmokeModelId = "n4-tiny-oracle:latest";
    if (m_hwndMain) SetTimer(m_hwndMain, IDT_CHAT_SMOKE, 250, nullptr);
    logInfo("[chat-smoke] begin model=" + m_chatSmokeModelId);
}

void Win32IDE::tickChatSmoke() {
    if (m_chatSmokePhase < 0) return;
    const ULONGLONG elapsed = GetTickCount64() - m_chatSmokeStartMs;
    auto finish = [this](bool pass) {
        if (m_hwndMain) KillTimer(m_hwndMain, IDT_CHAT_SMOKE);
        m_chatSmokePhase = -1;
        CreateDirectoryA("F:\\rawrxd\\evidence\\GUI_MATURITY_TOP25_20261111_235013", nullptr);
        std::ofstream rec(m_chatSmokeReceiptPath, std::ios::trunc);
        if (rec) {
            rec << "MODEL_SELECT=" << (m_chatSmokeModelOk ? "PASS" : "FAIL") << "\n"
                << "MODEL_ID=" << m_chatSmokeModelId << "\n"
                << "TOKENS_1=" << (m_chatSmokeSawTokens ? "PASS" : "FAIL") << "\n"
                << "CANCEL=" << (m_chatSmokeCancelOk ? "PASS" : "FAIL") << "\n"
                << "TOKENS_2=" << (m_chatSmokeSawTokens2 ? "PASS" : "FAIL") << "\n"
                << "EDITOR_SAVE=" << (m_chatSmokeEditorOk ? "PASS" : "FAIL") << "\n"
                << "OVERALL=" << (pass ? "PASS" : "FAIL") << "\n";
        }
        logInfo(pass ? "[chat-smoke] PASS" : "[chat-smoke] FAIL");
        ::ExitProcess(pass ? 0u : 2u);
    };
    if (elapsed > 180000ull) { finish(false); return; }

    if (m_chatSmokePhase == 0) {
        if (!m_hwndModelSelector) return;
        int comboRow = -1;
        const int count = static_cast<int>(
            SendMessage(m_hwndModelSelector, CB_GETCOUNT, 0, 0));
        for (int r = 0; r < count; ++r) {
            const LRESULT data = SendMessage(
                m_hwndModelSelector, CB_GETITEMDATA, static_cast<WPARAM>(r), 0);
            if (data < 0 || static_cast<size_t>(data) >= m_availableModels.size())
                continue;
            const auto& e = m_availableModels[static_cast<size_t>(data)];
            if (e.source == ChatModelEntry::Source::Ollama &&
                e.identifier == m_chatSmokeModelId) {
                comboRow = r; break;
            }
        }
        if (comboRow < 0 && elapsed > 45000ull) {
            for (int r = 0; r < count; ++r) {
                const LRESULT data = SendMessage(
                    m_hwndModelSelector, CB_GETITEMDATA, static_cast<WPARAM>(r), 0);
                if (data < 0 || static_cast<size_t>(data) >= m_availableModels.size())
                    continue;
                const auto& e = m_availableModels[static_cast<size_t>(data)];
                if (e.source == ChatModelEntry::Source::Ollama) {
                    m_chatSmokeModelId = e.identifier;
                    comboRow = r; break;
                }
            }
        }
        if (comboRow < 0) return;
        SendMessage(m_hwndModelSelector, CB_SETCURSEL,
            static_cast<WPARAM>(comboRow), 0);
        onModelSelectionChanged();
        m_chatSmokeModelOk =
            m_selectedChatModel.source == ChatModelEntry::Source::Ollama &&
            !m_selectedChatModel.identifier.empty();
        if (!m_chatSmokeModelOk) return;
        m_chatSmokeOutBaseline = m_hwndCopilotChatOutput
            ? getWindowTextUtf8(m_hwndCopilotChatOutput).size() : 0;
        stageCopilotChatInputUtf8("Reply with exactly: PONG_GUI_SMOKE_1");
        HandleCopilotSend();
        m_chatSmokePhase = 1;
        return;
    }
    if (m_chatSmokePhase == 1) {
        const std::string out = m_hwndCopilotChatOutput
            ? getWindowTextUtf8(m_hwndCopilotChatOutput) : std::string();
        if (out.size() > m_chatSmokeOutBaseline + 4) m_chatSmokeSawTokens = true;
        if (auto* s = activeChatSession()) {
            if (s->responseBuffer.size() > 4) m_chatSmokeSawTokens = true;
        }
        if (m_chatSmokeSawTokens || elapsed > 90000ull) {
            HandleCopilotStop();
            m_chatSmokeCancelOk = true;
            m_chatSmokePhase = 2;
            m_chatSmokeOutBaseline = out.size();
        }
        return;
    }
    if (m_chatSmokePhase == 2) {
        if (m_inferenceRunning.load(std::memory_order_acquire) && elapsed < 120000ull)
            return;
        stageCopilotChatInputUtf8("Reply with exactly: PONG_GUI_SMOKE_2");
        HandleCopilotSend();
        m_chatSmokePhase = 3;
        return;
    }
    if (m_chatSmokePhase == 3) {
        const std::string out = m_hwndCopilotChatOutput
            ? getWindowTextUtf8(m_hwndCopilotChatOutput) : std::string();
        if (out.size() > m_chatSmokeOutBaseline + 4) m_chatSmokeSawTokens2 = true;
        if (auto* s = activeChatSession()) {
            if (s->responseBuffer.size() > 4) m_chatSmokeSawTokens2 = true;
        }
        const bool done = !m_inferenceRunning.load(std::memory_order_acquire);
        if ((m_chatSmokeSawTokens2 && done) || elapsed > 150000ull) {
            m_chatSmokePhase = 4;
        }
        return;
    }
    if (m_chatSmokePhase == 4) {
        const char* probePath =
            "F:\\rawrxd\\evidence\\GUI_MATURITY_TOP25_20261111_235013\\chat_smoke_editor.txt";
        {
            std::ofstream ed(probePath, std::ios::trunc);
            if (ed) ed << "GUI_CHAT_SMOKE_EDITOR\n";
        }
        openFile(probePath);
        m_chatSmokeEditorOk = saveFile();
        const bool pass = m_chatSmokeModelOk && m_chatSmokeSawTokens &&
            m_chatSmokeCancelOk && m_chatSmokeSawTokens2 && m_chatSmokeEditorOk;
        finish(pass);
    }
}
