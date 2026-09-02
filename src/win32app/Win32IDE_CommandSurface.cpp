// Win32IDE_CommandSurface.cpp â€” RawrXD ScreenPilot command-home (Desktop Preview)
#include "Win32IDE.h"
#include "resource.h"
#include "../command/CommandBroker.h"
#include "../command/CommandEventJournal.h"
#include "../command/IControlChannel.h"
#include "../command/SessionBinder.h"
#include "ScreenPilotModelHub.h"
#include "Win32Utf8.hpp"
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
#include "P1PRA_ProcessState.hpp"
#include "../core/GpuDecodeEfficiency.hpp"
#endif
#ifdef RAWRXD_TOKEN_PRESSURE_VALVE
#include "TokenPressure.hpp"
#endif
#include "../agentic/AgentToolHandlers.h"
#include <algorithm>
#include <commctrl.h>
#include <commdlg.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <thread>

namespace fs = std::filesystem;
using RawrXD::Command::CommandBroker;
using RawrXD::Command::CommandEventJournal;
using RawrXD::Command::JournalEventType;
using RawrXD::Command::SessionBinder;
using RawrXD::Command::SessionSnapshot;

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
static bool p1praBridgeLoadModelSeh(AgenticBridge* bridge, const std::string& path,
                                    unsigned long* sehCodeOut) noexcept
{
    if (sehCodeOut)
        *sehCodeOut = 0;
    if (!bridge)
        return false;
    __try {
        return bridge->LoadModel(path);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (sehCodeOut)
            *sehCodeOut = GetExceptionCode();
        return false;
    }
}
#endif

static constexpr COLORREF kSpPanel = RGB(24, 24, 27);
static constexpr COLORREF kSpText = RGB(244, 244, 245);

static std::wstring utf8w(const std::string& s) {
    if (s.empty()) return L"";
    const int len = MultiByteToWideChar(
        CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (len <= 0) return L"";
    std::wstring w(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), len);
    return w;
}

static std::string readGitBranch(const std::string& repoRoot) {
    std::ifstream head(fs::path(repoRoot) / ".git" / "HEAD");
    if (!head) return "main";
    std::string line;
    std::getline(head, line);
    const std::string prefix = "ref: refs/heads/";
    if (line.rfind(prefix, 0) == 0) return line.substr(prefix.size());
    if (line.size() >= 7) return line.substr(0, 7);
    return "detached";
}

static std::string leafName(const std::string& path) {
    if (path.empty()) return "workspace";
    fs::path p(path);
    const auto leaf = p.filename().string();
    return leaf.empty() ? path : leaf;
}

static void styleChildFont(HWND h, HFONT font) {
    if (h && font) SendMessageW(h, WM_SETFONT, (WPARAM)font, TRUE);
}

static std::string formatBytes(uint64_t n) {
    if (n >= (1ull << 30)) return std::to_string(n / (1ull << 30)) + " GB";
    if (n >= (1ull << 20)) return std::to_string(n / (1ull << 20)) + " MB";
    return std::to_string(n) + " B";
}

static bool nameMatchesRecommend(const std::string& fileName, const char* id) {
    std::string lower = fileName;
    std::string key = id;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    std::transform(key.begin(), key.end(), key.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return lower.find(key) != std::string::npos ||
           (lower.find("deepseek") != std::string::npos &&
            key.find("deepseek") != std::string::npos) ||
           (lower.find("qwen") != std::string::npos && key.find("qwen") != std::string::npos);
}

LRESULT CALLBACK Win32IDE::CommandHostProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ide = reinterpret_cast<Win32IDE*>(GetPropW(hwnd, L"IDE_PTR"));
    switch (msg) {
    case WM_ERASEBKGND: {
        RECT rc{};
        GetClientRect(hwnd, &rc);
        HBRUSH bg = (ide && ide->m_cmdBgBrush) ? ide->m_cmdBgBrush
                                               : (HBRUSH)GetStockObject(BLACK_BRUSH);
        FillRect(reinterpret_cast<HDC>(wp), &rc, bg);
        return 1;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = reinterpret_cast<HDC>(wp);
        SetBkColor(hdc, kSpPanel);
        SetTextColor(hdc, kSpText);
        if (ide && ide->m_cmdPanelBrush) return (LRESULT)ide->m_cmdPanelBrush;
        return (LRESULT)GetStockObject(BLACK_BRUSH);
    }
    case WM_COMMAND: {
        if (!ide)
            break;
        const int id = LOWORD(wp);
        // STATIC DefWindowProc swallows child BN_CLICKED; dispatch Send locally.
        if (id == IDC_CMD_SEND_BTN) {
            ide->handleCommandSend(hwnd);
            return 0;
        }
        if (ide->m_hwndMain)
            return SendMessageW(ide->m_hwndMain, WM_COMMAND, wp, lp);
        break;
    }
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void Win32IDE::appendCommandConversation(const std::string& line, bool ensureNewline) {
    if (!m_hwndCommandConversation || !IsWindow(m_hwndCommandConversation)) return;
    std::string text = line;
    if (ensureNewline && !text.empty() && text.back() != '\n') text += "\n";
    const int len = GetWindowTextLengthW(m_hwndCommandConversation);
    SendMessageW(m_hwndCommandConversation, EM_SETSEL, len, len);
    SendMessageW(m_hwndCommandConversation, EM_REPLACESEL, FALSE,
                 (LPARAM)utf8w(text).c_str());
    SendMessageW(m_hwndCommandConversation, WM_VSCROLL, SB_BOTTOM, 0);
}

void Win32IDE::appendCommandOutput(const std::string& line, bool ensureNewline) {
    std::string text = line;
    if (ensureNewline && !text.empty() && text.back() != '\n') text += "\n";
    if (m_hwndCommandOutput && IsWindow(m_hwndCommandOutput)) {
        const int len = GetWindowTextLengthW(m_hwndCommandOutput);
        SendMessageW(m_hwndCommandOutput, EM_SETSEL, len, len);
        SendMessageW(m_hwndCommandOutput, EM_REPLACESEL, FALSE,
                     (LPARAM)utf8w(text).c_str());
        SendMessageW(m_hwndCommandOutput, WM_VSCROLL, SB_BOTTOM, 0);
    }
    appendToOutput(text, "Output", OutputSeverity::Info);
}

void Win32IDE::appendCommandConversationStream(const std::string& chunk) {
#ifdef RAWRXD_TOKEN_PRESSURE_VALVE
    if (!chunk.empty()) {
        const auto act = token_pressure::OnUtf8Chunk(chunk.data(), chunk.size());
        if (act == token_pressure::ValveAction::StopRequest) {
            m_inferenceStopRequested = true;
            if (m_agenticBridge)
                m_agenticBridge->StopAgentLoop();
            appendCommandConversation(
                "\n[TokenPressure] STOP_REQUEST â€” cutoff/repeat pressure\n", true);
        }
    }
#endif
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    if (P1PRA_RequestActive() && !chunk.empty()) {
        static std::atomic<bool> s_p1praDecodeWindowOpen{false};
        if (!s_p1praDecodeWindowOpen.exchange(true, std::memory_order_relaxed)) {
            P1PRA_Witness("P1PRA_DECODE", "pre_enter");
            rawrxd::GpuDecodeEfficiencyAuthority::Instance().BeginDecodeWindow();
            P1PRA_Witness("P1PRA_DECODE", "pre_exit");
        }
        const auto n = static_cast<std::uint64_t>(chunk.size());
        P1PRA_Witness("P1PRA_UI_EMIT", "hook_enter");
        P1PRA_OnUiEmit(n);
        P1PRA_Witness("P1PRA_UI_EMIT", "hook_exit");
    }
#endif
    appendCommandConversation(chunk, false);
}

static std::uint64_t p1praFileSizeBytes(const std::string& path) {
    if (path.empty()) return 0;
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad))
        return 0;
    ULARGE_INTEGER u;
    u.HighPart = fad.nFileSizeHigh;
    u.LowPart = fad.nFileSizeLow;
    return u.QuadPart;
}

std::string Win32IDE::assembleCommandInferenceContext(const std::string& userMsg,
                                                      std::size_t byteBudget) const {
    const std::size_t budget = byteBudget == 0 ? 12288 : byteBudget;
    std::ostringstream ctx;
    ctx << "[ScreenPilot context â€” bounded]\n";
    std::size_t used = 0;
    auto take = [&](const std::string& block) {
        if (block.empty() || used >= budget) return;
        const std::size_t room = budget - used;
        if (block.size() <= room) {
            ctx << block;
            used += block.size();
        } else {
            ctx << block.substr(0, room) << "\nâ€¦[truncated]\n";
            used = budget;
        }
    };

    if (m_hwndEditor && IsWindow(m_hwndEditor)) {
        DWORD start = 0, end = 0;
        SendMessageW(m_hwndEditor, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
        if (end > start && (end - start) < 65536) {
            const int len = GetWindowTextLengthW(m_hwndEditor);
            if (len > 0) {
                std::wstring w(static_cast<size_t>(len) + 1, L'\0');
                GetWindowTextW(m_hwndEditor, w.data(), len + 1);
                w.resize(static_cast<size_t>(len));
                if (end <= w.size() && start < end) {
                    const std::string sel = RawrXD::WideToUtf8(w.substr(start, end - start));
                    take("## Selection\n```\n" + sel + "\n```\n");
                }
            }
        }
    }

    int openCount = 0;
    for (const auto& tab : m_editorTabs) {
        if (openCount >= 4 || used >= budget) break;
        if (tab.filePath.empty() && tab.displayName.empty()) continue;
        std::string snippet = tab.content;
        if (snippet.size() > 1500) snippet = snippet.substr(0, 1500) + "\nâ€¦";
        take(std::string("## Open: ") +
             (tab.filePath.empty() ? tab.displayName : tab.filePath) + "\n```\n" +
             snippet + "\n```\n");
        ++openCount;
    }

    take("## User\n" + userMsg + "\n");
    return ctx.str();
}

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
void Win32IDE::p1praWitnessModelLoadReady() {
    P1PRA_SetModelReadyWitness();
    P1PRA_Witness("P1PRA_LOAD", "model_ready");
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    // #region agent log
    P1PRA_AgentDbg("H2", "p1praWitnessModelLoadReady", "load_witness",
                   P1PRA_RequestActive() ? 1u : 0u, 0, 0);
    // #endregion agent log
#endif
    const std::string modelPath = getLoadedModelPath();
    if (modelPath.empty()) {
        P1PRA_Witness("P1PRA_LOAD_PATH", "empty");
        return;
    }
    char buf[384];
    snprintf(buf, sizeof(buf), "path=%s bytes=%llu req_active=%u",
             modelPath.c_str(),
             static_cast<unsigned long long>(p1praFileSizeBytes(modelPath)),
             P1PRA_RequestActive() ? 1u : 0u);
    P1PRA_Witness("P1PRA_LOAD_PATH", buf);
}

void Win32IDE::p1praAdvanceRequestProductPath() {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    // #region agent log
    P1PRA_AgentDbg("H4", "p1praAdvanceRequestProductPath", "advance_enter",
                   P1PRA_RequestActive() ? 1u : 0u,
                   P1PRA_CurrentRequestId(), 0);
    // #endregion agent log
#endif
    if (!P1PRA_RequestActive())
        return;
    P1PRA_OnRouterDispatch();
    const std::string modelPath = getLoadedModelPath();
    if (modelPath.empty())
        return;
    P1PRA_OnGgufOpen(1);
    const std::uint64_t wb = p1praFileSizeBytes(modelPath);
    if (wb > 0)
        P1PRA_OnWeightAccess(wb);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    // #region agent log
    P1PRA_AgentDbg("H4", "p1praAdvanceRequestProductPath", "advance_done",
                   P1PRA_CurrentRequestId(), wb, 0);
    // #endregion agent log
#endif
}


void Win32IDE::p1praCompleteProductRequest(const char* steerModeLabel, bool streamOk) {
    P1PRA_Witness("P1PRA_CALLBACK_ENTER", "1");
    const bool physical = P1PRA_RealProductRequestPass(streamOk);
    P1PRA_Witness("P1PRA_STREAM_PHYS", physical ? "witnessed" : "not_witnessed");
    P1PRA_Witness("P1PRA_RESULT_STATUS",
                  physical ? "stream_ok" : "stream_fail");
    const std::uint64_t tok = P1PRA_EngineSampleCount();
    const auto eff =
        rawrxd::GpuDecodeEfficiencyAuthority::Instance().EndAndPublish(tok);
    if (eff.power_valid) {
        char tpw[64];
        snprintf(tpw, sizeof(tpw), "%.6f", eff.tokens_per_watt_gpu);
        P1PRA_Witness("TOKENS_PER_WATT_GPU", tpw);
        char pw[64];
        snprintf(pw, sizeof(pw), "%.2f", eff.average_gpu_watts);
        P1PRA_Witness("AVG_GPU_WATTS", pw);
    } else {
        P1PRA_Witness("GPU_POWER_VALID", "0");
    }
    P1PRA_E2E_Meta meta;
    const std::string modelPath = getLoadedModelPath();
    meta.modelPath = modelPath.c_str();
    meta.steerMode = steerModeLabel ? steerModeLabel : "";
    meta.exeSha256 = P1PRA_GetExeSha256Hex();
    meta.loadModelPass = P1PRA_ModelReadyWitnessed() ? 1 : 0;
    meta.commandSendPass = (P1PRA_CurrentRequestId() > 0) ? 1 : 0;
    meta.realInferenceEngine = (P1PRA_EngineForwardCount() > 0) ? 1 : 0;
    meta.streamBegin = (P1PRA_EngineSampleCount() > 0) ? 1 : 0;
    meta.streamEnd = physical ? 1 : 0;
    meta.syntheticFallback = 0;
    meta.leaseReleased = 1;
    meta.exitCode = physical ? 0 : 1;
    P1PRA_OnRequestComplete(meta);
}
#endif

void Win32IDE::bindCommandSessionFromWorkspace() {
    updateGitStatus();
    SessionSnapshot snap;
    snap.workspaceRoot = m_gitRepoPath.empty() ? fs::current_path().string() : m_gitRepoPath;
    snap.repository = leafName(snap.workspaceRoot);
    snap.branch = m_gitStatus.branch.empty() ? readGitBranch(snap.workspaceRoot)
                                             : m_gitStatus.branch;
    snap.model = "Deep2 Local";
    char machine[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameA(machine, &sz)) snap.machine = machine;
    else snap.machine = "This PC";
    SessionBinder::instance().bind(snap);
    CommandEventJournal::instance().setWorkspaceRoot(snap.workspaceRoot);
    CommandEventJournal::instance().append(JournalEventType::SessionBound,
        "\"" + snap.machine + "/" + snap.repository + "\"");
}

void Win32IDE::refreshCommandContextBar() {
    if (!m_hwndTopContextBar) return;
    const auto& s = SessionBinder::instance().snapshot();
    std::wostringstream w;
    w << L"RawrXD ScreenPilot  |  " << utf8w(s.machine) << L"  |  "
      << utf8w(s.repository) << L"  |  " << utf8w(s.branch);
    SetWindowTextW(m_hwndTopContextBar, w.str().c_str());
}

void Win32IDE::refreshCommandLeftRail() {
    if (!m_hwndCommandLeftRail) return;
    SendMessageW(m_hwndCommandLeftRail, LB_RESETCONTENT, 0, 0);
    const auto& s = SessionBinder::instance().snapshot();
    SendMessageW(m_hwndCommandLeftRail, LB_ADDSTRING, 0, (LPARAM)L"Machines");
    SendMessageW(m_hwndCommandLeftRail, LB_ADDSTRING, 0,
                 (LPARAM)(L"  " + utf8w(s.machine)).c_str());
    SendMessageW(m_hwndCommandLeftRail, LB_ADDSTRING, 0, (LPARAM)L"Workspaces");
    SendMessageW(m_hwndCommandLeftRail, LB_ADDSTRING, 0,
                 (LPARAM)(L"  " + utf8w(s.repository)).c_str());
    SendMessageW(m_hwndCommandLeftRail, LB_ADDSTRING, 0, (LPARAM)L"Git");
    std::wstring gitLine = L"  " + utf8w(s.branch);
    if (m_gitStatus.hasChanges) {
        gitLine += L"  M" + std::to_wstring(m_gitStatus.modified) + L" A" +
                   std::to_wstring(m_gitStatus.added) + L" D" +
                   std::to_wstring(m_gitStatus.deleted) + L" ?" +
                   std::to_wstring(m_gitStatus.untracked);
    } else {
        gitLine += L"  clean";
    }
    SendMessageW(m_hwndCommandLeftRail, LB_ADDSTRING, 0, (LPARAM)gitLine.c_str());
    const auto pendingList = CommandBroker::instance().pendingApprovals();
    if (!pendingList.empty()) {
        SendMessageW(m_hwndCommandLeftRail, LB_ADDSTRING, 0, (LPARAM)L"Approvals");
        for (const auto& p : pendingList) {
            std::wstring row = L"  " + utf8w(p.id) + L": " + utf8w(p.action);
            SendMessageW(m_hwndCommandLeftRail, LB_ADDSTRING, 0, (LPARAM)row.c_str());
        }
    }
    HWND approveBtn = m_hwndActivityStrip
                          ? GetDlgItem(m_hwndActivityStrip, IDC_CMD_APPROVE_BTN)
                          : nullptr;
    HWND denyBtn = m_hwndActivityStrip
                       ? GetDlgItem(m_hwndActivityStrip, IDC_CMD_DENY_BTN)
                       : nullptr;
    const bool showApproval = !pendingList.empty();
    if (approveBtn) ShowWindow(approveBtn, showApproval ? SW_SHOW : SW_HIDE);
    if (denyBtn) ShowWindow(denyBtn, showApproval ? SW_SHOW : SW_HIDE);
}

void Win32IDE::refreshCommandFooter() {
    if (!m_hwndCommandFooter) return;
    SetWindowTextW(m_hwndCommandFooter,
                   L"Desktop Preview Â· LOCAL_ONLY_001 Â· Deep2/GGUF Â· "
                   L"local authority retained Â· EGRESS_001 open");
}

void Win32IDE::refreshCommandActivityStrip() {
    if (!m_hwndActivityStripText) return;
    std::string status = CommandBroker::instance().activityStatus();
    if (status.empty()) {
        status = std::string("RawrXD Agent idle â€” ") +
                 CommandBroker::instance().steerModeLabel(
                     CommandBroker::instance().steerMode()) +
                 " mode";
    }
    if (CommandBroker::instance().agentActive()) {
        status += " Â· write lease: edit/command_steer";
    }
    SetWindowTextW(m_hwndActivityStripText,
                   utf8w(status.empty() ? "RawrXD Agent idle" : status).c_str());
    const size_t n = CommandBroker::instance().pendingApprovalCount();
    if (m_hwndCmdApprovalBadge) {
        if (n > 0) {
            const auto pending = CommandBroker::instance().pendingApprovals();
            std::wstring badge = L"Approvals: " + std::to_wstring(n);
            if (!pending.empty()) badge += L" (" + utf8w(pending.front().action) + L")";
            SetWindowTextW(m_hwndCmdApprovalBadge, badge.c_str());
            ShowWindow(m_hwndCmdApprovalBadge, SW_SHOW);
        } else {
            ShowWindow(m_hwndCmdApprovalBadge, SW_HIDE);
        }
    }
    refreshCommandLeftRail();
}

void Win32IDE::refreshCommandModelHub() {
    if (!m_hwndModelLocalList || !m_hwndModelRecList) return;
    using RawrXD::ScreenPilot::ModelHub;
    const auto inv = ModelHub::scanLocalInventory(128);
    m_cmdModelInventoryPaths.clear();
    SendMessageW(m_hwndModelLocalList, LB_RESETCONTENT, 0, 0);
    for (const auto& e : inv) {
        m_cmdModelInventoryPaths.push_back(e.fullPath);
        const std::string line = e.fileName + "  (" + formatBytes(e.bytes) + ")";
        SendMessageW(m_hwndModelLocalList, LB_ADDSTRING, 0, (LPARAM)utf8w(line).c_str());
    }
    SendMessageW(m_hwndModelRecList, LB_RESETCONTENT, 0, 0);
    for (const auto& rec : ModelHub::topRecommendations()) {
        bool onDisk = false;
        for (const auto& e : inv) {
            if (nameMatchesRecommend(e.fileName, rec.id)) {
                onDisk = true;
                break;
            }
        }
        std::string line = std::string(rec.label) + "  [" + rec.sizeHint + "]  " +
                           (onDisk ? "READY" : "not on disk");
        SendMessageW(m_hwndModelRecList, LB_ADDSTRING, 0, (LPARAM)utf8w(line).c_str());
    }
    if (m_hwndModelHubStatus) {
        const auto roots = ModelHub::storageRoots();
        const std::string root = roots.empty() ? "F:\\OllamaModels" : roots.front();
        std::wstring msg = L"LOCAL_ONLY_001 Â· " + utf8w(root) + L" Â· " +
                           std::to_wstring(inv.size()) + L" weights Â· loopback only";
        SetWindowTextW(m_hwndModelHubStatus, msg.c_str());
    }
    if (m_hwndModelHubHdr) {
        SetWindowTextW(m_hwndModelHubHdr,
                       L"Engine control Â· Deep2/GGUF Â· browse/load local weights only");
    }
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    {
        char hub[48];
        snprintf(hub, sizeof(hub), "count=%zu", inv.size());
        P1PRA_Witness("P1PRA_HUB", hub);
    }
#endif
}

void Win32IDE::handleCommandModelLoad() {
    if (!m_hwndModelLocalList) return;
    const int sel = (int)SendMessageW(m_hwndModelLocalList, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= (int)m_cmdModelInventoryPaths.size()) {
        appendCommandConversation("[System] Select a local .gguf from the inventory list.");
        return;
    }
    const std::string path = m_cmdModelInventoryPaths[static_cast<size_t>(sel)];
    appendCommandConversation("[System] Loading model: " + path);
    CommandBroker::instance().setActivityStatus("Loading local GGUF...");
    refreshCommandActivityStrip();
    if (!m_agenticBridge)
        initializeAgenticBridge();
    if (!m_agenticBridge) {
        appendCommandConversation("[System] Model load failed â€” agentic bridge unavailable.");
        CommandBroker::instance().setActivityStatus("Model load failed");
        refreshCommandActivityStrip();
        refreshCommandModelHub();
        return;
    }
    appendToOutput("Loading model (worker): " + path + "\n", "System", OutputSeverity::Info);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_ClearModelReadyWitness();
    P1PRA_Witness("P1PRA_LOAD", "worker_dispatch");
#endif
    AgenticBridge* bridge = m_agenticBridge;
    const std::string pathCopy = path;
    HWND hwndNotify = m_hwndMain;
    std::thread loadWorker([bridge, pathCopy, hwndNotify]() {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        P1PRA_Witness("P1PRA_LOAD", "worker_enter");
        P1PRA_ThreadStartWitness("cmd_load_worker");
        P1PRA_Witness("P1PRA_LOAD", "path_begin");
        const void* pathPtr = pathCopy.data();
        const std::size_t pathLen = pathCopy.size();
        P1PRA_Witness("P1PRA_LOAD", "path_ok");
        const std::uint64_t pathHash = P1PRA_Fnv1a64(pathPtr, pathLen);
        P1PRA_WitnessPtr("P1PRA_LOAD", "engine_ptr", bridge);
        P1PRA_WitnessLoadWorkerSnap(bridge, pathPtr, pathLen, pathHash, hwndNotify);
        P1PRA_Witness("P1PRA_LOAD", "before_load");
        // #region agent log
        P1PRA_AgentDbg("H1", "cmd_load_worker", "LoadModel_enter", 0, 0, 0);
        // #endregion
        unsigned long sehCode = 0;
        const bool ok = p1praBridgeLoadModelSeh(bridge, pathCopy, &sehCode);
        if (sehCode != 0)
        {
            char sehBuf[64];
            snprintf(sehBuf, sizeof(sehBuf), "after_load_seh code=%08lX", sehCode);
            P1PRA_Witness("P1PRA_LOAD", sehBuf);
            P1PRA_Witness("P1PRA_LOAD", "worker_fail");
            P1PRA_AgentDbg("H1", "cmd_load_worker", "LoadModel_exit", 0, 1, sehCode);
        }
        else if (!ok)
        {
            P1PRA_Witness("P1PRA_LOAD", "after_load_fail");
            P1PRA_Witness("P1PRA_LOAD", "worker_fail");
            P1PRA_AgentDbg("H1", "cmd_load_worker", "LoadModel_exit", 0, 0, 0);
        }
        else
        {
            P1PRA_Witness("P1PRA_LOAD", "after_load_ok");
            P1PRA_AgentDbg("H1", "cmd_load_worker", "LoadModel_exit", 1, 0, 0);
        }
        // #endregion agent log
#else
        const bool ok = bridge ? bridge->LoadModel(pathCopy) : false;
#endif
        auto* pathHeap = new (std::nothrow) std::string(pathCopy);
        if (hwndNotify && IsWindow(hwndNotify) && pathHeap)
            PostMessageA(hwndNotify, WM_APP + 206, ok ? 1u : 0u, reinterpret_cast<LPARAM>(pathHeap));
        else
            delete pathHeap;
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        P1PRA_Witness("P1PRA_LOAD", "post_message");
        P1PRA_ThreadStopWitness("cmd_load_worker");
#endif
    });
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_Witness("P1PRA_LOAD", "worker_thread_spawned");
#endif
    loadWorker.detach();
}

void Win32IDE::onCommandModelLoadWorkerDone(bool ok, const std::string& path) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    {
        char dj[96];
        snprintf(dj, sizeof(dj), "{\"ok\":%u,\"path_len\":%zu}", ok ? 1u : 0u, path.size());
        // #region agent log
        P1PRA_DebugLog("H5", "onCommandModelLoadWorkerDone", "ui_callback", dj);
        // #endregion
    }
#endif
    if (!ok) {
        appendCommandConversation("[System] Model load failed — check Output panel.");
        CommandBroker::instance().setActivityStatus("Model load failed");
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        if (m_agenticBridge) {
            const std::string err = m_agenticBridge->GetLastModelLoadError();
            if (!err.empty())
                P1PRA_Witness("P1PRA_LOAD_ERR", err.c_str());
        }
#endif
        refreshCommandActivityStrip();
        refreshCommandModelHub();
        return;
    }
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_Witness("P1PRA_LOAD", "ready_publish_begin");
#endif
    if (finishLoadModelForInferenceUI(path, ok)) {
        m_nativeEngine = RawrXD::CPUInferenceEngine::GetSharedInstance();
        if (m_nativeEngine && m_nativeEngine->IsModelLoaded())
            m_nativeEngineLoaded = true;
        // Worker path already loaded via AgenticBridge/CPU engine â€” skip duplicate init
        // that wires AI completion and can AV on CPU-only E2E hosts after hub shows ready.
        if (!m_nativeEngineLoaded)
            initializeInference();
        appendCommandConversation("[System] Model loaded into Deep2 local engine.");
        CommandBroker::instance().setActivityStatus("Deep2 local engine ready");
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        P1PRA_Witness("P1PRA_LOAD", "ready_publish_end");
        P1PRA_Witness("P1PRA_LOAD", "worker_ok");
        p1praWitnessModelLoadReady();
#endif
    } else {
        appendCommandConversation("[System] Model load failed — check Output panel.");
        CommandBroker::instance().setActivityStatus("Model load failed");
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        P1PRA_Witness("P1PRA_LOAD", "ready_publish_fail");
        if (m_agenticBridge) {
            const std::string err = m_agenticBridge->GetLastModelLoadError();
            if (!err.empty())
                P1PRA_Witness("P1PRA_LOAD_ERR", err.c_str());
        }
#endif
    }
    if (ok) {
        if (m_hwndModelHubStatus) {
            SetWindowTextW(m_hwndModelHubStatus, L"Deep2 local engine ready");
        }
        refreshCommandActivityStrip();
    }
}

void Win32IDE::handleCommandModelBrowse() {
    wchar_t pathBuf[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFilter = L"GGUF Models\0*.gguf\0All Files\0*.*\0";
    ofn.lpstrFile = pathBuf;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"Select local GGUF (LOCAL_ONLY_001 â€” no cloud pull)";
    ofn.lpstrInitialDir = L"F:\\OllamaModels";
    if (!GetOpenFileNameW(&ofn)) return;
    const std::string path = RawrXD::WideToUtf8(pathBuf);
    appendCommandConversation("[System] Loading browsed model: " + path);
    if (loadModelForInference(path)) {
        initializeInference();
        appendCommandConversation("[System] Model loaded.");
        CommandBroker::instance().setActivityStatus("Deep2 local engine ready");
    }
    refreshCommandActivityStrip();
    refreshCommandModelHub();
}

bool Win32IDE::unloadModelForInference() {
    m_inferenceStopRequested = true;
    if (m_agenticBridge) {
        m_agenticBridge->StopAgentLoop();
    }
    shutdownInference();
    {
        std::unique_lock<std::shared_mutex> lock(m_loadedModelPathMutex);
        m_loadedModelPath.clear();
    }
    m_nativeEngineLoaded = false;
    if (m_nativeEngine) {
        // Shared engine may still hold weights; clear IDE-side ready flag only.
    }
    if (m_hwndModelHubStatus)
        SetWindowTextW(m_hwndModelHubStatus, L"No model loaded");
    CommandBroker::instance().setActivityStatus("Model unloaded");
    return true;
}

void Win32IDE::handleCommandModelUnload() {
    unloadModelForInference();
    appendCommandConversation("[System] Model unloaded â€” load another .gguf without restarting.");
    refreshCommandActivityStrip();
    refreshCommandModelHub();
}

void Win32IDE::handleCommandModelReload() {
    const std::string path = getLoadedModelPath();
    if (path.empty()) {
        appendCommandConversation("[System] No model path to reload â€” Load or Browse first.");
        return;
    }
    appendCommandConversation("[System] Reloading model: " + path);
    unloadModelForInference();
    if (loadModelForInference(path)) {
        initializeInference();
        appendCommandConversation("[System] Model reloaded.");
        CommandBroker::instance().setActivityStatus("Deep2 local engine ready");
    } else {
        appendCommandConversation("[System] Reload failed.");
        CommandBroker::instance().setActivityStatus("Model reload failed");
    }
    refreshCommandActivityStrip();
    refreshCommandModelHub();
}

void Win32IDE::handleCommandInferenceCancel() {
    m_inferenceStopRequested = true;
    stopInference();
    if (m_agenticBridge)
        m_agenticBridge->StopAgentLoop();
    shutdownInference();
    stopTerminal();
    CommandBroker::instance().setAgentActive(false);
    CommandBroker::instance().setActivityStatus("Inference cancelled");
    appendCommandConversation("[System] Inference / agent cancelled.");
    refreshCommandActivityStrip();
}

void Win32IDE::layoutCommandSurface(int cw, int ch) {
    if (!m_hwndCommandHost || cw <= 0 || ch <= 0) return;
    const int pad = 12;
    const int railW = 220;
    const int ctxH = 36;
    const int steerH = 52;
    const int hubH = 132;
    const int actH = 40;
    const int footH = 28;
    const int compH = 88;
    const int comboW = 140;
    const int btnW = 96;
    int hubUse = hubH;
    int y = pad;
    if (m_hwndTopContextBar)
        MoveWindow(m_hwndTopContextBar, pad, y, cw - 2 * pad, ctxH, TRUE);
    y += ctxH + pad;
    const int bodyTop = y;
    const int bodyH = ch - bodyTop - footH - pad;
    if (m_hwndCommandLeftRail)
        MoveWindow(m_hwndCommandLeftRail, pad, bodyTop, railW, bodyH, TRUE);
    const int mainX = pad + railW + pad;
    const int mainW = (std::max)(120, cw - mainX - pad);
    int mainY = bodyTop;
    int convH = bodyH - steerH - hubUse - actH - compH - 5 * pad;
    const int outputHdrH = 18;
    const int outputH = (std::max)(88, convH / 3);
    convH -= outputHdrH + outputH + pad;
    if (convH < 100) {
        hubUse = (std::max)(72, hubUse - (100 - convH));
        convH = bodyH - steerH - hubUse - actH - compH - 4 * pad;
    }
    convH = (std::max)(80, convH);
    if (m_hwndCommandConversation)
        MoveWindow(m_hwndCommandConversation, mainX, mainY, mainW, convH, TRUE);
    mainY += convH + pad;
    if (m_hwndCommandOutputHdr)
        MoveWindow(m_hwndCommandOutputHdr, mainX, mainY, mainW, outputHdrH, TRUE);
    mainY += outputHdrH;
    if (m_hwndCommandOutput)
        MoveWindow(m_hwndCommandOutput, mainX, mainY, mainW, outputH, TRUE);
    mainY += outputH + pad;
    if (m_hwndSteeringBelt)
        MoveWindow(m_hwndSteeringBelt, mainX, mainY, mainW, steerH, TRUE);
    mainY += steerH + pad;
    if (m_hwndModelHubHdr)
        MoveWindow(m_hwndModelHubHdr, mainX, mainY, mainW, 18, TRUE);
    mainY += 20;
    const int halfW = (mainW - 8) / 2;
    const int hubListH = (std::max)(48, hubUse - 24);
    if (m_hwndModelRecList)
        MoveWindow(m_hwndModelRecList, mainX, mainY, halfW, hubListH, TRUE);
    if (m_hwndModelLocalList)
        MoveWindow(m_hwndModelLocalList, mainX + halfW + 8, mainY, halfW, hubListH, TRUE);
    mainY += hubListH + 4;
    HWND loadBtn = GetDlgItem(m_hwndCommandHost, IDC_CMD_MODEL_LOAD_BTN);
    if (loadBtn) MoveWindow(loadBtn, mainX, mainY, 88, 24, TRUE);
    HWND browseBtn = GetDlgItem(m_hwndCommandHost, IDC_CMD_MODEL_BROWSE_BTN);
    if (browseBtn) MoveWindow(browseBtn, mainX + 92, mainY, 100, 24, TRUE);
    HWND unloadBtn = GetDlgItem(m_hwndCommandHost, IDC_CMD_MODEL_UNLOAD_BTN);
    if (unloadBtn) MoveWindow(unloadBtn, mainX + 196, mainY, 72, 24, TRUE);
    HWND reloadBtn = GetDlgItem(m_hwndCommandHost, IDC_CMD_MODEL_RELOAD_BTN);
    if (reloadBtn) MoveWindow(reloadBtn, mainX + 272, mainY, 72, 24, TRUE);
    HWND cancelInfBtn = GetDlgItem(m_hwndCommandHost, IDC_CMD_MODEL_CANCEL_BTN);
    if (cancelInfBtn) MoveWindow(cancelInfBtn, mainX + 348, mainY, 72, 24, TRUE);
    if (m_hwndModelHubStatus)
        MoveWindow(m_hwndModelHubStatus, mainX + 424, mainY, (std::max)(40, mainW - 424), 24, TRUE);
    mainY += 28;
    if (m_hwndActivityStrip)
        MoveWindow(m_hwndActivityStrip, mainX, mainY, mainW, actH, TRUE);
    const int apprW = 72;
    const int stopW = btnW;
    const int controlsW = stopW + 2 * apprW + 16;
    if (m_hwndActivityStripText)
        MoveWindow(m_hwndActivityStripText, 8, 8, mainW - controlsW - 16, 24, TRUE);
    if (m_hwndCmdApprovalBadge)
        MoveWindow(m_hwndCmdApprovalBadge, mainW - controlsW, 10, controlsW - stopW - 8, 20, TRUE);
    HWND approveBtn = m_hwndActivityStrip
                          ? GetDlgItem(m_hwndActivityStrip, IDC_CMD_APPROVE_BTN)
                          : nullptr;
    HWND denyBtn = m_hwndActivityStrip
                       ? GetDlgItem(m_hwndActivityStrip, IDC_CMD_DENY_BTN)
                       : nullptr;
    if (approveBtn) MoveWindow(approveBtn, mainW - stopW - 2 * apprW - 12, 6, apprW, 28, TRUE);
    if (denyBtn) MoveWindow(denyBtn, mainW - stopW - apprW - 6, 6, apprW, 28, TRUE);
    HWND stopBtn = GetDlgItem(m_hwndActivityStrip, IDC_CMD_STOP_BTN);
    if (stopBtn) MoveWindow(stopBtn, mainW - stopW - 8, 6, stopW, 28, TRUE);
    mainY += actH + pad;
    if (m_hwndCommandComposer)
        MoveWindow(m_hwndCommandComposer, mainX, mainY, mainW - 2 * comboW - btnW - 24,
                   compH, TRUE);
    int cx = mainX + mainW - 2 * comboW - btnW - 16;
    if (m_hwndCmdModelCombo) MoveWindow(m_hwndCmdModelCombo, cx, mainY + 8, comboW, 200, TRUE);
    cx += comboW + 8;
    if (m_hwndCmdModeCombo) MoveWindow(m_hwndCmdModeCombo, cx, mainY + 8, comboW, 200, TRUE);
    cx += comboW + 8;
    HWND sendBtn = GetDlgItem(m_hwndCommandHost, IDC_CMD_SEND_BTN);
    if (sendBtn) MoveWindow(sendBtn, cx, mainY + 8, btnW, 32, TRUE);
    HWND workBtn = GetDlgItem(m_hwndCommandHost, IDC_CMD_WORK_MODE_BTN);
    if (workBtn) MoveWindow(workBtn, mainX, mainY + compH - 28, 260, 28, TRUE);
    if (m_hwndCommandFooter)
        MoveWindow(m_hwndCommandFooter, pad, ch - footH - pad / 2, cw - 2 * pad, footH, TRUE);
}

static void setChromeVisible(HWND h, int cmd) {
    if (h && IsWindow(h)) ShowWindow(h, cmd);
}

void Win32IDE::applyShellModeChrome() {
    const bool cmd = (m_shellMode == AppShellMode::Command);
    if (cmd) {
        if (m_hwndFindDialog && IsWindow(m_hwndFindDialog)) {
            DestroyWindow(m_hwndFindDialog);
            m_hwndFindDialog = nullptr;
        }
        setChromeVisible(m_hwndCommandHost, SW_SHOW);
        setChromeVisible(m_hwndToolbar, SW_HIDE);
        setChromeVisible(m_hwndActivityBar, SW_HIDE);
        setChromeVisible(m_hwndSidebar, SW_HIDE);
        setChromeVisible(m_hwndSecondarySidebar, SW_HIDE);
        setChromeVisible(m_hwndTabBar, SW_HIDE);
        setChromeVisible(m_hwndEditor, SW_HIDE);
        setChromeVisible(m_hwndStatusBar, SW_HIDE);
        setChromeVisible(m_hwndOutputTabs, SW_HIDE);
        setChromeVisible(m_hwndPowerShellPanel, SW_HIDE);
        setChromeVisible(m_hwndBreadcrumbs, SW_HIDE);
        setChromeVisible(m_hwndLineNumbers, SW_HIDE);
        setChromeVisible(m_hwndMinimap, SW_HIDE);
        setChromeVisible(m_hwndMonacoContainer, SW_HIDE);
        setChromeVisible(m_hwndAnnotationOverlay, SW_HIDE);
        setChromeVisible(m_hwndProblemsListView, SW_HIDE);
        setChromeVisible(m_hwndSearchInput, SW_HIDE);
        setChromeVisible(m_hwndSearchResults, SW_HIDE);
        setChromeVisible(m_hwndSearchOptions, SW_HIDE);
        setChromeVisible(m_hwndSearchReplace, SW_HIDE);
        setChromeVisible(m_hwndSearchInclude, SW_HIDE);
        setChromeVisible(m_hwndSearchExclude, SW_HIDE);
        setChromeVisible(m_hwndSearchStatus, SW_HIDE);
        for (auto& kv : m_outputWindows)
            setChromeVisible(kv.second, SW_HIDE);
        if (m_hwndMain) {
            SetWindowTextW(m_hwndMain, L"RawrXD ScreenPilot â€” Desktop Preview");
            RECT rc{};
            GetClientRect(m_hwndMain, &rc);
            if (m_hwndCommandHost && IsWindow(m_hwndCommandHost)) {
                SetWindowPos(m_hwndCommandHost, HWND_TOP, 0, 0, rc.right, rc.bottom,
                             SWP_SHOWWINDOW);
                layoutCommandSurface(rc.right, rc.bottom);
            }
        }
        return;
    }
    setChromeVisible(m_hwndCommandHost, SW_HIDE);
    setChromeVisible(m_hwndToolbar, SW_SHOW);
    setChromeVisible(m_hwndActivityBar, SW_SHOW);
    if (m_sidebarVisible)
        setChromeVisible(m_hwndSidebar, SW_SHOW);
    if (m_secondarySidebarVisible)
        setChromeVisible(m_hwndSecondarySidebar, SW_SHOW);
    setChromeVisible(m_hwndTabBar, SW_SHOW);
    setChromeVisible(m_hwndEditor, SW_SHOW);
    setChromeVisible(m_hwndStatusBar, SW_SHOW);
    if (m_outputPanelVisible)
        setChromeVisible(m_hwndOutputTabs, SW_SHOW);
    if (m_powerShellPanelVisible)
        setChromeVisible(m_hwndPowerShellPanel, SW_SHOW);
    if (m_settings.breadcrumbsEnabled)
        setChromeVisible(m_hwndBreadcrumbs, SW_SHOW);
    if (m_hwndLineNumbers && IsWindowVisible(m_hwndLineNumbers))
        setChromeVisible(m_hwndLineNumbers, SW_SHOW);
    if (m_minimapVisible)
        setChromeVisible(m_hwndMinimap, SW_SHOW);
    if (m_hwndMain) {
        SetWindowTextW(m_hwndMain, L"RawrXD IDE â€” Work Mode");
        RECT rc{};
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right, rc.bottom);
    }
}

void Win32IDE::enterCommandMode() {
    m_shellMode = AppShellMode::Command;
    bindCommandSessionFromWorkspace();
    refreshCommandContextBar();
    refreshCommandLeftRail();
    refreshCommandFooter();
    refreshCommandModelHub();
    refreshCommandActivityStrip();
    applyShellModeChrome();
    CommandEventJournal::instance().append(JournalEventType::ModeSwitch, "\"command_home\"");
}

void Win32IDE::enterWorkMode() {
    m_shellMode = AppShellMode::Work;
    if (!m_localServerRunning.load()) {
        try { startLocalServer(); } catch (...) {}
    }
    applyShellModeChrome();
    CommandEventJournal::instance().append(JournalEventType::ModeSwitch, "\"work_mode\"");
}

void Win32IDE::handleCommandStop() {
    if (m_agenticBridge)
        m_agenticBridge->StopAgentLoop();
    CommandBroker::instance().stopAgent();
    refreshCommandActivityStrip();
    appendCommandConversation("[System] Agent stop requested.");
}

void Win32IDE::handleCommandApprove() {
    const auto pending = CommandBroker::instance().pendingApprovals();
    if (pending.empty()) {
        if (m_currentPlan.status == PlanStatus::AwaitingApproval &&
            !m_currentPlan.steps.empty()) {
            appendCommandConversation("[System] Plan approved â€” executing...");
            executePlan();
            refreshCommandActivityStrip();
            return;
        }
        // Build edit transaction: Allow applies staged diffs
        agentAcceptAll();
        refreshAgentDiffDisplay();
        appendCommandConversation("[System] Applied staged Build edits (or nothing pending).");
        refreshCommandActivityStrip();
        return;
    }
    const std::string& id = pending.front().id;
    const std::string action = pending.front().action;
    if (CommandBroker::instance().resolveApproval(id, true)) {
        appendCommandConversation("[System] Approved: " + id + " (" + action + ")");
        if (m_currentPlan.status == PlanStatus::AwaitingApproval)
            executePlan();
        if (action.find("write") != std::string::npos || action.find("edit") != std::string::npos ||
            action == "write_file" || action == "replace_in_file") {
            agentAcceptAll();
            refreshAgentDiffDisplay();
        }
    }
    refreshCommandActivityStrip();
}

void Win32IDE::handleCommandDeny() {
    const auto pending = CommandBroker::instance().pendingApprovals();
    if (pending.empty()) {
        agentRejectAll();
        refreshAgentDiffDisplay();
        appendCommandConversation("[System] Rejected staged Build edits (or nothing pending).");
        refreshCommandActivityStrip();
        return;
    }
    const std::string& id = pending.front().id;
    if (CommandBroker::instance().resolveApproval(id, false)) {
        appendCommandConversation("[System] Denied: " + id + " (" + pending.front().action + ")");
        agentRejectAll();
        refreshAgentDiffDisplay();
    }
    refreshCommandActivityStrip();
}

void Win32IDE::resumeCommandJournal() {
    std::string summary;
    if (!CommandEventJournal::instance().resumeFromLast(&summary)) return;
    const uint64_t seq = CommandEventJournal::instance().lastSeq();
    appendCommandOutput("[Journal] Resumed " + std::to_string(seq) + " event(s) from disk.");
    appendCommandConversation("[Journal] Resumed " + std::to_string(seq) + " event(s) from disk.");
}

void Win32IDE::handleCommandSend(HWND cmdHostHint) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_Witness("P1PRA_SEND", "handle_enter");
#endif
    HWND host = (cmdHostHint && IsWindow(cmdHostHint)) ? cmdHostHint : nullptr;
    if (!host && m_hwndCommandHost && IsWindow(m_hwndCommandHost))
        host = m_hwndCommandHost;
    HWND composer = nullptr;
    if (host && IsWindow(host))
        composer = GetDlgItem(host, IDC_CMD_COMPOSER_INPUT);
    if ((!composer || !IsWindow(composer)) && m_hwndCommandComposer &&
        IsWindow(m_hwndCommandComposer))
        composer = m_hwndCommandComposer;
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_Witness("P1PRA_SEND", "hwnd_check");
#endif
    if (!composer || !IsWindow(composer)) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        P1PRA_Witness("P1PRA_SEND", "no_composer");
#endif
        return;
    }
    m_hwndCommandComposer = composer;
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_Witness("P1PRA_SEND", "prompt_read_begin");
#endif
    wchar_t buf[8192] = {};
    GetWindowTextW(composer, buf, 8191);
    const std::string msg = RawrXD::WideToUtf8(std::wstring(buf));
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_Witness("P1PRA_SEND", "prompt_read_ok");
#endif
    if (msg.empty()) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        P1PRA_Witness("P1PRA_SEND", "empty_composer");
#endif
        return;
    }

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_Witness("P1PRA_SEND", "p1pra_begin");
    P1PRA_OnAcceptedUserPrompt(msg.data(), msg.size());
    P1PRA_Witness("P1PRA_SEND", "p1pra_ok");
    P1PRA_Witness("P1PRA_SEND", "accepted");
    {
        std::lock_guard<std::mutex> infLock(m_inferenceMutex);
        if (m_inferenceRunning.load(std::memory_order_acquire)) {
            m_inferenceStopRequested = true;
            m_inferenceRunning.store(false, std::memory_order_release);
            P1PRA_Witness("P1PRA_INFERENCE", "send_preempt");
            P1PRA_AgentDbg("H6", "handleCommandSend", "send_preempt", 1u,
                           static_cast<unsigned long>(GetCurrentThreadId()), 0);
        }
    }
#endif

    if (m_hwndCmdModeCombo && IsWindow(m_hwndCmdModeCombo)) {
        const int modeSel = (int)SendMessageW(m_hwndCmdModeCombo, CB_GETCURSEL, 0, 0);
        using SM = RawrXD::Command::SteerMode;
        const SM mode = modeSel == 0 ? SM::Plan : (modeSel == 1 ? SM::Build : SM::Agent);
        CommandBroker::instance().setSteerMode(mode);
        // Keep Work-mode AgenticMode in sync with ScreenPilot steering.
        if (mode == SM::Plan)
            setAgenticMode(RawrXD::AgenticMode::Plan);
        else if (mode == SM::Agent)
            setAgenticMode(RawrXD::AgenticMode::Agent);
        else
            setAgenticMode(RawrXD::AgenticMode::Ask); // Build maps to Ask+implement lane
    }
    appendCommandConversation("[You] " + msg);
    SetWindowTextW(m_hwndCommandComposer, L"");
#ifdef RAWRXD_PRODUCT100
    if (msg == "/git status" || msg == "/git-status") {
        product100GitStatus();
        return;
    }
    if (msg == "/git diff" || msg == "/git-diff") {
        product100GitDiff();
        return;
    }
    if (msg.rfind("/search ", 0) == 0) {
        product100SearchLiteral(msg.substr(8));
        return;
    }
#endif
    if (msg == "/approve" || msg == "/approve-test") {
        if (m_currentPlan.status == PlanStatus::AwaitingApproval &&
            !m_currentPlan.steps.empty()) {
            appendCommandConversation("[System] Executing approved plan...");
            executePlan();
            refreshCommandActivityStrip();
            return;
        }
        if (msg == "/approve-test") {
            const auto r = CommandBroker::instance().requestApproval(
                "git_write", "synthetic git commit approval test", RawrXD::Command::CapCommit);
            appendCommandConversation(r.text);
            refreshCommandActivityStrip();
            return;
        }
        appendCommandConversation("[System] No plan awaiting approval. Use Plan mode first.");
        return;
    }
    if (msg.find("git commit") != std::string::npos ||
        msg.find("git push") != std::string::npos) {
        const auto cap = msg.find("git push") != std::string::npos
                             ? RawrXD::Command::CapPush
                             : RawrXD::Command::CapCommit;
        const auto r = CommandBroker::instance().requestApproval("git_write", msg, cap);
        if (r.needsApproval) {
            appendCommandConversation(r.text);
            refreshCommandActivityStrip();
            return;
        }
    }
    const auto r = CommandBroker::instance().steer(msg);
    if (!r.ok && !r.text.empty()) appendCommandConversation(r.text);
    refreshCommandActivityStrip();
}

void Win32IDE::createCommandSurface(HWND parent) {
    if (m_hwndCommandHost && IsWindow(m_hwndCommandHost)) return;
    if (!m_cmdBgBrush) m_cmdBgBrush = CreateSolidBrush(RGB(9, 9, 11));
    if (!m_cmdPanelBrush) m_cmdPanelBrush = CreateSolidBrush(kSpPanel);
    if (!m_cmdUIFont) {
        m_cmdUIFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }
    m_hwndCommandHost = CreateWindowExW(0, L"STATIC", nullptr, WS_CHILD | WS_VISIBLE,
                                        0, 0, 100, 100, parent, nullptr, m_hInstance, nullptr);
    SetPropW(m_hwndCommandHost, L"IDE_PTR", (HANDLE)this);
    SetWindowLongPtrW(m_hwndCommandHost, GWLP_WNDPROC, (LONG_PTR)CommandHostProc);
    auto mk = [&](DWORD style, LPCWSTR cls, LPCWSTR text, int id, HWND par) {
        return CreateWindowExW(0, cls, text, style, 0, 0, 10, 10, par,
                               (HMENU)(INT_PTR)id, m_hInstance, nullptr);
    };
    m_hwndCommandLeftRail = mk(WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY, L"LISTBOX",
                               L"", IDC_CMD_WORKSPACE_LIST, m_hwndCommandHost);
    m_hwndTopContextBar = mk(WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS | SS_NOPREFIX,
                             L"STATIC",
                             L"RawrXD ScreenPilot  |  This PC  |  workspace  |  main", 0,
                             m_hwndCommandHost);
    m_hwndCommandConversation = mk(WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                       ES_READONLY | ES_AUTOVSCROLL | ES_WANTRETURN | WS_BORDER,
                                   L"EDIT", L"", IDC_CMD_CONVERSATION, m_hwndCommandHost);
    m_hwndCommandOutputHdr = mk(WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, L"STATIC",
                                L"Output", IDC_CMD_OUTPUT_HDR, m_hwndCommandHost);
    m_hwndCommandOutput = mk(WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                 ES_READONLY | ES_AUTOVSCROLL | WS_BORDER,
                             L"EDIT", L"", IDC_CMD_OUTPUT, m_hwndCommandHost);
    m_hwndSteeringBelt = mk(WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, L"STATIC",
                            L"Remote steering â€” Coming next (EGRESS_001 open)\r\n"
                            L"Local GUI: http://127.0.0.1:11435/gui  Â·  LOCAL_ONLY_001",
                            IDC_CMD_STEERING_BELT, m_hwndCommandHost);
    m_hwndModelHubHdr = mk(WS_CHILD | WS_VISIBLE | SS_LEFT, L"STATIC",
                           L"Engine control surface", IDC_CMD_MODEL_HUB_HDR, m_hwndCommandHost);
    m_hwndModelRecList = mk(WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY, L"LISTBOX", L"",
                            IDC_CMD_MODEL_REC_LIST, m_hwndCommandHost);
    m_hwndModelLocalList = mk(WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY, L"LISTBOX", L"",
                              IDC_CMD_MODEL_LOCAL_LIST, m_hwndCommandHost);
    mk(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, L"BUTTON", L"Load selected",
       IDC_CMD_MODEL_LOAD_BTN, m_hwndCommandHost);
    mk(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, L"BUTTON", L"Browse .gguf",
       IDC_CMD_MODEL_BROWSE_BTN, m_hwndCommandHost);
    mk(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, L"BUTTON", L"Unload",
       IDC_CMD_MODEL_UNLOAD_BTN, m_hwndCommandHost);
    mk(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, L"BUTTON", L"Reload",
       IDC_CMD_MODEL_RELOAD_BTN, m_hwndCommandHost);
    mk(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, L"BUTTON", L"Cancel",
       IDC_CMD_MODEL_CANCEL_BTN, m_hwndCommandHost);
    m_hwndModelHubStatus = mk(WS_CHILD | WS_VISIBLE | SS_LEFT, L"STATIC", L"",
                              IDC_CMD_MODEL_HUB_STATUS, m_hwndCommandHost);
    m_hwndActivityStrip = mk(WS_CHILD | WS_VISIBLE | SS_LEFT, L"STATIC", L"", 0,
                             m_hwndCommandHost);
    m_hwndActivityStripText = mk(WS_CHILD | WS_VISIBLE | SS_LEFT, L"STATIC",
                                 L"RawrXD Agent idle", IDC_CMD_ACTIVITY_TEXT,
                                 m_hwndActivityStrip);
    mk(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, L"BUTTON", L"Stop agent", IDC_CMD_STOP_BTN,
       m_hwndActivityStrip);
    mk(WS_CHILD | BS_PUSHBUTTON, L"BUTTON", L"Allow", IDC_CMD_APPROVE_BTN, m_hwndActivityStrip);
    mk(WS_CHILD | BS_PUSHBUTTON, L"BUTTON", L"Deny", IDC_CMD_DENY_BTN, m_hwndActivityStrip);
    m_hwndCmdApprovalBadge = mk(WS_CHILD | SS_LEFT, L"STATIC", L"", IDC_CMD_APPROVAL_BADGE,
                                m_hwndActivityStrip);
    m_hwndCommandComposer = mk(WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_BORDER | ES_AUTOVSCROLL,
                               L"EDIT", L"", IDC_CMD_COMPOSER_INPUT, m_hwndCommandHost);
    m_hwndCmdModelCombo = mk(WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, L"COMBOBOX", L"",
                             IDC_CMD_MODEL_COMBO, m_hwndCommandHost);
    m_hwndCmdModeCombo = mk(WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, L"COMBOBOX", L"",
                            IDC_CMD_MODE_COMBO, m_hwndCommandHost);
    mk(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, L"BUTTON", L"Send", IDC_CMD_SEND_BTN,
       m_hwndCommandHost);
    mk(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, L"BUTTON", L"Open workspace editor (Ctrl+Shift+W)",
       IDC_CMD_WORK_MODE_BTN, m_hwndCommandHost);
    m_hwndCommandFooter = mk(WS_CHILD | WS_VISIBLE | SS_LEFT, L"STATIC",
                             L"Desktop Preview Â· local authority retained", 0, m_hwndCommandHost);
    SendMessageW(m_hwndCmdModelCombo, CB_ADDSTRING, 0, (LPARAM)L"Deep2 Local");
    SendMessageW(m_hwndCmdModelCombo, CB_SETCURSEL, 0, 0);
    SendMessageW(m_hwndCmdModeCombo, CB_ADDSTRING, 0, (LPARAM)L"Plan");
    SendMessageW(m_hwndCmdModeCombo, CB_ADDSTRING, 0, (LPARAM)L"Build");
    SendMessageW(m_hwndCmdModeCombo, CB_ADDSTRING, 0, (LPARAM)L"Agent");
    SendMessageW(m_hwndCmdModeCombo, CB_SETCURSEL, 2, 0);
    for (HWND h : {m_hwndCommandLeftRail, m_hwndTopContextBar, m_hwndCommandConversation,
                   m_hwndCommandOutputHdr, m_hwndCommandOutput,
                   m_hwndSteeringBelt, m_hwndModelHubHdr, m_hwndModelRecList,
                   m_hwndModelLocalList, m_hwndModelHubStatus, m_hwndActivityStrip,
                   m_hwndActivityStripText, m_hwndCommandComposer, m_hwndCommandFooter,
                   m_hwndCmdModelCombo, m_hwndCmdModeCombo, m_hwndCmdApprovalBadge}) {
        styleChildFont(h, m_cmdUIFont);
    }
    const int btnIds[] = {IDC_CMD_MODEL_LOAD_BTN, IDC_CMD_MODEL_BROWSE_BTN,
                          IDC_CMD_MODEL_UNLOAD_BTN, IDC_CMD_MODEL_RELOAD_BTN,
                          IDC_CMD_MODEL_CANCEL_BTN, IDC_CMD_SEND_BTN,
                          IDC_CMD_WORK_MODE_BTN, IDC_CMD_STOP_BTN, IDC_CMD_APPROVE_BTN,
                          IDC_CMD_DENY_BTN};
    for (int id : btnIds) {
        HWND btn = GetDlgItem(m_hwndCommandHost, id);
        if (!btn && m_hwndActivityStrip)
            btn = GetDlgItem(m_hwndActivityStrip, id);
        styleChildFont(btn, m_cmdUIFont);
    }
    appendCommandOutput(
        "RawrXD ScreenPilot - Desktop Preview\n"
        "Your machine. Your models. Your agents. Any screen.\n"
        "Pick Plan / Build / Agent above the composer (Cursor-style steering).\n"
        "Ctrl+Shift+W - open full workspace IDE  |  Ctrl+Shift+1 - return here\n"
        "Local Deep2/GGUF lane active. Remote steering ships after EGRESS_001.\n");
    appendCommandConversation(
        "RawrXD ScreenPilot - Desktop Preview\n"
        "Pick Plan / Build / Agent above the composer.\n");
    bindCommandSessionFromWorkspace();
    refreshCommandLeftRail();
    refreshCommandContextBar();
    refreshCommandFooter();
    refreshCommandModelHub();
    rawrxd::InitGpuPowerProbeMainThread();
    RawrXD::Agent::AgentToolHandlers::SetIdeTerminalRunner(
        [this](const std::string& cmd) { runAgentCommandInTerminal(cmd); });
    RawrXD::Agent::AgentToolHandlers::SetStageEditHandler(
        [this](const std::string& path, const std::string& content) {
            return stageCommandBuildEdit(path, content);
        });
#ifdef RAWRXD_PRODUCT100
    product100Init();
#endif
    CommandBroker::instance().setSteerHandler([this](const std::string& msg,
                                                     RawrXD::Command::SteerMode mode) {
        const bool bridgeReady =
            m_agenticBridge && !getLoadedModelPath().empty();
        const bool nativeReady = m_nativeEngineLoaded && m_nativeEngine;
        if (!bridgeReady && !nativeReady) {
            appendCommandConversation(
                "LOCAL_ONLY_001: Load a local GGUF model for Deep2 inference "
                "(Engine control â†’ Load selected or Browse .gguf).\n");
            CommandBroker::instance().setAgentActive(false);
            CommandBroker::instance().setActivityStatus("Awaiting local model");
            refreshCommandActivityStrip();
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
            if (P1PRA_RequestActive()) {
                const char* modeLabel =
                    mode == RawrXD::Command::SteerMode::Plan ? "Plan"
                    : mode == RawrXD::Command::SteerMode::Build ? "Build" : "Agent";
                p1praCompleteProductRequest(modeLabel, false);
            }
#endif
            return;
        }

        const char* steerLabel =
            mode == RawrXD::Command::SteerMode::Plan ? "Plan"
            : mode == RawrXD::Command::SteerMode::Build ? "Build" : "Agent";
#ifdef RAWRXD_TOKEN_PRESSURE_VALVE
        if (mode == RawrXD::Command::SteerMode::Plan)
            token_pressure::SetSpray(token_pressure::SprayMode::Needle);
        else if (mode == RawrXD::Command::SteerMode::Build)
            token_pressure::SetSpray(token_pressure::SprayMode::RepairJet);
        else
            token_pressure::SetSpray(token_pressure::SprayMode::Pulse);
#endif
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        p1praAdvanceRequestProductPath();
#endif

        const std::string ctxPrompt = assembleCommandInferenceContext(msg);
        m_lastCopilotUserPrompt = msg;
        m_chatHistory.push_back({"user", msg});

        // -------- PLAN: structured checklist â†’ approval dialog --------
        if (mode == RawrXD::Command::SteerMode::Plan) {
            appendCommandConversation(
                "[Plan] Decomposing goal into steps (approve to execute)...\n");
            CommandBroker::instance().setActivityStatus("Plan â€” generating");
            refreshCommandActivityStrip();
            generateAgentPlan(ctxPrompt);
            return;
        }

        // -------- BUILD: implement with CapEdit + tool protocol --------
        if (mode == RawrXD::Command::SteerMode::Build) {
            appendCommandConversation("[Build] ", false);
            if (m_agenticBridge) {
                m_agenticBridge->SetHotpatchSubAgentToolProtocol(true);
                m_agenticBridge->SetAutoCorrect(true);
            }
            const std::string buildPrompt =
                "[ScreenPilot Build mode] Implement the requested changes in the "
                "workspace. Prefer concrete file edits and verification. Pause for "
                "approval before git commit/push or destructive ops.\n\n" +
                ctxPrompt;
            auto streamSaw = std::make_shared<bool>(false);
            generateResponseAsync(buildPrompt, [this, streamSaw](const std::string& token, bool complete) {
                if (!token.empty()) {
                    *streamSaw = true;
                    appendCommandConversationStream(token);
                }
                if (complete) {
                    if (*streamSaw) {
                        appendCommandConversationStream("\n\n");
                        if (m_agenticBridge && !m_currentInferenceResponse.empty()) {
                            std::string toolResult;
                            m_agenticBridge->DispatchModelToolCalls(
                                m_currentInferenceResponse, toolResult);
                            if (!toolResult.empty())
                                appendCommandConversation("[Tools]\n" + toolResult);
                        }
                    }
                    CommandBroker::instance().setAgentActive(false);
                    CommandBroker::instance().setActivityStatus("RawrXD Agent idle");
                    refreshCommandActivityStrip();
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                    p1praCompleteProductRequest("Build",
                                                P1PRA_RealProductRequestPass(*streamSaw));
#endif
                }
            });
            return;
        }

        // -------- AGENT: multi-turn StartAgentLoop with tools --------
        appendCommandConversation("[Agent] ", false);
        if (m_agenticBridge) {
            m_agenticBridge->SetHotpatchSubAgentToolProtocol(true);
            m_agenticBridge->SetAutoCorrect(true);
            auto streamSaw = std::make_shared<bool>(false);
            m_agenticBridge->SetOutputCallback(
                [this, streamSaw](const std::string& title, const std::string& content) {
                    if (!title.empty())
                        appendCommandConversation("\n[" + title + "]\n");
                    if (!content.empty()) {
                        *streamSaw = true;
                        appendCommandConversationStream(content);
                    }
                });
            CommandBroker::instance().setActivityStatus("Agent â€” autonomous loop");
            refreshCommandActivityStrip();
            std::thread([this, ctxPrompt, streamSaw]() {
                DetachedThreadGuard _guard(m_activeDetachedThreads, m_shuttingDown);
                if (_guard.cancelled) {
                    CommandBroker::instance().setAgentActive(false);
                    return;
                }
                const bool ok = m_agenticBridge->StartAgentLoop(ctxPrompt, 8);
                if (m_hwndMain && IsWindow(m_hwndMain)) {
                    PostMessageW(m_hwndMain, WM_APP, 0, 0); // wake UI
                }
                appendCommandConversation(ok
                    ? "\n[Agent] Loop complete.\n\n"
                    : "\n[Agent] Loop failed or not initialized.\n\n");
                CommandBroker::instance().setAgentActive(false);
                CommandBroker::instance().setActivityStatus("RawrXD Agent idle");
                refreshCommandActivityStrip();
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                p1praCompleteProductRequest("Agent", P1PRA_RealProductRequestPass(*streamSaw));
#endif
            }).detach();
            return;
        }

        // Fallback single-turn if bridge missing but native ready
        {
            auto streamSaw = std::make_shared<bool>(false);
            generateResponseAsync(ctxPrompt, [this, streamSaw](const std::string& token, bool complete) {
                if (!token.empty()) {
                    *streamSaw = true;
                    appendCommandConversationStream(token);
                }
                if (complete) {
                    appendCommandConversationStream("\n\n");
                    CommandBroker::instance().setAgentActive(false);
                    CommandBroker::instance().setActivityStatus("RawrXD Agent idle");
                    refreshCommandActivityStrip();
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                    p1praCompleteProductRequest("Agent", P1PRA_RealProductRequestPass(*streamSaw));
#endif
                }
            });
        }
    });
    CommandBroker::instance().setStopHandler([this]() {
        m_inferenceStopRequested = true;
        if (m_agenticBridge)
            m_agenticBridge->StopAgentLoop();
        shutdownInference();
        stopTerminal();
        CommandBroker::instance().setAgentActive(false);
    });
    (void)RawrXD::Command::controlChannel();
    resumeCommandJournal();
    enterCommandMode();
}
