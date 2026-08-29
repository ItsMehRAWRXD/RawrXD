// ============================================================================
// Win32IDE_HexMagCopilotRoute.cpp — F control-plane dependency (not HexMag UI)
// ============================================================================
// HandleCopilotSend → HexMagRuntimeController → FinalizePolicy → F render path
// IDE does NOT own retry / generation / NEED_INPUT / FINAL authorization.
// ============================================================================
#include "Win32IDE.h"
#include "Win32IDE_HexMagMessages.h"
#include "core/hexmag_runtime_controller.hpp"
#include "agent/hexmag_client.hpp"

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <thread>

namespace {

enum class HexMagCopilotStatus : uint8_t {
    Final = 1,
    NeedInput = 2,
    Failed = 3,
};

struct HexMagCopilotDonePayload {
    HexMagCopilotStatus status = HexMagCopilotStatus::Failed;
    std::string text;
};

void setHexMagRunningHint(Win32IDE* ide)
{
    if (!ide)
        return;
    HWND sb = ide->getStatusBar();
    if (sb && IsWindow(sb))
        SendMessageW(sb, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(L"HexMag: running…"));
}

void setHexMagResultHint(Win32IDE* ide, HexMagCopilotStatus st)
{
    if (!ide)
        return;
    HWND sb = ide->getStatusBar();
    if (!sb || !IsWindow(sb))
        return;
    const wchar_t* tip = L"HexMag: failure";
    if (st == HexMagCopilotStatus::Final)
        tip = L"HexMag: FINAL";
    else if (st == HexMagCopilotStatus::NeedInput)
        tip = L"HexMag: NEED_INPUT";
    SendMessageW(sb, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(tip));
}

} // namespace

void RawrXD_FinishHexMagCopilotDone(void* idePtr, LPARAM lParam)
{
    auto* ide = static_cast<Win32IDE*>(idePtr);
    std::unique_ptr<HexMagCopilotDonePayload> p(
        reinterpret_cast<HexMagCopilotDonePayload*>(lParam));
    if (!ide || !p)
        return;

    std::string line;
    switch (p->status) {
    case HexMagCopilotStatus::Final:
        line = p->text;
        ide->appendToOutput("[HexMag] FINAL → Copilot render\n", "Agent",
                            Win32IDE::OutputSeverity::Info);
        break;
    case HexMagCopilotStatus::NeedInput:
        line = std::string("[NEED_INPUT] ") + p->text;
        ide->appendToOutput("[HexMag] NEED_INPUT (no FINAL)\n", "Agent",
                            Win32IDE::OutputSeverity::Warning);
        break;
    case HexMagCopilotStatus::Failed:
    default:
        line = std::string("[HexMag failure] ") + p->text;
        ide->appendToOutput("[HexMag] fail-closed: " + p->text + "\n", "Errors",
                            Win32IDE::OutputSeverity::Error);
        break;
    }

    if (!line.empty())
        ide->HandleCopilotStreamUpdate(line.c_str(), line.size());
    ide->HandleCopilotStreamUpdate("\n\n", 2);
    setHexMagResultHint(ide, p->status);
}

bool Win32IDE::tryHexMagControllerCopilotSend(const std::string& userMessage)
{
#ifndef RAWR_HAS_MASM
    (void)userMessage;
    return false;
#else
    if (userMessage.empty() || userMessage.front() == '/')
        return false;

    if (!m_settings.hexmagRouteCopilotPanel)
        return false;

    setHexMagRunningHint(this);
    appendToOutput("[HexMag] IDE SEND → RuntimeController\n", "Agent",
                   OutputSeverity::Info);

    HWND hwndMain = m_hwndMain;
    std::string context;
    if (!m_currentFile.empty() && m_hwndEditor) {
        context = getWindowText(m_hwndEditor);
        if (context.size() > 800)
            context.resize(800);
    }

    std::thread([hwndMain, userMessage, context]() {
        using namespace RawrXD::HexMag;
        auto* payload = new HexMagCopilotDonePayload();

        try {
            LiveHexMagTransport transport;
            HexMagRuntimeController controller(&transport, ControllerConfig{0});
            controller.resetSession();
            const ControllerResult r = controller.run(userMessage, context);

            if (r.needInputLatched || r.fail == ControllerFail::NeedInput) {
                payload->status = HexMagCopilotStatus::NeedInput;
                payload->text = !r.lastClient.ask.error.empty()
                    ? r.lastClient.ask.error
                    : (r.diagnostic.empty() ? "INSUFFICIENT_INFORMATION"
                                            : r.diagnostic);
            } else if (r.finalAuthority && r.finalize.allowed) {
                payload->status = HexMagCopilotStatus::Final;
                payload->text = !r.lastClient.ask.answer.empty()
                    ? r.lastClient.ask.answer
                    : (!r.lastClient.ask.selectedCandidate.empty()
                           ? r.lastClient.ask.selectedCandidate
                           : r.diagnostic);
                if (payload->text.empty())
                    payload->text = "goal.satisfied";
            } else {
                payload->status = HexMagCopilotStatus::Failed;
                payload->text = r.diagnostic.empty()
                    ? (r.lastClient.ask.error.empty()
                           ? "HexMag controller failed (no FINAL)"
                           : r.lastClient.ask.error)
                    : r.diagnostic;
            }
        } catch (const std::exception& ex) {
            payload->status = HexMagCopilotStatus::Failed;
            payload->text = std::string("controller_exception: ") + ex.what();
        } catch (...) {
            payload->status = HexMagCopilotStatus::Failed;
            payload->text = "controller_exception: unknown";
        }

        if (!hwndMain ||
            !IsWindow(hwndMain) ||
            !PostMessageW(hwndMain,
                          WM_HEXMAG_COPILOT_DONE,
                          0,
                          reinterpret_cast<LPARAM>(payload))) {
            delete payload;
        }
    }).detach();

    return true;
#endif
}

bool Win32IDE::handleHexMagCommand(unsigned) { return false; }
void Win32IDE::setHexMagStatusBarHint(const std::wstring& text) {
    if (m_hwndStatusBar && IsWindow(m_hwndStatusBar))
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(text.c_str()));
}
void Win32IDE::setHexMagStatusBarHint(const std::string& text) {
    if (text.empty()) { setHexMagStatusBarHint(std::wstring()); return; }
    const int n = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    std::wstring w;
    if (n > 1) {
        w.assign(static_cast<size_t>(n - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, w.data(), n);
    }
    setHexMagStatusBarHint(w);
}
void Win32IDE::refreshHexMagAgentMenuChecks() {}
void Win32IDE::onHexMagStartService() {
    setHexMagStatusBarHint(L"HexMag: control plane via Copilot send");
    (void)RawrXD::HexMag::tryLaunchService();
}
void Win32IDE::onHexMagHealthCheck() {
    const bool ok = RawrXD::HexMag::healthCheck();
    setHexMagStatusBarHint(ok ? L"HexMag: healthy" : L"HexMag: offline");
}
void Win32IDE::onHexMagToggleGgufFallback() {
    m_settings.hexmagGgufFallbackEnabled = !m_settings.hexmagGgufFallbackEnabled;
}
void Win32IDE::onHexMagToggleRouteCopilotPanel() {
    m_settings.hexmagRouteCopilotPanel = !m_settings.hexmagRouteCopilotPanel;
    setHexMagStatusBarHint(m_settings.hexmagRouteCopilotPanel
        ? L"HexMag Copilot route: on"
        : L"HexMag Copilot route: off");
}
void Win32IDE::applyHexMagSwarmAgentCount(int count) {
    if (count < 1) count = 1;
    if (count > 8) count = 8;
    m_settings.hexmagSwarmAgentCount = count;
    RawrXD::HexMag::setSwarmAgentCount(static_cast<uint32_t>(count));
}
void Win32IDE::onHexMagCycleSwarmSize() {
    applyHexMagSwarmAgentCount(m_settings.hexmagSwarmAgentCount >= 8
        ? 1 : m_settings.hexmagSwarmAgentCount + 1);
}
void Win32IDE::onHexMagSetSwarmSizeFromCmd(unsigned) {}
void Win32IDE::appendHexMagTelemetryText(const std::wstring&) {}
void Win32IDE::ensureHexMagTelemetryTab() {}
void Win32IDE::showHexMagTelemetryPanel() {}
void Win32IDE::clearHexMagTelemetryPanel() {}
void Win32IDE::onHexMagShowTelemetryPanel() {}
void Win32IDE::onHexMagStartAgentTelemetryStream() {}
void Win32IDE::appendCopilotChatTextOnUiThread(const std::string& text) {
    if (!text.empty())
        HandleCopilotStreamUpdate(text.c_str(), text.size());
}
void Win32IDE::setCopilotInteractionBusyOnUiThread(bool busy) {
    if (m_hwndCopilotSendBtn && IsWindow(m_hwndCopilotSendBtn))
        EnableWindow(m_hwndCopilotSendBtn, busy ? FALSE : TRUE);
    if (m_hwndCopilotChatInput && IsWindow(m_hwndCopilotChatInput))
        EnableWindow(m_hwndCopilotChatInput, busy ? FALSE : TRUE);
}
void Win32IDE::showAgentActivityStatus(const std::string& text, int) {
    setHexMagStatusBarHint(text);
}
bool Win32IDE::tryDispatchCopilotThroughHexMag(const std::string& userMessage, unsigned long long) {
    return tryHexMagControllerCopilotSend(userMessage);
}
void Win32IDE::dispatchHexMagAskFromUi(const std::string& question, bool) {
    (void)tryHexMagControllerCopilotSend(question);
}
