// Win32IDE_StreamingUX.cpp — token streaming display and progress
#include <windows.h>
#include <string>
#include <atomic>
#include <functional>
#include <cstdio>

namespace RawrXD::IDE {

// Forward declarations
void ChatPanel_BeginStreaming();
void ChatPanel_AppendStreamToken(const std::string& token);
void ChatPanel_EndStreaming();

// ── Streaming state ───────────────────────────────────────────────────────────
static std::atomic<bool> g_streamActive{false};
static std::atomic<bool> g_streamCancelled{false};
static HWND              g_statusBar = nullptr;
static uint64_t          g_tokenCount = 0;
static std::function<void()> g_onComplete;

void StreamingUX_SetStatusBar(HWND hBar) { g_statusBar = hBar; }

void StreamingUX_Begin(const std::string& /*modelName*/)
{
    g_streamActive.store(true);
    g_streamCancelled.store(false);
    g_tokenCount = 0;
    ChatPanel_BeginStreaming();
    if (g_statusBar)
        SetWindowTextA(g_statusBar, "Generating...");
}

void StreamingUX_Token(const std::string& token)
{
    if (g_streamCancelled.load()) return;
    ++g_tokenCount;
    ChatPanel_AppendStreamToken(token);
    if (g_statusBar && (g_tokenCount % 10 == 0)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Generating... %llu tokens", (unsigned long long)g_tokenCount);
        SetWindowTextA(g_statusBar, buf);
    }
}

void StreamingUX_End()
{
    g_streamActive.store(false);
    ChatPanel_EndStreaming();
    if (g_statusBar) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Done — %llu tokens", (unsigned long long)g_tokenCount);
        SetWindowTextA(g_statusBar, buf);
    }
    if (g_onComplete) g_onComplete();
}

void StreamingUX_Cancel()
{
    g_streamCancelled.store(true);
    g_streamActive.store(false);
    ChatPanel_EndStreaming();
    if (g_statusBar) SetWindowTextA(g_statusBar, "Cancelled");
}

bool StreamingUX_IsActive()     { return g_streamActive.load(); }
bool StreamingUX_IsCancelled()  { return g_streamCancelled.load(); }

void StreamingUX_SetOnComplete(std::function<void()> cb) { g_onComplete = std::move(cb); }

} // namespace RawrXD::IDE
