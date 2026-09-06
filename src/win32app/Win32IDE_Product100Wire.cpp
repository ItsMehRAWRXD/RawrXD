// Win32IDE_Product100Wire.cpp — thin host glue for Product100 overlay.
#include "Win32IDE.h"
#include "RawrXD_Product100.hpp"
#include "Win32Utf8.hpp"
#include "../command/CommandBroker.h"

#include <filesystem>
#include <string>

#ifdef RAWRXD_PRODUCT100

void __stdcall Win32IDE::product100TextSink(const wchar_t* channel, const wchar_t* text, void* user)
{
    auto* ide = static_cast<Win32IDE*>(user);
    if (!ide || !text) return;
    std::string line = RawrXD::WideToUtf8(std::wstring(text));
    if (channel && channel[0])
        line = std::string("[") + RawrXD::WideToUtf8(std::wstring(channel)) + "] " + line;
    ide->appendCommandConversation(line);
    ide->appendCommandOutput(line);
}

static std::wstring widenPath(const std::string& s)
{
    return s.empty() ? std::wstring() : RawrXD::Utf8ToWide(s);
}

void Win32IDE::product100Init()
{
    P100_Context ctx = {};
    ctx.size = sizeof(ctx);
    const std::string ws = m_gitRepoPath.empty()
                               ? std::filesystem::current_path().string()
                               : m_gitRepoPath;
    wcsncpy_s(ctx.workspace, widenPath(ws).c_str(), _TRUNCATE);
    wcsncpy_s(ctx.evidence_dir, L"evidence\\IDE_PRODUCT_FINISH_BATCH_085", _TRUNCATE);
    ctx.capabilities =
        P100_CAP_READ | P100_CAP_SEARCH | P100_CAP_EDIT | P100_CAP_COMMAND |
        P100_CAP_GIT_READ | P100_CAP_GIT_WRITE | P100_CAP_SETTINGS |
        P100_CAP_PERSISTENCE | P100_CAP_TERMINAL;
    ctx.sink = &Win32IDE::product100TextSink;
    ctx.sink_user = this;
    if (P100_Init(&ctx) != P100_OK) {
        appendCommandConversation("[P100] init HOLD — see DescribeError.");
        return;
    }
    appendCommandOutput("[P100] Waves 3-4 APIs initialized (source-applied; not live-certified).");
    appendCommandConversation("[P100] Waves 3-4 APIs initialized (source-applied; not live-certified).");

    P100_SessionV1 session = {};
    session.size = sizeof(session);
    if (P100_LoadSession(&session) == P100_OK && session.model_path[0]) {
        const std::string saved = std::string("[P100] Saved model: ") +
                                  RawrXD::WideToUtf8(std::wstring(session.model_path));
        appendCommandOutput(saved);
        appendCommandConversation(saved);
    }

    P100_SettingsV1 settings = {};
    settings.size = sizeof(settings);
    if (P100_LoadSettings(&settings) == P100_OK) {
        if (settings.context_tokens > 0)
            m_inferenceConfig.contextWindow = static_cast<int>(settings.context_tokens);
        if (settings.temperature >= 0.0f)
            m_inferenceConfig.temperature = settings.temperature;
    }
}

void Win32IDE::product100Shutdown()
{
    P100_SessionV1 session = {};
    session.size = sizeof(session);
    const std::string ws = m_gitRepoPath.empty()
                               ? std::filesystem::current_path().string()
                               : m_gitRepoPath;
    wcsncpy_s(session.workspace, widenPath(ws).c_str(), _TRUNCATE);
    wcsncpy_s(session.model_path, widenPath(getLoadedModelPath()).c_str(), _TRUNCATE);
    const char* modeLabel = RawrXD::Command::CommandBroker::steerModeLabel(
        RawrXD::Command::CommandBroker::instance().steerMode());
    wcsncpy_s(session.mode, widenPath(modeLabel ? modeLabel : "Agent").c_str(), _TRUNCATE);
    (void)P100_SaveSession(&session);

    P100_SettingsV1 settings = {};
    settings.size = sizeof(settings);
    wcsncpy_s(settings.model_path, widenPath(getLoadedModelPath()).c_str(), _TRUNCATE);
    settings.context_tokens = static_cast<uint32_t>(m_inferenceConfig.contextWindow);
    settings.temperature = m_inferenceConfig.temperature;
    (void)P100_SaveSettings(&settings);
    P100_Shutdown();
}

void Win32IDE::product100GitStatus()
{
    wchar_t out[P100_TEXT_CCH] = {};
    P100_RunResult rr = {};
    if (P100_GitStatus(out, P100_TEXT_CCH, &rr) != P100_OK) {
        wchar_t err[512] = {};
        P100_DescribeError(P100_E_PROCESS_FAILED, L"git status", err, 512);
        appendCommandConversation(std::string("[P100/Git] ") + RawrXD::WideToUtf8(std::wstring(err)));
        return;
    }
    appendCommandConversation(std::string("[P100/Git status]\n") + RawrXD::WideToUtf8(std::wstring(out)));
}

void Win32IDE::product100GitDiff()
{
    wchar_t out[P100_TEXT_CCH] = {};
    P100_RunResult rr = {};
    if (P100_GitDiff(out, P100_TEXT_CCH, &rr) != P100_OK) {
        wchar_t err[512] = {};
        P100_DescribeError(P100_E_PROCESS_FAILED, L"git diff", err, 512);
        appendCommandConversation(std::string("[P100/Git] ") + RawrXD::WideToUtf8(std::wstring(err)));
        return;
    }
    appendCommandConversation(std::string("[P100/Git diff]\n") + RawrXD::WideToUtf8(std::wstring(out)));
}

void Win32IDE::product100SearchLiteral(const std::string& query)
{
    struct Hits { Win32IDE* ide; int n; } hits{this, 0};
    struct Sink {
        static int32_t P100_CALL Fn(const P100_SearchHit* hit, void* user) {
            auto* h = static_cast<Hits*>(user);
            if (!hit || !h || !h->ide) return 0;
            ++h->n;
            h->ide->appendCommandConversation(
                std::string("[Search] ") + RawrXD::WideToUtf8(std::wstring(hit->path)) + ":" +
                std::to_string(hit->line) + "  " +
                RawrXD::WideToUtf8(std::wstring(hit->preview)));
            return 1;
        }
    };
    if (P100_SearchWorkspaceLiteral(widenPath(query).c_str(), 1, 64, &Sink::Fn, &hits) != P100_OK) {
        wchar_t err[512] = {};
        P100_DescribeError(P100_E_IO, L"search", err, 512);
        appendCommandConversation(std::string("[P100/Search] ") + RawrXD::WideToUtf8(std::wstring(err)));
        return;
    }
    appendCommandConversation("[P100/Search] hits=" + std::to_string(hits.n));
}

std::string Win32IDE::product100DescribeError(int code, const std::string& detail)
{
    wchar_t out[1024] = {};
    P100_DescribeError(static_cast<int32_t>(code), widenPath(detail).c_str(), out, 1024);
    return RawrXD::WideToUtf8(std::wstring(out));
}

#endif  // RAWRXD_PRODUCT100
