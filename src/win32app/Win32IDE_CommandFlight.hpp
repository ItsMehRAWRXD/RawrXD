// Win32IDE_CommandFlight.hpp — P1_UI_MENU_COMMAND_FLIGHT_001
// Independent of status bar / UI text. Ring buffer + optional JSONL journal.
#pragma once

#include <windows.h>
#include <cstdint>

namespace RawrXD::CommandTelemetry {

enum class CommandFlightPhase : uint8_t {
    Received = 0,
    Resolved,
    HandlerEntered,
    EffectCommitted,
    Completed,
    Failed
};

struct CommandFlight {
    uint64_t sequence = 0;
    uint32_t rawId = 0;
    uint32_t logicalId = 0;
    HWND targetHwnd = nullptr;
    CommandFlightPhase phase = CommandFlightPhase::Received;
    bool resolved = false;
    bool handlerEntered = false;
    bool effectCommitted = false;
    uint64_t preGeneration = 0;
    uint64_t postGeneration = 0;
    int result = 0;
    LARGE_INTEGER beginQpc{};
    LARGE_INTEGER endQpc{};
    char logicalName[32] = {};
    char failReason[48] = {};
};

constexpr size_t kCommandFlightCapacity = 1024;
constexpr wchar_t kPropMainMenuReady[] = L"RawrXD.MainMenuReady";
#ifndef WM_APP_RUN_MENU_PROBE
#define WM_APP_RUN_MENU_PROBE (WM_APP + 321)
#endif

struct ProductGenerations {
    uint64_t documentGeneration = 0;
    uint64_t findGeneration = 0;
    uint64_t minimapGeneration = 0;
};

ProductGenerations& Generations();
uint64_t BumpDocumentGeneration();
uint64_t BumpFindGeneration();
uint64_t BumpMinimapGeneration();

CommandFlight& Begin(HWND hwnd, UINT rawId);
void Resolved(CommandFlight& flight, uint32_t logicalId, const char* logicalName);
void HandlerEntered(CommandFlight& flight);
void EffectCommitted(CommandFlight& flight, uint64_t generation);
void Fail(CommandFlight& flight, const char* reason);
void Finish(CommandFlight& flight, int result);

CommandFlight* Current();
CommandFlight* FindLatestByRawId(UINT rawId);
const CommandFlight* RingAt(size_t index);
size_t RingCount();

void SetJournalEnabled(bool enabled);
bool JournalEnabled();
void EnsureJournalPath();

void MarkMainMenuReady(HWND hwnd);
bool IsMainMenuReady(HWND hwnd);
void ClearMainMenuReady(HWND hwnd);

const char* LogicalNameForRawId(UINT rawId);
uint32_t LogicalIdForRawId(UINT rawId);

// P1_UI_MENU_E2E_001 — first-chance / SEH localization (does not reopen lifetime).
bool CmdDiagActive();
void CmdDiagMarkArmed();
void CmdDiagNoteMessage(unsigned msg, unsigned long long wParam, void* hwnd,
                        unsigned long long lParam);
void CmdDiagBreadcrumb(int cmdId, const char* step);
void CmdDiagException(int cmdId, unsigned long code, const void* addr,
                      const void* const* frames, unsigned frameCount,
                      const char* kind);

// IDE sender proof for SB_GETTEXTW — leave IDE_GETTEXT_INFLIGHT while SendMessage runs.
void CmdDiagIdeGetTextBegin(const char* tag, HWND hwnd, int part, const void* buf);
void CmdDiagIdeGetTextEnd(const char* tag);

struct CmdDiagIdeGetTextScope {
    const char* tag;
    CmdDiagIdeGetTextScope(const char* t, HWND hwnd, int part, const void* buf)
        : tag(t)
    {
        CmdDiagIdeGetTextBegin(t, hwnd, part, buf);
    }
    ~CmdDiagIdeGetTextScope() { CmdDiagIdeGetTextEnd(tag); }
    CmdDiagIdeGetTextScope(const CmdDiagIdeGetTextScope&) = delete;
    CmdDiagIdeGetTextScope& operator=(const CmdDiagIdeGetTextScope&) = delete;
};

}  // namespace RawrXD::CommandTelemetry
