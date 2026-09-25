#pragma once
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

#include "ContinuousExecution.hpp"
#include "ContinuousEventLedger.hpp"
#include <atomic>
#include <memory>
#include <thread>

namespace rawrxd::continuous {

#ifdef _WIN32

// Receives Event objects from EventPipe without polling or timers and transfers
// ownership to the Win32 UI thread through PostMessageW.
//
// lParam is Event*. The window procedure MUST delete it after handling.
// If the HWND becomes invalid, events are preserved in the authoritative ledger
// rather than destroyed. The model worker never waits on UI rendering.
class Win32EventBridge final {
public:
    static constexpr UINT kDefaultMessage = WM_APP + 0x2D2;

    Win32EventBridge(std::shared_ptr<EventPipe> pipe,
                     std::shared_ptr<EventLedger> ledger,
                     HWND target,
                     UINT message = kDefaultMessage);
    ~Win32EventBridge();

    Win32EventBridge(const Win32EventBridge&) = delete;
    Win32EventBridge& operator=(const Win32EventBridge&) = delete;

    void start();
    void stop();
    // Replay events from ledger that the UI may have missed
    void replaySince(uint64_t sequence, HWND target);

private:
    void pump();

    std::shared_ptr<EventPipe> pipe_;
    std::shared_ptr<EventLedger> ledger_;
    HWND target_{};
    UINT message_{};
    std::thread thread_;
    std::atomic<bool> stop_{false};
};

#endif

} // namespace rawrxd::continuous
