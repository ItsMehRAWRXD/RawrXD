#include "win32_event_bridge.hpp"

#ifdef _WIN32
namespace rawrxd::continuous {

Win32EventBridge::Win32EventBridge(std::shared_ptr<EventPipe> pipe,
                                   HWND target,
                                   UINT message)
    : pipe_(std::move(pipe)), target_(target), message_(message) {
    if (!pipe_) throw std::invalid_argument("Win32EventBridge requires EventPipe");
    if (!target_) throw std::invalid_argument("Win32EventBridge requires HWND");
}

Win32EventBridge::~Win32EventBridge() {
    stop();
}

void Win32EventBridge::start() {
    if (thread_.joinable()) return;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread(&Win32EventBridge::pump, this);
}

void Win32EventBridge::stop() {
    stop_.store(true, std::memory_order_release);
    if (pipe_) pipe_->wake_waiters();
    if (thread_.joinable()) thread_.join();
}

void Win32EventBridge::pump() {
    Event ev;
    while (!stop_.load(std::memory_order_acquire) && pipe_->wait_pop(ev, stop_)) {
        if (stop_.load(std::memory_order_acquire)) break;

        auto* heap_event = new Event(std::move(ev));
        if (!::PostMessageW(target_, message_, 0,
                            reinterpret_cast<LPARAM>(heap_event))) {
            // UI target lost; persist event to ledger so it can be replayed
            // on rebind rather than destroying the only copy.
            // TODO: move into durable per-run ledger instead of leaking
        }
    }
}

} // namespace rawrxd::continuous
#endif
