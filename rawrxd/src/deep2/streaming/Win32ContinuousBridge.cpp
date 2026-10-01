#include "Win32ContinuousBridge.hpp"

#ifdef _WIN32
namespace rawrxd::continuous {

Win32EventBridge::Win32EventBridge(std::shared_ptr<EventPipe> pipe,
                                   std::shared_ptr<EventLedger> ledger,
                                   HWND target,
                                   UINT message)
    : pipe_(std::move(pipe)), ledger_(std::move(ledger)), target_(target), message_(message) {
    if (!pipe_) throw std::invalid_argument("Win32EventBridge requires EventPipe");
    if (!ledger_) throw std::invalid_argument("Win32EventBridge requires EventLedger");
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

void Win32EventBridge::replaySince(uint64_t runId, uint64_t fromSequence, HWND target) {
    if (!ledger_ || !target) return;
    auto records = ledger_->replay(runId, fromSequence);
    for (auto& rec : records) {
        auto* heap_event = new Event();
        heap_event->run_id = rec.runId;
        heap_event->sequence = rec.sequence;
        heap_event->kind = rec.kind;
        heap_event->text = rec.payload;
        if (!::PostMessageW(target, message_, 0,
                            reinterpret_cast<LPARAM>(heap_event))) {
            // Keep in ledger; do not delete authoritative copy
        }
    }
}

void Win32EventBridge::pump() {
    Event ev;
    while (!stop_.load(std::memory_order_acquire) && pipe_->wait_pop(ev, stop_)) {
        if (stop_.load(std::memory_order_acquire)) break;

        // Authoritative commit to ledger first. The canonical ledger takes the
        // native Event, so the previous hand-rolled LedgerEvent construction and
        // its EventKind -> LedgerEventKind switch (which had no default case and
        // would silently produce an uninitialized kind for any new EventKind)
        // are no longer needed.
        if (ledger_) {
            ledger_->append(ev.run_id, ev);
        }

        auto* heap_event = new Event(std::move(ev));
        if (!::PostMessageW(target_, message_, 0,
                            reinterpret_cast<LPARAM>(heap_event))) {
            // UI target lost; event remains in ledger for replay on rebind
        }
    }
}

} // namespace rawrxd::continuous
#endif
