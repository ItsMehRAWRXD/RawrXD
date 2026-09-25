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

void Win32EventBridge::replaySince(uint64_t sequence, HWND target) {
    if (!ledger_) return;
    auto evs = ledger_->replaySince(sequence);
    for (auto& ev : evs) {
        auto* heap_event = new Event();
        heap_event->run_id = ev.runId;
        heap_event->sequence = ev.sequence;
        heap_event->text = std::move(ev.payload);
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

        // Authoritative commit to ledger first
        if (ledger_) {
            LedgerEvent le;
            le.runId = ev.run_id;
            le.sequence = ev.sequence;
            switch (ev.kind) {
                case EventKind::StateChanged: le.kind = LedgerEventKind::StateChanged; break;
                case EventKind::Progress: le.kind = LedgerEventKind::Progress; break;
                case EventKind::TextDelta: le.kind = LedgerEventKind::TextDelta; break;
                case EventKind::ToolCall: le.kind = LedgerEventKind::ToolCall; break;
                case EventKind::ToolResult: le.kind = LedgerEventKind::ToolResult; break;
                case EventKind::FinalText: le.kind = LedgerEventKind::FinalText; break;
                case EventKind::Completed: le.kind = LedgerEventKind::Completed; break;
                case EventKind::Error: le.kind = LedgerEventKind::Error; break;
            }
            le.payload = ev.text;
            ledger_->append(std::move(le));
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
