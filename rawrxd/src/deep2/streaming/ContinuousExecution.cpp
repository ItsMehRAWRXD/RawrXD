#include "ContinuousExecution.hpp"

#include <algorithm>
#include <exception>

namespace rawrxd::continuous {

PushResult EventPipe::push(Event ev) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return PushResult::TransportClosed;
        q_.push_back(std::move(ev));
    }
    cv_.notify_one();
    return PushResult::Committed;
}

bool EventPipe::wait_pop(Event& out) {
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [&]{ return closed_ || !q_.empty(); });
    if (q_.empty()) return false;
    out = std::move(q_.front());
    q_.pop_front();
    return true;
}

bool EventPipe::wait_pop(Event& out, const std::atomic<bool>& stop_flag) {
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [&]{
        return closed_ || stop_flag.load(std::memory_order_acquire) || !q_.empty();
    });
    if (stop_flag.load(std::memory_order_acquire) || q_.empty()) return false;
    out = std::move(q_.front());
    q_.pop_front();
    return true;
}

bool EventPipe::try_pop(Event& out) {
    std::lock_guard<std::mutex> lk(mu_);
    if (q_.empty()) return false;
    out = std::move(q_.front());
    q_.pop_front();
    return true;
}

void EventPipe::wake_waiters() {
    cv_.notify_all();
}

void EventPipe::close() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        closed_ = true;
    }
    cv_.notify_all();
}

bool EventPipe::closed() const {
    std::lock_guard<std::mutex> lk(mu_);
    return closed_;
}

void ToolRegistry::add(std::string name, Fn fn) {
    if (name.empty() || !fn) {
        throw std::invalid_argument("ToolRegistry::add requires a name and real function");
    }
    tools_.insert_or_assign(std::move(name), std::move(fn));
}

bool ToolRegistry::execute(std::string_view name,
                           std::string_view arguments,
                           std::string& result,
                           std::string& error) const {
    const auto it = tools_.find(std::string(name));
    if (it == tools_.end()) {
        error = "tool not registered: " + std::string(name);
        return false;
    }
    try {
        return it->second(arguments, result, error);
    } catch (const std::exception& e) {
        error = std::string("tool exception: ") + e.what();
        return false;
    } catch (...) {
        error = "tool exception: unknown";
        return false;
    }
}

Session::Session(RunId id,
                 ModelBindings model,
                 std::shared_ptr<const ToolRegistry> tools,
                 std::shared_ptr<EventPipe> events,
                 EventLedger* ledger)
    : id_(id), model_(std::move(model)), tools_(std::move(tools)), events_(std::move(events)), ledger_(ledger) {
    validate_bindings();

    if (model_.set_progress_sink) {
        model_.set_progress_sink(
            [this](std::uint64_t epoch,
                   std::uint32_t layer,
                   std::uint32_t layers,
                   std::string_view phase) {
                work_epoch_.store(std::max(work_epoch_.load(std::memory_order_relaxed), epoch),
                                  std::memory_order_release);
                Event ev;
                ev.kind = EventKind::Progress;
                ev.state = state();
                ev.work_epoch = epoch;
                ev.token_index = token_index_;
                ev.layer_index = layer;
                ev.layer_count = layers;
                ev.text.assign(phase);
                emit(std::move(ev));
            });
    }
}

Session::~Session() {
    if (!terminal()) cancel();
    join();

    // Prevent a backend-owned progress callback from outliving this Session.
    if (model_.set_progress_sink) {
        try { model_.set_progress_sink({}); } catch (...) {}
    }
}

void Session::validate_bindings() const {
    if (!events_) throw std::invalid_argument("Session requires EventPipe");
    if (!model_.prefill) throw std::invalid_argument("missing real model prefill binding");
    if (!model_.decode_one) throw std::invalid_argument("missing real model decode_one binding");
    if (!model_.append_tool_result) throw std::invalid_argument("missing real append_tool_result binding");
    if (!model_.cancel) throw std::invalid_argument("missing real model cancel binding");
    if (!model_.set_progress_sink) throw std::invalid_argument("missing real model progress sink binding");
}

void Session::start(Request request) {
    if (worker_.joinable()) {
        throw std::logic_error("Session already started");
    }
    worker_ = std::thread(&Session::run, this, std::move(request));
}

void Session::cancel() {
    bool expected = false;
    if (cancel_requested_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        try { model_.cancel(); } catch (...) {}
    }
}

void Session::join() {
    if (worker_.joinable()) worker_.join();
}

bool Session::terminal() const noexcept {
    const auto s = state();
    return s == State::Completed || s == State::Failed || s == State::Cancelled;
}

void Session::emit(Event ev) {
    ev.run_id = id_;
    ev.sequence = sequence_.fetch_add(1, std::memory_order_acq_rel) + 1;
    ev.work_epoch = std::max(ev.work_epoch, work_epoch_.load(std::memory_order_acquire));

    // RAWRXD_CONTINUOUS_STREAM_REALITY_001: persist to durable ledger first.
    if (ledger_) {
        ledger_->append(id_, ev);
    }

    auto pr = events_->push(std::move(ev));
    if (pr == PushResult::TransportClosed) {
        if (!terminal()) {
            state_.store(State::Failed, std::memory_order_release);
        }
    }
}

void Session::set_state(State s, std::string_view detail) {
    state_.store(s, std::memory_order_release);
    Event ev;
    ev.kind = EventKind::StateChanged;
    ev.state = s;
    ev.token_index = token_index_;
    ev.text.assign(detail);
    emit(std::move(ev));
}

void Session::fail(FinishReason reason, std::string_view message) {
    state_.store(State::Failed, std::memory_order_release);
    Event err;
    err.kind = EventKind::Error;
    err.state = State::Failed;
    err.finish = reason;
    err.token_index = token_index_;
    err.text.assign(message);
    emit(std::move(err));

    Event done;
    done.kind = EventKind::Completed;
    done.state = State::Failed;
    done.finish = reason;
    done.token_index = token_index_;
    emit(std::move(done));
}

void Session::finish(FinishReason reason) {
    if (reason == FinishReason::Cancelled) {
        state_.store(State::Cancelled, std::memory_order_release);
    } else {
        state_.store(State::Completed, std::memory_order_release);
    }

    Event final_ev;
    final_ev.kind = EventKind::FinalText;
    final_ev.state = state();
    final_ev.finish = reason;
    final_ev.token_index = token_index_;
    final_ev.text = full_text_;
    emit(std::move(final_ev));

    Event done;
    done.kind = EventKind::Completed;
    done.state = state();
    done.finish = reason;
    done.token_index = token_index_;
    emit(std::move(done));
}

void Session::run(Request request) {
    try {
        set_state(State::Prefill, "prefill");

        std::string error;
        if (!model_.prefill(request.prompt, error)) {
            fail(FinishReason::BackendError,
                 error.empty() ? "model prefill failed" : error);
            return;
        }
        work_epoch_.fetch_add(1, std::memory_order_acq_rel);

        set_state(State::Decode, "decode");

        for (;;) {
            if (cancel_requested_.load(std::memory_order_acquire)) {
                finish(FinishReason::Cancelled);
                return;
            }

            // A caller token cap is explicit policy. No wall clock, timeout,
            // watchdog tick, TPS threshold, scheduler credit, or elapsed time
            // participates in this transition.
            if (request.max_output_tokens != 0 &&
                token_index_ >= request.max_output_tokens) {
                finish(FinishReason::UserTokenLimit);
                return;
            }

            DecodeResult step = model_.decode_one();
            work_epoch_.fetch_add(1, std::memory_order_acq_rel);

            if (cancel_requested_.load(std::memory_order_acquire)) {
                finish(FinishReason::Cancelled);
                return;
            }

            switch (step.kind) {
            case DecodeKind::Text: {
                ++token_index_;
                full_text_.append(step.text);

                Event ev;
                ev.kind = EventKind::TextDelta;
                ev.state = State::Decode;
                ev.token_index = token_index_;
                ev.text = std::move(step.text);
                emit(std::move(ev));
                break;
            }

            case DecodeKind::ToolCall: {
                if (step.tool.name.empty()) {
                    fail(FinishReason::ProtocolError, "tool call missing name");
                    return;
                }
                if (!tools_) {
                    fail(FinishReason::ToolError,
                         "model requested a tool but no real ToolRegistry is bound");
                    return;
                }

                Event call;
                call.kind = EventKind::ToolCall;
                call.state = State::ToolRunning;
                call.token_index = token_index_;
                call.name = step.tool.name;
                call.payload = step.tool.arguments;
                emit(std::move(call));

                set_state(State::ToolRunning, step.tool.name);

                std::string result;
                std::string tool_error;
                if (!tools_->execute(step.tool.name, step.tool.arguments, result, tool_error)) {
                    fail(FinishReason::ToolError,
                         tool_error.empty() ? "tool execution failed" : tool_error);
                    return;
                }
                work_epoch_.fetch_add(1, std::memory_order_acq_rel);

                Event tool_result;
                tool_result.kind = EventKind::ToolResult;
                tool_result.state = State::ToolRunning;
                tool_result.token_index = token_index_;
                tool_result.name = step.tool.name;
                tool_result.payload = result;
                emit(std::move(tool_result));

                set_state(State::ResumeAfterTool, step.tool.name);

                error.clear();
                if (!model_.append_tool_result(step.tool.name, result, error)) {
                    fail(FinishReason::BackendError,
                         error.empty() ? "failed to append tool result to model context" : error);
                    return;
                }
                work_epoch_.fetch_add(1, std::memory_order_acq_rel);
                set_state(State::Decode, "decode");
                break;
            }

            case DecodeKind::Eos:
                finish(FinishReason::Eos);
                return;

            case DecodeKind::StopSequence:
                finish(FinishReason::StopSequence);
                return;

            case DecodeKind::Error:
            default:
                fail(FinishReason::BackendError,
                     step.error.empty() ? "decode backend returned error" : step.error);
                return;
            }
        }
    } catch (const std::exception& e) {
        fail(FinishReason::BackendError, e.what());
    } catch (...) {
        fail(FinishReason::BackendError, "unknown execution failure");
    }
}

Controller::Controller() : events_(std::make_shared<EventPipe>()), ledger_(nullptr) {}
Controller::Controller(EventLedger* ledger) : events_(std::make_shared<EventPipe>()), ledger_(ledger) {}

RunId Controller::start(ModelBindings model,
                        std::shared_ptr<const ToolRegistry> tools,
                        Request request) {
    std::unique_ptr<Session> s;
    RunId id{};
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (shutting_down_) throw std::logic_error("Controller is shutting down");
        id = next_id_.fetch_add(1, std::memory_order_acq_rel);
        s = std::make_unique<Session>(id, std::move(model), std::move(tools), events_, ledger_);
        auto* raw = s.get();
        sessions_.emplace(id, std::move(s));
        raw->start(std::move(request));
    }
    return id;
}

bool Controller::cancel(RunId id) {
    std::lock_guard<std::mutex> lk(mu_);
    const auto it = sessions_.find(id);
    if (it == sessions_.end()) return false;
    it->second->cancel();
    return true;
}

void Controller::reap_terminal() {
    std::vector<std::unique_ptr<Session>> done;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (it->second->terminal()) {
                done.push_back(std::move(it->second));
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& s : done) s->join();
}

void Controller::shutdown() {
    std::vector<std::unique_ptr<Session>> all;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (shutting_down_) return;
        shutting_down_ = true;
        for (auto& [id, s] : sessions_) {
            (void)id;
            s->cancel();
            all.push_back(std::move(s));
        }
        sessions_.clear();
    }
    for (auto& s : all) s->join();
    events_->close();
}

} // namespace rawrxd::continuous
