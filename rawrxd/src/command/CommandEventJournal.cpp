#include "CommandEventJournal.hpp"
#include <fstream>
#include <sstream>
#include <map>

namespace rawrxd::command {

class CommandEventJournal::Impl {
public:
    mutable std::mutex mutex_;
    std::vector<CommandEvent> events_;
    uint64_t next_id_ = 1;
    EventCallback event_cb_;
};

CommandEventJournal::CommandEventJournal() : impl_(std::make_unique<Impl>()) {}
CommandEventJournal::~CommandEventJournal() = default;

uint64_t CommandEventJournal::Append(uint64_t command_id, const std::string& event_type, const std::string& payload) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    CommandEvent ev;
    ev.id = impl_->next_id_++;
    ev.command_id = command_id;
    ev.event_type = event_type;
    ev.payload = payload;
    ev.timestamp = std::chrono::steady_clock::now();
    impl_->events_.push_back(ev);
    if (impl_->event_cb_) impl_->event_cb_(ev);
    return ev.id;
}

void CommandEventJournal::AppendSync(uint64_t command_id, const std::string& event_type, const std::string& payload) {
    Append(command_id, event_type, payload);
}

std::vector<CommandEvent> CommandEventJournal::GetAll() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->events_;
}

std::vector<CommandEvent> CommandEventJournal::GetByCommand(uint64_t command_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<CommandEvent> out;
    for (const auto& ev : impl_->events_) {
        if (ev.command_id == command_id) out.push_back(ev);
    }
    return out;
}

std::vector<CommandEvent> CommandEventJournal::GetByType(const std::string& event_type) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<CommandEvent> out;
    for (const auto& ev : impl_->events_) {
        if (ev.event_type == event_type) out.push_back(ev);
    }
    return out;
}

std::optional<CommandEvent> CommandEventJournal::GetLatest() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->events_.empty()) return std::nullopt;
    return impl_->events_.back();
}

size_t CommandEventJournal::GetCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->events_.size();
}

void CommandEventJournal::SetEventCallback(EventCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->event_cb_ = std::move(cb);
}

bool CommandEventJournal::SaveToFile(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ofstream ofs(path);
    if (!ofs) return false;
    for (const auto& ev : impl_->events_) {
        ofs << ev.id << "," << ev.command_id << "," << ev.event_type << "," << ev.payload << "\n";
    }
    return ofs.good();
}

bool CommandEventJournal::LoadFromFile(const std::string& /*path*/) {
    // TODO: implement CSV deserialization
    return false;
}

void CommandEventJournal::Clear() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->events_.clear();
}

} // namespace rawrxd::command
