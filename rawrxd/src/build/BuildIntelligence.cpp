#include "BuildIntelligence.hpp"
#include <fstream>
#include <sstream>
#include <regex>
#include <mutex>
#include <map>
#include <algorithm>
#include <chrono>

namespace rawrxd::build {

class BuildIntelligence::Impl {
public:
    mutable std::mutex mutex_;
    std::vector<BuildIntelligenceEvent> events_;
    std::map<std::string, std::vector<bool>> build_history_;
    uint64_t next_event_id_ = 1;
};

BuildIntelligence::BuildIntelligence() : impl_(std::make_unique<Impl>()) {}
BuildIntelligence::~BuildIntelligence() = default;

void BuildIntelligence::IngestEvent(const BuildIntelligenceEvent& event) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    BuildIntelligenceEvent e = event;
    e.event_id = impl_->next_event_id_++;
    e.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    impl_->events_.push_back(e);
    if (event_cb_) event_cb_(e);
}

void BuildIntelligence::IngestCompilerOutput(const std::string& raw_output, IntelligenceSource src) {
    std::vector<BuildIntelligenceEvent> parsed;
    if (src == IntelligenceSource::CompilerOutput) {
        // Try MSVC first, then GCC/Clang
        parsed = ParseMSVCOutput(raw_output);
        if (parsed.empty()) parsed = ParseGCCOutput(raw_output);
    } else if (src == IntelligenceSource::CMakeBuild || src == IntelligenceSource::CMakeConfigure) {
        parsed = ParseCMakeErrorOutput(raw_output);
    }
    for (const auto& e : parsed) {
        IngestEvent(e);
    }
}

void BuildIntelligence::IngestCMakeOutput(const std::string& raw_output) {
    auto parsed = ParseCMakeErrorOutput(raw_output);
    for (const auto& e : parsed) {
        IngestEvent(e);
    }
}

BuildMetrics BuildIntelligence::AnalyzeBuild() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    BuildMetrics m;
    m.total_events = impl_->events_.size();
    float total_conf = 0.0f;
    std::map<std::string, uint64_t> category_counts;
    for (const auto& e : impl_->events_) {
        if (e.severity == "error") m.error_count++;
        else if (e.severity == "warning") m.warning_count++;
        else if (e.severity == "suggestion" || e.severity == "info") m.suggestion_count++;
        if (e.is_auto_fixable) m.auto_fixable_count++;
        total_conf += e.confidence;
        category_counts[e.category]++;
    }
    if (m.total_events > 0) m.avg_confidence = total_conf / m.total_events;
    std::vector<std::pair<std::string, uint64_t>> sorted(category_counts.begin(), category_counts.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    for (size_t i = 0; i < std::min(size_t(5), sorted.size()); ++i) {
        m.top_error_categories.push_back(sorted[i].first);
    }
    return m;
}

std::vector<BuildIntelligenceEvent> BuildIntelligence::GetErrors() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<BuildIntelligenceEvent> out;
    for (const auto& e : impl_->events_) {
        if (e.severity == "error") out.push_back(e);
    }
    return out;
}

std::vector<BuildIntelligenceEvent> BuildIntelligence::GetWarnings() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<BuildIntelligenceEvent> out;
    for (const auto& e : impl_->events_) {
        if (e.severity == "warning") out.push_back(e);
    }
    return out;
}

std::vector<BuildIntelligenceEvent> BuildIntelligence::GetSuggestions() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<BuildIntelligenceEvent> out;
    for (const auto& e : impl_->events_) {
        if (e.severity == "suggestion" || e.severity == "info") out.push_back(e);
    }
    return out;
}

std::vector<BuildIntelligenceEvent> BuildIntelligence::GetByCategory(const std::string& category) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<BuildIntelligenceEvent> out;
    for (const auto& e : impl_->events_) {
        if (e.category == category) out.push_back(e);
    }
    return out;
}

std::vector<BuildIntelligenceEvent> BuildIntelligence::GetByFile(const std::string& file_path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<BuildIntelligenceEvent> out;
    for (const auto& e : impl_->events_) {
        if (e.file_path == file_path) out.push_back(e);
    }
    return out;
}

std::vector<BuildIntelligenceEvent> BuildIntelligence::GetAutoFixableEvents() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<BuildIntelligenceEvent> out;
    for (const auto& e : impl_->events_) {
        if (e.is_auto_fixable) out.push_back(e);
    }
    return out;
}

bool BuildIntelligence::GenerateFixPatch(const BuildIntelligenceEvent& event, std::string& out_patch) const {
    if (!event.is_auto_fixable) return false;
    out_patch = event.proposed_patch;
    return !out_patch.empty();
}

std::vector<std::string> BuildIntelligence::SuggestBuildOptimizations() const {
    std::vector<std::string> suggestions;
    auto metrics = AnalyzeBuild();
    if (metrics.error_count > 10) {
        suggestions.push_back("High error count detected. Consider running incremental builds or precompiled headers.");
    }
    if (metrics.warning_count > 50) {
        suggestions.push_back("Large number of warnings. Enable -Werror or fix systematically.");
    }
    if (metrics.auto_fixable_count > 0) {
        suggestions.push_back(std::to_string(metrics.auto_fixable_count) + " issues are auto-fixable. Apply patches.");
    }
    return suggestions;
}

float BuildIntelligence::PredictBuildSuccessRate() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t total = impl_->events_.size();
    if (total == 0) return 1.0f;
    size_t errors = 0;
    for (const auto& e : impl_->events_) {
        if (e.severity == "error") errors++;
    }
    return std::max(0.0f, 1.0f - (errors / static_cast<float>(total)));
}

void BuildIntelligence::RecordBuildAttempt(bool success, const std::string& target) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->build_history_[target].push_back(success);
    if (impl_->build_history_[target].size() > 100) {
        impl_->build_history_[target].erase(impl_->build_history_[target].begin());
    }
}

float BuildIntelligence::GetSuccessRateForTarget(const std::string& target) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->build_history_.find(target);
    if (it == impl_->build_history_.end() || it->second.empty()) return 0.0f;
    size_t successes = 0;
    for (bool b : it->second) if (b) successes++;
    return successes / static_cast<float>(it->second.size());
}

std::vector<std::string> BuildIntelligence::GetFlakyTargets() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> flaky;
    for (const auto& [target, history] : impl_->build_history_) {
        if (history.size() < 5) continue;
        float rate = 0.0f;
        for (bool b : history) if (b) rate += 1.0f;
        rate /= history.size();
        if (rate > 0.1f && rate < 0.9f) {
            flaky.push_back(target);
        }
    }
    return flaky;
}

bool BuildIntelligence::SaveState(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    auto append_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) { ofs.put(static_cast<char>(v & 0xFF)); v >>= 8; }
    };
    auto append_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) { ofs.put(static_cast<char>(v & 0xFF)); v >>= 8; }
    };
    auto append_str = [&](const std::string& s) {
        append_u64(s.size());
        ofs.write(s.data(), static_cast<std::streamsize>(s.size()));
    };
    append_u32(static_cast<uint32_t>(impl_->events_.size()));
    for (const auto& e : impl_->events_) {
        append_u64(e.event_id);
        append_u32(static_cast<uint32_t>(e.source));
        append_str(e.severity);
        append_str(e.file_path);
        append_u32(e.line_number);
        append_u32(e.column_number);
        append_str(e.message);
        append_str(e.category);
        append_str(e.suggestion);
        // confidence as uint32_t * 1000
        append_u32(static_cast<uint32_t>(e.confidence * 1000.0f));
        append_u64(e.timestamp_ms);
        // RAWRXD_GOLD_LINK_BLOCKER_001
        // Was `out.put(...)`. `out` is not declared anywhere in this function --
        // the stream is `ofs`, as every other write in this same block uses --
        // so this line failed to compile:
        //     BuildIntelligence.cpp(223,9): error C2065: 'out': undeclared identifier
        // and took the whole RawrXD_Gold target down with it. Because the error is
        // a compile error the file could never have been linked, so the byte
        // SaveState wrote for e.is_auto_fixable was never produced and the
        // matching read at LoadState:276 has never been exercised. Both halves
        // are byte-identical now: SaveState writes one byte, LoadState reads one.
        ofs.put(e.is_auto_fixable ? 1 : 0);
        append_str(e.proposed_patch);
    }
    append_u32(static_cast<uint32_t>(impl_->build_history_.size()));
    for (const auto& [target, hist] : impl_->build_history_) {
        append_str(target);
        append_u32(static_cast<uint32_t>(hist.size()));
        for (bool b : hist) ofs.put(b ? 1 : 0);
    }
    return ofs.good();
}

bool BuildIntelligence::LoadState(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    auto read_u32 = [&]() -> uint32_t {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            char c; ifs.get(c);
            v |= static_cast<uint32_t>(static_cast<uint8_t>(c)) << (i * 8);
        }
        return v;
    };
    auto read_u64 = [&]() -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            char c; ifs.get(c);
            v |= static_cast<uint64_t>(static_cast<uint8_t>(c)) << (i * 8);
        }
        return v;
    };
    auto read_str = [&]() -> std::string {
        uint64_t len = read_u64();
        std::string s(len, '\0');
        ifs.read(s.data(), static_cast<std::streamsize>(len));
        return s;
    };
    uint32_t event_count = read_u32();
    impl_->events_.clear();
    for (uint32_t i = 0; i < event_count; ++i) {
        BuildIntelligenceEvent e;
        e.event_id = read_u64();
        e.source = static_cast<IntelligenceSource>(read_u32());
        e.severity = read_str();
        e.file_path = read_str();
        e.line_number = read_u32();
        e.column_number = read_u32();
        e.message = read_str();
        e.category = read_str();
        e.suggestion = read_str();
        e.confidence = read_u32() / 1000.0f;
        e.timestamp_ms = read_u64();
        char fixable; ifs.get(fixable); e.is_auto_fixable = (fixable != 0);
        e.proposed_patch = read_str();
        impl_->events_.push_back(e);
    }
    uint32_t hist_count = read_u32();
    impl_->build_history_.clear();
    for (uint32_t i = 0; i < hist_count; ++i) {
        std::string target = read_str();
        uint32_t hlen = read_u32();
        std::vector<bool> hist;
        hist.reserve(hlen);
        for (uint32_t j = 0; j < hlen; ++j) {
            char b; ifs.get(b); hist.push_back(b != 0);
        }
        impl_->build_history_[target] = std::move(hist);
    }
    return true;
}

void BuildIntelligence::ClearState() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->events_.clear();
    impl_->build_history_.clear();
}

// ───────────────────────────────────────────────────────────────
// Static parsers
// ───────────────────────────────────────────────────────────────
std::vector<BuildIntelligenceEvent> BuildIntelligence::ParseMSVCOutput(const std::string& output) {
    std::vector<BuildIntelligenceEvent> events;
    std::istringstream stream(output);
    std::string line;
    // MSVC pattern: file(line[,col]): severity C####: message
    std::regex msvc_re(R"((.+?)\((\d+)(?:,(\d+))?\):\s*(error|warning|info)\s+([A-Za-z]*\d+)?:\s*(.+))");
    while (std::getline(stream, line)) {
        std::smatch m;
        if (std::regex_search(line, m, msvc_re)) {
            BuildIntelligenceEvent e;
            e.file_path = m[1].str();
            e.line_number = static_cast<uint32_t>(std::stoul(m[2].str()));
            if (m[3].matched) e.column_number = static_cast<uint32_t>(std::stoul(m[3].str()));
            e.severity = m[4].str();
            e.category = m[5].str();
            e.message = m[6].str();
            e.source = IntelligenceSource::CompilerOutput;
            e.confidence = 0.95f;
            events.push_back(e);
        }
    }
    return events;
}

std::vector<BuildIntelligenceEvent> BuildIntelligence::ParseGCCOutput(const std::string& output) {
    std::vector<BuildIntelligenceEvent> events;
    std::istringstream stream(output);
    std::string line;
    // GCC pattern: file:line:col: severity: message
    std::regex gcc_re(R"((.+?):(\d+):(\d+):\s*(error|warning|note):\s*(.+))");
    while (std::getline(stream, line)) {
        std::smatch m;
        if (std::regex_search(line, m, gcc_re)) {
            BuildIntelligenceEvent e;
            e.file_path = m[1].str();
            e.line_number = static_cast<uint32_t>(std::stoul(m[2].str()));
            e.column_number = static_cast<uint32_t>(std::stoul(m[3].str()));
            e.severity = m[4].str();
            if (e.severity == "note") e.severity = "info";
            e.message = m[5].str();
            e.category = "compiler_diagnostic";
            e.source = IntelligenceSource::CompilerOutput;
            e.confidence = 0.95f;
            events.push_back(e);
        }
    }
    return events;
}

std::vector<BuildIntelligenceEvent> BuildIntelligence::ParseCMakeErrorOutput(const std::string& output) {
    std::vector<BuildIntelligenceEvent> events;
    std::istringstream stream(output);
    std::string line;
    std::regex cmake_re(R"(CMake\s+(Error|Warning)\s+at\s+(.+?):(\d+)\s*\((.+)\):\s*(.+))");
    while (std::getline(stream, line)) {
        std::smatch m;
        if (std::regex_search(line, m, cmake_re)) {
            BuildIntelligenceEvent e;
            e.severity = m[1].str();
            e.file_path = m[2].str();
            e.line_number = static_cast<uint32_t>(std::stoul(m[3].str()));
            e.category = m[4].str();
            e.message = m[5].str();
            e.source = IntelligenceSource::CMakeConfigure;
            e.confidence = 0.98f;
            events.push_back(e);
        }
    }
    return events;
}

} // namespace rawrxd::build
