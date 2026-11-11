// ============================================================================
// OutputPanel.cpp - Output Panel Implementation
// ============================================================================

#include "OutputPanel.hpp"
#include <fstream>
#include <sstream>
#include <cstdarg>
#include <iostream>
#include <algorithm>

namespace Sovereign {

OutputPanel::OutputPanel() = default;
OutputPanel::~OutputPanel() { Shutdown(); }

bool OutputPanel::Initialize(size_t maxEntries) {
    maxEntries_ = maxEntries;
    return true;
}

void OutputPanel::Shutdown() { entries_.clear(); channelEntries_.clear(); }

void OutputPanel::Write(OutputChannel channel, const std::string& text, const std::string& source) {
    AddEntry(channel, text, source, 0);
}

void OutputPanel::WriteLine(OutputChannel channel, const std::string& text, const std::string& source) {
    AddEntry(channel, text + "\n", source, 0);
}

void OutputPanel::WriteError(OutputChannel channel, const std::string& text, const std::string& source) {
    AddEntry(channel, text, source, 2);
}

void OutputPanel::AddEntry(OutputChannel channel, const std::string& text, const std::string& source, int severity) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    OutputEntry entry;
    entry.id = nextId_++;
    entry.channel = channel;
    entry.text = text;
    entry.source = source;
    entry.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    entry.severity = severity;
    entry.isError = severity >= 2;
    
    entries_.push_back(entry);
    channelEntries_[channel].push_back(entry);
    totalEntries_++;
    
    if (severity == 0) stats_.infoEntries++;
    else if (severity == 1) stats_.warningEntries++;
    else stats_.errorEntries++;
    stats_.totalEntries++;
    
    if (entries_.size() > maxEntries_) entries_.pop_front();
    if (channelEntries_[channel].size() > maxEntries_) channelEntries_[channel].pop_front();
    
    if (writeCallback_) writeCallback_(entry);
    if (entry.isError && errorCallback_) errorCallback_(entry);
}

void OutputPanel::Clear(OutputChannel channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    channelEntries_[channel].clear();
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
        [channel](const OutputEntry& e) { return e.channel == channel; }), entries_.end());
}

void OutputPanel::ClearAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    channelEntries_.clear();
}

std::vector<OutputEntry> OutputPanel::GetEntries(OutputChannel channel, size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = channelEntries_.find(channel);
    if (it == channelEntries_.end()) return {};
    std::vector<OutputEntry> result;
    size_t start = it->second.size() > count ? it->second.size() - count : 0;
    for (size_t i = start; i < it->second.size(); ++i) result.push_back(it->second[i]);
    return result;
}

std::vector<OutputEntry> OutputPanel::GetRecent(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<OutputEntry> result;
    size_t start = entries_.size() > count ? entries_.size() - count : 0;
    for (size_t i = start; i < entries_.size(); ++i) result.push_back(entries_[i]);
    return result;
}

std::vector<OutputEntry> OutputPanel::GetErrors(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<OutputEntry> result;
    for (auto it = entries_.rbegin(); it != entries_.rend() && result.size() < count; ++it) {
        if (it->isError) result.push_back(*it);
    }
    return result;
}

bool OutputPanel::HasErrors() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(entries_.begin(), entries_.end(), [](const OutputEntry& e) { return e.isError; });
}

bool OutputPanel::SaveToFile(const std::string& path, OutputChannel channel) {
    std::ofstream file(path);
    if (!file) return false;
    auto entries = GetEntries(channel, maxEntries_);
    for (const auto& e : entries) file << "[" << e.timestamp << "] " << e.text << "\n";
    return true;
}

bool OutputPanel::SaveAllToFile(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    auto entries = GetRecent(maxEntries_);
    for (const auto& e : entries) file << "[" << e.timestamp << "] " << e.text << "\n";
    return true;
}

} // namespace Sovereign
