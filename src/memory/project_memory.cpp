#include "project_memory.hpp"
#include <algorithm>
#include <iostream>

namespace rawrxd {
namespace memory {

ProjectMemory::ProjectMemory() = default;
ProjectMemory::~ProjectMemory() = default;

void ProjectMemory::recordDecision(const DecisionEntry& entry) {
    DecisionEntry timed = entry;
    if (timed.timestamp_ms == 0) {
        timed.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    decisions_.push_back(timed);
}

std::vector<DecisionEntry> ProjectMemory::getDecisions() const {
    return decisions_;
}

std::vector<DecisionEntry> ProjectMemory::findDecisions(const std::string& query) const {
    std::vector<DecisionEntry> results;
    std::string lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);

    for (const auto& d : decisions_) {
        std::string lower_task = d.task;
        std::transform(lower_task.begin(), lower_task.end(), lower_task.begin(), ::tolower);
        if (lower_task.find(lower_query) != std::string::npos) {
            results.push_back(d);
        }
    }
    return results;
}

void ProjectMemory::addFact(const ProjectFact& fact) {
    ProjectFact timed = fact;
    if (timed.timestamp_ms == 0) {
        timed.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    facts_[fact.key] = timed;
}

ProjectFact* ProjectMemory::getFact(const std::string& key) {
    auto it = facts_.find(key);
    if (it != facts_.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<ProjectFact> ProjectMemory::getAllFacts() const {
    std::vector<ProjectFact> result;
    result.reserve(facts_.size());
    for (const auto& pair : facts_) {
        result.push_back(pair.second);
    }
    return result;
}

void ProjectMemory::recordChange(const ChangeRecord& record) {
    ChangeRecord timed = record;
    if (timed.timestamp_ms == 0) {
        timed.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    changes_.push_back(timed);
}

std::vector<ChangeRecord> ProjectMemory::getChanges(const std::string& file) const {
    std::vector<ChangeRecord> results;
    for (const auto& c : changes_) {
        if (c.file == file) {
            results.push_back(c);
        }
    }
    return results;
}

std::vector<ChangeRecord> ProjectMemory::getAllChanges() const {
    return changes_;
}

void ProjectMemory::clear() {
    decisions_.clear();
    facts_.clear();
    changes_.clear();
}

size_t ProjectMemory::decisionCount() const { return decisions_.size(); }
size_t ProjectMemory::factCount() const { return facts_.size(); }
size_t ProjectMemory::changeCount() const { return changes_.size(); }

} // namespace memory
} // namespace rawrxd
