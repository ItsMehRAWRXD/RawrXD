#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <chrono>

namespace rawrxd {
namespace memory {

struct DecisionEntry {
    uint64_t timestamp_ms;
    std::string task;
    std::string decision;
    std::string rationale;
    std::string outcome;
    std::vector<std::string> files_affected;
};

struct ProjectFact {
    std::string key;
    std::string value;
    std::string source;
    uint64_t timestamp_ms;
};

struct ChangeRecord {
    uint64_t timestamp_ms;
    std::string file;
    std::string change_type;  // "create", "modify", "delete"
    std::string summary;
    std::string diff;
};

class ProjectMemory {
public:
    ProjectMemory();
    ~ProjectMemory();

    void recordDecision(const DecisionEntry& entry);
    std::vector<DecisionEntry> getDecisions() const;
    std::vector<DecisionEntry> findDecisions(const std::string& query) const;

    void addFact(const ProjectFact& fact);
    ProjectFact* getFact(const std::string& key);
    std::vector<ProjectFact> getAllFacts() const;

    void recordChange(const ChangeRecord& record);
    std::vector<ChangeRecord> getChanges(const std::string& file) const;
    std::vector<ChangeRecord> getAllChanges() const;

    void clear();
    size_t decisionCount() const;
    size_t factCount() const;
    size_t changeCount() const;

private:
    std::vector<DecisionEntry> decisions_;
    std::unordered_map<std::string, ProjectFact> facts_;
    std::vector<ChangeRecord> changes_;
};

} // namespace memory
} // namespace rawrxd
