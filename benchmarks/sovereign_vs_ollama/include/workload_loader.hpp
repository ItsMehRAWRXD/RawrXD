// Workload Loader
// Loads versioned prompt suites from JSON
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <fstream>
#include <filesystem>

namespace rawrxd::benchmark {

// ============================================================================
// Prompt Definition
// ============================================================================
struct Prompt {
    std::string id;
    std::string name;
    std::string prompt;
    int expected_tokens = 200;
    int context_tokens = 0;
    std::string difficulty = "medium";
    std::string category;
};

// ============================================================================
// Workload Suite
// ============================================================================
struct WorkloadSuite {
    std::string version;
    std::string name;
    std::string description;
    std::string sha256;
    std::string created_date;
    
    std::map<std::string, std::vector<Prompt>> categories;
    
    // Metadata
    int total_prompts = 0;
    int recommended_runs = 10;
    bool randomize_order = true;
    int fixed_seed = 42;
    
    // Get all prompts flattened
    std::vector<Prompt> GetAllPrompts() const {
        std::vector<Prompt> all;
        for (const auto& [cat, prompts] : categories) {
            all.insert(all.end(), prompts.begin(), prompts.end());
        }
        return all;
    }
    
    // Get prompts by category
    std::vector<Prompt> GetCategory(const std::string& category) const {
        auto it = categories.find(category);
        if (it != categories.end()) {
            return it->second;
        }
        return {};
    }
    
    // Get warmup prompts
    std::vector<Prompt> GetWarmupPrompts() const {
        // Return stress category prompts for warmup
        return GetCategory("stress");
    }
    
    // Validate suite integrity
    bool Validate() const {
        if (version.empty() || total_prompts == 0) {
            return false;
        }
        
        int count = 0;
        for (const auto& [cat, prompts] : categories) {
            count += static_cast<int>(prompts.size());
            for (const auto& p : prompts) {
                if (p.id.empty() || p.prompt.empty()) {
                    return false;
                }
            }
        }
        
        return count == total_prompts;
    }
};

// ============================================================================
// Workload Loader
// ============================================================================
class WorkloadLoader {
public:
    // Load workload suite from JSON file
    static std::optional<WorkloadSuite> LoadFromFile(const std::string& filepath);
    
    // Load latest version from directory
    static std::optional<WorkloadSuite> LoadLatest(const std::string& directory);
    
    // Load specific version
    static std::optional<WorkloadSuite> LoadVersion(const std::string& directory, 
                                                      const std::string& version);
    
    // List available versions
    static std::vector<std::string> ListVersions(const std::string& directory);
    
    // Calculate SHA256 of workload file
    static std::string CalculateSHA256(const std::string& filepath);
    
private:
    // Simple JSON parsing (in production, use nlohmann/json)
    static WorkloadSuite ParseJson(const std::string& json_content);
    static std::string ExtractString(const std::string& json, const std::string& key);
    static int ExtractInt(const std::string& json, const std::string& key, int default_val = 0);
};

// ============================================================================
// Workload Profile Integration
// ============================================================================
class WorkloadProfileManager {
public:
    // Initialize with workload suite
    bool Initialize(const std::string& workload_path);
    
    // Get workload config for a specific benchmark category
    WorkloadConfig GetWorkload(const std::string& category, 
                               int max_tokens = 512,
                               int num_prompts = -1);  // -1 = all
    
    // Get shuffled workload with fixed seed
    WorkloadConfig GetShuffledWorkload(const std::string& category,
                                       int max_tokens = 512,
                                       int seed = 42);
    
    // Get current suite info
    const WorkloadSuite& GetSuite() const { return suite_; }
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
private:
    WorkloadSuite suite_;
    bool initialized_ = false;
};

// ============================================================================
// Global Workload Instance
// ============================================================================
extern WorkloadProfileManager g_workload_manager;

} // namespace rawrxd::benchmark
