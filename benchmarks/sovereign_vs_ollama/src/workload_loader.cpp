// Workload Loader Implementation
// Copyright (c) 2026 RawrXD Team

#include "workload_loader.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <regex>

namespace rawrxd::benchmark {

// Global workload manager instance
WorkloadProfileManager g_workload_manager;

// ============================================================================
// WorkloadLoader Implementation
// ============================================================================

std::optional<WorkloadSuite> WorkloadLoader::LoadFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file) {
        std::cerr << "Failed to open workload file: " << filepath << "\n";
        return std::nullopt;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    try {
        WorkloadSuite suite = ParseJson(buffer.str());
        
        // Calculate and verify SHA256
        std::string actual_sha256 = CalculateSHA256(filepath);
        if (!suite.sha256.empty() && suite.sha256 != "TBD" && suite.sha256 != actual_sha256) {
            std::cerr << "Warning: SHA256 mismatch for " << filepath << "\n";
            std::cerr << "  Expected: " << suite.sha256 << "\n";
            std::cerr << "  Actual: " << actual_sha256 << "\n";
        }
        
        if (!suite.Validate()) {
            std::cerr << "Workload suite validation failed\n";
            return std::nullopt;
        }
        
        return suite;
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse workload JSON: " << e.what() << "\n";
        return std::nullopt;
    }
}

std::optional<WorkloadSuite> WorkloadLoader::LoadLatest(const std::string& directory) {
    auto versions = ListVersions(directory);
    if (versions.empty()) {
        std::cerr << "No workload versions found in: " << directory << "\n";
        return std::nullopt;
    }
    
    // Sort versions (semantic versioning)
    std::sort(versions.begin(), versions.end(), [](const std::string& a, const std::string& b) {
        // Simple version comparison (assumes format X.Y.Z)
        return a > b; // Higher version first
    });
    
    return LoadVersion(directory, versions[0]);
}

std::optional<WorkloadSuite> WorkloadLoader::LoadVersion(const std::string& directory,
                                                              const std::string& version) {
    std::string filepath = directory + "/workloads_v" + version + ".json";
    return LoadFromFile(filepath);
}

std::vector<std::string> WorkloadLoader::ListVersions(const std::string& directory) {
    std::vector<std::string> versions;
    
    // In production, use std::filesystem::directory_iterator
    // For now, assume standard naming convention
    std::vector<std::string> expected_files = {
        "workloads_v1.0.0.json"
    };
    
    for (const auto& file : expected_files) {
        std::string path = directory + "/" + file;
        std::ifstream test(path);
        if (test) {
            // Extract version from filename
            size_t start = file.find("_v");
            size_t end = file.find(".json");
            if (start != std::string::npos && end != std::string::npos) {
                std::string version = file.substr(start + 2, end - start - 2);
                versions.push_back(version);
            }
        }
    }
    
    return versions;
}

std::string WorkloadLoader::CalculateSHA256(const std::string& filepath) {
    // In production, use proper SHA256 implementation
    // For now, return placeholder
    // This would typically use OpenSSL or similar
    return "TBD";
}

// Simple JSON parsing (production should use nlohmann/json)
WorkloadSuite WorkloadLoader::ParseJson(const std::string& json_content) {
    WorkloadSuite suite;
    
    // Extract basic fields using simple regex
    auto extract_string = [&](const std::string& key) -> std::string {
        std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
        std::smatch match;
        if (std::regex_search(json_content, match, pattern)) {
            return match[1];
        }
        return "";
    };
    
    suite.version = extract_string("version");
    suite.name = extract_string("name");
    suite.description = extract_string("description");
    suite.sha256 = extract_string("sha256");
    suite.created_date = extract_string("created");
    
    // Extract total_prompts
    std::regex total_pattern("\"total_prompts\"\\s*:\\s*(\\d+)");
    std::smatch total_match;
    if (std::regex_search(json_content, total_match, total_pattern)) {
        suite.total_prompts = std::stoi(total_match[1]);
    }
    
    // Extract recommended_runs
    std::regex runs_pattern("\"recommended_runs_per_prompt\"\\s*:\\s*(\\d+)");
    std::smatch runs_match;
    if (std::regex_search(json_content, runs_match, runs_pattern)) {
        suite.recommended_runs = std::stoi(runs_match[1]);
    }
    
    // Extract fixed_seed
    std::regex seed_pattern("\"fixed_seed\"\\s*:\\s*(\\d+)");
    std::smatch seed_match;
    if (std::regex_search(json_content, seed_match, seed_pattern)) {
        suite.fixed_seed = std::stoi(seed_match[1]);
    }
    
    // Extract randomize_order
    std::regex random_pattern("\"randomize_order\"\\s*:\\s*(true|false)");
    std::smatch random_match;
    if (std::regex_search(json_content, random_match, random_pattern)) {
        suite.randomize_order = (random_match[1] == "true");
    }
    
    // Parse categories (simplified - production should use proper JSON parser)
    // This is a placeholder that would be replaced with actual JSON parsing
    std::vector<std::string> categories = {
        "chat", "coding", "agentic", "swarm", 
        "long_context", "autonomous", "recovery", "stress"
    };
    
    for (const auto& cat : categories) {
        // In production, properly parse the JSON array
        // For now, create placeholder prompts
        std::vector<Prompt> prompts;
        for (int i = 1; i <= 5; ++i) {
            Prompt p;
            p.id = cat + "_" + std::to_string(i);
            p.name = "Prompt " + std::to_string(i);
            p.prompt = "Sample prompt for " + cat + " category";
            p.expected_tokens = 200;
            p.difficulty = "medium";
            p.category = cat;
            prompts.push_back(p);
        }
        suite.categories[cat] = prompts;
    }
    
    return suite;
}

// ============================================================================
// WorkloadProfileManager Implementation
// ============================================================================

bool WorkloadProfileManager::Initialize(const std::string& workload_path) {
    auto suite = WorkloadLoader::LoadFromFile(workload_path);
    if (!suite) {
        // Try loading latest from directory
        suite = WorkloadLoader::LoadLatest(workload_path);
    }
    
    if (suite) {
        suite_ = *suite;
        initialized_ = true;
        return true;
    }
    
    return false;
}

WorkloadConfig WorkloadProfileManager::GetWorkload(const std::string& category,
                                                    int max_tokens,
                                                    int num_prompts) {
    WorkloadConfig config;
    config.max_tokens = max_tokens;
    
    auto prompts = suite_.GetCategory(category);
    if (prompts.empty()) {
        // Fallback to stress category
        prompts = suite_.GetCategory("stress");
    }
    
    // Limit number of prompts if specified
    if (num_prompts > 0 && num_prompts < static_cast<int>(prompts.size())) {
        prompts.resize(num_prompts);
    }
    
    // Extract prompt strings
    for (const auto& p : prompts) {
        config.prompts.push_back(p.prompt);
    }
    
    return config;
}

WorkloadConfig WorkloadProfileManager::GetShuffledWorkload(const std::string& category,
                                                             int max_tokens,
                                                             int seed) {
    WorkloadConfig config = GetWorkload(category, max_tokens);
    
    // Shuffle with fixed seed for reproducibility
    std::mt19937 rng(seed);
    std::shuffle(config.prompts.begin(), config.prompts.end(), rng);
    
    return config;
}

} // namespace rawrxd::benchmark
