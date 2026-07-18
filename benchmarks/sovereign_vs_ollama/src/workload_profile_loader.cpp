// workload_profile_loader.cpp
// Batch 5: Workload Profile Loader
//
// Loads and manages benchmark workload profiles from JSON/config files
// Features: Profile validation, parameter substitution, workload composition
// Output: Validated workload configurations for benchmarks

#include "benchmark_tiers.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <optional>

namespace Benchmark {

class WorkloadProfileLoader {
public:
    struct WorkloadProfile {
        std::string name;
        std::string description;
        std::string version = "1.0";
        
        // Inference parameters
        struct {
            std::vector<std::string> models;
            std::vector<std::string> prompts;
            std::vector<int> max_tokens;
            std::vector<float> temperatures;
            int default_seed = 42;
        } inference;
        
        // Load parameters
        struct {
            int warmup_runs = 5;
            int measured_runs = 30;
            int duration_seconds = 60;
            std::vector<int> concurrency_levels;
        } load;
        
        // Stress parameters
        struct {
            int stress_duration_seconds = 300;
            std::vector<int> request_rates;
            std::vector<int> agent_counts;
        } stress;
        
        // Custom parameters
        std::map<std::string, std::string> custom_params;
    };

    struct ValidationError {
        std::string field;
        std::string message;
    };

    explicit WorkloadProfileLoader(const std::string& profiles_dir = "profiles/")
        : profiles_dir_(profiles_dir) {}

    // Load a profile from JSON file
    std::optional<WorkloadProfile> LoadFromFile(const std::string& filename,
                                                std::vector<ValidationError>& errors) {
        std::ifstream file(profiles_dir_ + filename);
        if (!file.is_open()) {
            errors.push_back({"file", "Failed to open: " + profiles_dir_ + filename});
            return std::nullopt;
        }
        
        // Parse JSON (simplified - would use nlohmann/json in production)
        WorkloadProfile profile;
        
        // For now, create default profiles programmatically
        if (filename == "quick_test.json") {
            profile = CreateQuickTestProfile();
        } else if (filename == "standard.json") {
            profile = CreateStandardProfile();
        } else if (filename == "stress_test.json") {
            profile = CreateStressTestProfile();
        } else if (filename == "ci_profile.json") {
            profile = CreateCIProfile();
        } else {
            errors.push_back({"profile", "Unknown profile: " + filename});
            return std::nullopt;
        }
        
        // Validate
        if (!Validate(profile, errors)) {
            return std::nullopt;
        }
        
        return profile;
    }

    // Load with auto-detection of profile type
    std::optional<WorkloadProfile> LoadAuto(const std::string& mode,
                                             std::vector<ValidationError>& errors) {
        if (mode == "quick" || mode == "smoke") {
            return CreateQuickTestProfile();
        } else if (mode == "standard") {
            return CreateStandardProfile();
        } else if (mode == "stress" || mode == "chaos") {
            return CreateStressTestProfile();
        } else if (mode == "ci") {
            return CreateCIProfile();
        } else {
            errors.push_back({"mode", "Unknown workload mode: " + mode});
            return std::nullopt;
        }
    }

    // List available profiles
    std::vector<std::string> ListAvailableProfiles() {
        return {
            "quick_test.json",
            "standard.json",
            "stress_test.json",
            "ci_profile.json"
        };
    }

    // Apply profile to benchmark configuration
    template<typename Config>
    void ApplyProfile(const WorkloadProfile& profile, Config& config) {
        // Apply inference parameters
        if (!profile.inference.models.empty()) {
            config.model = profile.inference.models[0];
        }
        if (!profile.inference.max_tokens.empty()) {
            config.max_tokens = profile.inference.max_tokens[0];
        }
        if (!profile.inference.temperatures.empty()) {
            config.temperature = profile.inference.temperatures[0];
        }
        config.seed = profile.inference.default_seed;
        
        // Apply load parameters
        // (Config-specific application)
    }

    // Create a composite profile from multiple profiles
    WorkloadProfile ComposeProfile(const std::vector<std::string>& profile_names,
                                   std::vector<ValidationError>& errors) {
        WorkloadProfile composite;
        composite.name = "composite";
        composite.description = "Composed from multiple profiles";
        
        for (const auto& name : profile_names) {
            auto profile = LoadFromFile(name, errors);
            if (profile) {
                MergeProfile(composite, *profile);
            }
        }
        
        return composite;
    }

    // Print profile summary
    static void PrintProfile(const WorkloadProfile& profile) {
        std::cout << "\nWorkload Profile: " << profile.name << "\n";
        std::cout << std::string(50, '-') << "\n";
        std::cout << "Description: " << profile.description << "\n";
        std::cout << "Version: " << profile.version << "\n\n";
        
        std::cout << "Inference Parameters:\n";
        std::cout << "  Models: ";
        for (const auto& m : profile.inference.models) {
            std::cout << m << " ";
        }
        std::cout << "\n";
        std::cout << "  Max Tokens: ";
        for (const auto& t : profile.inference.max_tokens) {
            std::cout << t << " ";
        }
        std::cout << "\n";
        std::cout << "  Temperatures: ";
        for (const auto& t : profile.inference.temperatures) {
            std::cout << t << " ";
        }
        std::cout << "\n";
        std::cout << "  Default Seed: " << profile.inference.default_seed << "\n\n";
        
        std::cout << "Load Parameters:\n";
        std::cout << "  Warmup Runs: " << profile.load.warmup_runs << "\n";
        std::cout << "  Measured Runs: " << profile.load.measured_runs << "\n";
        std::cout << "  Duration: " << profile.load.duration_seconds << "s\n";
        std::cout << "  Concurrency Levels: ";
        for (const auto& c : profile.load.concurrency_levels) {
            std::cout << c << " ";
        }
        std::cout << "\n\n";
        
        if (!profile.custom_params.empty()) {
            std::cout << "Custom Parameters:\n";
            for (const auto& [key, value] : profile.custom_params) {
                std::cout << "  " << key << " = " << value << "\n";
            }
        }
    }

private:
    std::string profiles_dir_;

    bool Validate(const WorkloadProfile& profile, std::vector<ValidationError>& errors) {
        bool valid = true;
        
        if (profile.name.empty()) {
            errors.push_back({"name", "Profile name is required"});
            valid = false;
        }
        
        if (profile.inference.models.empty()) {
            errors.push_back({"inference.models", "At least one model is required"});
            valid = false;
        }
        
        if (profile.load.measured_runs < 1) {
            errors.push_back({"load.measured_runs", "Must be at least 1"});
            valid = false;
        }
        
        return valid;
    }

    void MergeProfile(WorkloadProfile& target, const WorkloadProfile& source) {
        // Merge models
        for (const auto& model : source.inference.models) {
            if (std::find(target.inference.models.begin(), 
                         target.inference.models.end(), model) == target.inference.models.end()) {
                target.inference.models.push_back(model);
            }
        }
        
        // Merge prompts
        for (const auto& prompt : source.inference.prompts) {
            target.inference.prompts.push_back(prompt);
        }
        
        // Merge custom params
        for (const auto& [key, value] : source.custom_params) {
            target.custom_params[key] = value;
        }
    }

    // Predefined profiles
    WorkloadProfile CreateQuickTestProfile() {
        WorkloadProfile p;
        p.name = "quick_test";
        p.description = "Quick smoke test for rapid validation";
        p.inference.models = {"phi-4"};
        p.inference.max_tokens = {128};
        p.inference.temperatures = {0.0f};
        p.load.warmup_runs = 2;
        p.load.measured_runs = 10;
        p.load.duration_seconds = 30;
        p.load.concurrency_levels = {1, 4};
        p.stress.request_rates = {10};
        return p;
    }

    WorkloadProfile CreateStandardProfile() {
        WorkloadProfile p;
        p.name = "standard";
        p.description = "Standard benchmark suite for regular testing";
        p.inference.models = {"phi-4", "qwen2.5-7b"};
        p.inference.prompts = {
            "Explain quantum computing",
            "Write a Python function",
            "Summarize this article"
        };
        p.inference.max_tokens = {256, 512};
        p.inference.temperatures = {0.0f, 0.7f};
        p.load.warmup_runs = 5;
        p.load.measured_runs = 30;
        p.load.duration_seconds = 60;
        p.load.concurrency_levels = {1, 4, 8, 16};
        p.stress.request_rates = {10, 50, 100};
        p.stress.agent_counts = {4, 8, 16};
        return p;
    }

    WorkloadProfile CreateStressTestProfile() {
        WorkloadProfile p;
        p.name = "stress_test";
        p.description = "Extended stress and chaos testing";
        p.inference.models = {"phi-4", "qwen2.5-14b"};
        p.inference.max_tokens = {512, 1024};
        p.inference.temperatures = {0.0f};
        p.load.warmup_runs = 10;
        p.load.measured_runs = 100;
        p.load.duration_seconds = 300;
        p.load.concurrency_levels = {1, 8, 16, 32, 64};
        p.stress.stress_duration_seconds = 600;
        p.stress.request_rates = {10, 50, 100, 200, 500};
        p.stress.agent_counts = {4, 8, 16, 32, 64, 128};
        return p;
    }

    WorkloadProfile CreateCIProfile() {
        WorkloadProfile p;
        p.name = "ci";
        p.description = "CI-optimized profile for fast feedback";
        p.inference.models = {"phi-4"};
        p.inference.max_tokens = {128};
        p.inference.temperatures = {0.0f};
        p.load.warmup_runs = 3;
        p.load.measured_runs = 15;
        p.load.duration_seconds = 30;
        p.load.concurrency_levels = {1, 4, 8};
        p.stress.request_rates = {10, 50};
        p.custom_params["ci_mode"] = "true";
        p.custom_params["fail_fast"] = "true";
        return p;
    }
};

// Convenience function for loading profiles
std::optional<WorkloadProfileLoader::WorkloadProfile> LoadWorkloadProfile(
    const std::string& name_or_path,
    std::vector<WorkloadProfileLoader::ValidationError>& errors) {
    
    WorkloadProfileLoader loader;
    
    // Check if it's a file path or mode name
    if (name_or_path.find('.') != std::string::npos) {
        return loader.LoadFromFile(name_or_path, errors);
    } else {
        return loader.LoadAuto(name_or_path, errors);
    }
}

} // namespace Benchmark
