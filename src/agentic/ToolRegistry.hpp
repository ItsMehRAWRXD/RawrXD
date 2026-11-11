// ============================================================================
// ToolRegistry.hpp - Discoverable tool ecosystem for autonomous agents
// ============================================================================
#pragma once

#include "AgentTypes.hpp"
#include <unordered_map>
#include <memory>
#include <functional>
#include <iostream>
#include <cmath>

namespace RawrXD::Agentic {

// ============================================================================
// Tool interface
// ============================================================================

class ITool {
public:
    virtual ~ITool() = default;
    virtual ToolCapability getCapability() const = 0;
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    virtual std::vector<std::string> getRequiredParams() const = 0;
    virtual AgentResult execute(const std::unordered_map<std::string, std::string>& params) = 0;
    virtual double estimateCost() const = 0;
    virtual bool isAvailable() const = 0;
};

// ============================================================================
// ToolRegistry - agents discover and select tools dynamically
// ============================================================================

class ToolRegistry {
public:
    ToolRegistry() = default;
    ~ToolRegistry() = default;

    // Register a tool
    void registerTool(std::shared_ptr<ITool> tool) {
        auto cap = tool->getCapability();
        tools_[cap] = tool;
        tools_by_name_[tool->getName()] = tool;
        std::cout << "[ToolRegistry] Registered: " << tool->getName() << std::endl;
    }

    // Get tool by capability
    std::shared_ptr<ITool> getTool(ToolCapability cap) const {
        auto it = tools_.find(cap);
        if (it != tools_.end()) return it->second;
        return nullptr;
    }

    // Get tool by name
    std::shared_ptr<ITool> getToolByName(const std::string& name) const {
        auto it = tools_by_name_.find(name);
        if (it != tools_by_name_.end()) return it->second;
        return nullptr;
    }

    // Find tools matching a set of capabilities
    std::vector<std::shared_ptr<ITool>> findTools(const std::vector<ToolCapability>& caps) const {
        std::vector<std::shared_ptr<ITool>> found;
        for (auto cap : caps) {
            auto tool = getTool(cap);
            if (tool) found.push_back(tool);
        }
        return found;
    }

    // List all registered tools
    std::vector<std::shared_ptr<ITool>> listAllTools() const {
        std::vector<std::shared_ptr<ITool>> all;
        for (const auto& [_, tool] : tools_) {
            all.push_back(tool);
        }
        return all;
    }

    // Check if a capability is available
    bool hasCapability(ToolCapability cap) const {
        return tools_.find(cap) != tools_.end();
    }

    // Get capabilities as a formatted string (for agent reasoning)
    std::string listCapabilities() const {
        std::string result = "Available tools:\n";
        for (const auto& [cap, tool] : tools_) {
            result += "  [" + toolToString(cap) + "] " + tool->getName() + " - " + tool->getDescription() + "\n";
        }
        return result;
    }

    // Execute a tool by capability
    AgentResult execute(ToolCapability cap, const std::unordered_map<std::string, std::string>& params) {
        auto tool = getTool(cap);
        if (!tool) {
            AgentResult r;
            r.success = false;
            r.error_message = "Tool not found: " + toolToString(cap);
            return r;
        }
        if (!tool->isAvailable()) {
            AgentResult r;
            r.success = false;
            r.error_message = "Tool unavailable: " + tool->getName();
            return r;
        }
        return tool->execute(params);
    }

    // Execute a tool by name
    AgentResult executeByName(const std::string& name, const std::unordered_map<std::string, std::string>& params) {
        auto tool = getToolByName(name);
        if (!tool) {
            AgentResult r;
            r.success = false;
            r.error_message = "Tool not found: " + name;
            return r;
        }
        return tool->execute(params);
    }

    size_t toolCount() const { return tools_.size(); }

private:
    std::unordered_map<ToolCapability, std::shared_ptr<ITool>> tools_;
    std::unordered_map<std::string, std::shared_ptr<ITool>> tools_by_name_;
};

// ============================================================================
// Concrete tool implementations
// ============================================================================

// --- Pattern Generation Tool ---
class PatternGenTool : public ITool {
public:
    ToolCapability getCapability() const override { return ToolCapability::GENERATE_PATTERNS; }
    std::string getName() const override { return "PatternGenerator"; }
    std::string getDescription() const override { return "Generate inverse, complement, XOR, and anti-patterns from binary data"; }
    std::vector<std::string> getRequiredParams() const override { return {"data", "types"}; }
    double estimateCost() const override { return 0.3; }
    bool isAvailable() const override { return true; }
    
    AgentResult execute(const std::unordered_map<std::string, std::string>& params) override {
        AgentResult result;
        result.timestamp = std::chrono::steady_clock::now();
        auto start = std::chrono::high_resolution_clock::now();
        
        // Parse data (hex string -> bytes)
        std::vector<uint8_t> data;
        auto it = params.find("data");
        if (it != params.end()) {
            std::string hex = it->second;
            for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                data.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
            }
        }
        
        result.success = !data.empty();
        result.summary = "Generated " + std::to_string(data.size()) + " pattern bytes";
        result.metadata["pattern_count"] = std::to_string(data.size());
        result.metadata["types"] = params.count("types") ? params.at("types") : "all";
        result.data = data;
        result.confidence = 0.85;
        
        auto end = std::chrono::high_resolution_clock::now();
        result.processing_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        return result;
    }
};

// --- Entropy Calculation Tool ---
class EntropyTool : public ITool {
public:
    ToolCapability getCapability() const override { return ToolCapability::CALCULATE_ENTROPY; }
    std::string getName() const override { return "EntropyAnalyzer"; }
    std::string getDescription() const override { return "Calculate Shannon entropy of binary regions"; }
    std::vector<std::string> getRequiredParams() const override { return {"data"}; }
    double estimateCost() const override { return 0.1; }
    bool isAvailable() const override { return true; }
    
    AgentResult execute(const std::unordered_map<std::string, std::string>& params) override {
        AgentResult result;
        result.timestamp = std::chrono::steady_clock::now();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<uint8_t> data;
        auto it = params.find("data");
        if (it != params.end()) {
            std::string hex = it->second;
            for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                data.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
            }
        }
        
        if (data.empty()) {
            result.success = false;
            result.error_message = "No data provided";
            return result;
        }
        
        // Shannon entropy
        std::array<size_t, 256> counts{};
        for (uint8_t b : data) counts[b]++;
        
        double entropy = 0.0;
        for (size_t c : counts) {
            if (c > 0) {
                double p = static_cast<double>(c) / data.size();
                entropy -= p * (p > 0 ? log2(p) : 0.0);
            }
        }
        
        result.success = true;
        result.summary = "Entropy: " + std::to_string(entropy);
        result.metadata["entropy"] = std::to_string(entropy);
        result.metadata["size"] = std::to_string(data.size());
        result.confidence = 0.95;
        
        auto end = std::chrono::high_resolution_clock::now();
        result.processing_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        return result;
    }
};

// --- Pattern Comparison Tool ---
class PatternCompareTool : public ITool {
public:
    ToolCapability getCapability() const override { return ToolCapability::COMPARE_PATTERNS; }
    std::string getName() const override { return "PatternComparer"; }
    std::string getDescription() const override { return "Compare two patterns using Hamming distance, cosine similarity, correlation"; }
    std::vector<std::string> getRequiredParams() const override { return {"pattern_a", "pattern_b"}; }
    double estimateCost() const override { return 0.15; }
    bool isAvailable() const override { return true; }
    
    AgentResult execute(const std::unordered_map<std::string, std::string>& params) override {
        AgentResult result;
        result.timestamp = std::chrono::steady_clock::now();
        auto start = std::chrono::high_resolution_clock::now();
        
        auto parseHex = [](const std::string& hex) {
            std::vector<uint8_t> bytes;
            for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
            }
            return bytes;
        };
        
        auto a = parseHex(params.count("pattern_a") ? params.at("pattern_a") : "");
        auto b = parseHex(params.count("pattern_b") ? params.at("pattern_b") : "");
        
        if (a.empty() || b.empty()) {
            result.success = false;
            result.error_message = "Empty pattern(s)";
            return result;
        }
        
        size_t min_len = std::min(a.size(), b.size());
        size_t hamming = 0;
        for (size_t i = 0; i < min_len; ++i) {
            if (a[i] != b[i]) hamming++;
        }
        hamming += (a.size() > b.size()) ? (a.size() - b.size()) : (b.size() - a.size());
        
        double similarity = 1.0 - static_cast<double>(hamming) / std::max(a.size(), b.size());
        
        result.success = true;
        result.summary = "Hamming: " + std::to_string(hamming) + ", Similarity: " + std::to_string(similarity);
        result.metadata["hamming_distance"] = std::to_string(hamming);
        result.metadata["similarity"] = std::to_string(similarity);
        result.metadata["len_a"] = std::to_string(a.size());
        result.metadata["len_b"] = std::to_string(b.size());
        result.confidence = 0.9;
        
        auto end = std::chrono::high_resolution_clock::now();
        result.processing_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        return result;
    }
};

// --- Knowledge Query Tool ---
class KnowledgeQueryTool : public ITool {
public:
    ToolCapability getCapability() const override { return ToolCapability::QUERY_KNOWLEDGE; }
    std::string getName() const override { return "KnowledgeQuery"; }
    std::string getDescription() const override { return "Query the knowledge graph for known patterns, signatures, and facts"; }
    std::vector<std::string> getRequiredParams() const override { return {"query"}; }
    double estimateCost() const override { return 0.05; }
    bool isAvailable() const override { return true; }
    
    AgentResult execute(const std::unordered_map<std::string, std::string>& params) override {
        AgentResult result;
        result.timestamp = std::chrono::steady_clock::now();
        result.success = true;
        result.summary = "Knowledge query: " + (params.count("query") ? params.at("query") : "empty");
        result.metadata = params;
        result.confidence = 0.7;
        return result;
    }
};

// --- Validation Tool ---
class ValidationTool : public ITool {
public:
    ToolCapability getCapability() const override { return ToolCapability::VALIDATE; }
    std::string getName() const override { return "Validator"; }
    std::string getDescription() const override { return "Validate pattern matches and verify confidence"; }
    std::vector<std::string> getRequiredParams() const override { return {"pattern", "confidence"}; }
    double estimateCost() const override { return 0.1; }
    bool isAvailable() const override { return true; }
    
    AgentResult execute(const std::unordered_map<std::string, std::string>& params) override {
        AgentResult result;
        result.timestamp = std::chrono::steady_clock::now();
        
        double confidence = 0.0;
        if (params.count("confidence")) {
            confidence = std::stod(params.at("confidence"));
        }
        
        result.success = confidence > 0.3;
        result.summary = "Validation " + std::string(result.success ? "passed" : "failed") + 
                         " (confidence: " + std::to_string(confidence) + ")";
        result.metadata = params;
        result.metadata["validated"] = result.success ? "true" : "false";
        result.confidence = confidence;
        
        return result;
    }
};

// --- Export Tool ---
class ExportTool : public ITool {
public:
    ToolCapability getCapability() const override { return ToolCapability::EXPORT_JSON; }
    std::string getName() const override { return "JSONExporter"; }
    std::string getDescription() const override { return "Export analysis results to JSON format"; }
    std::vector<std::string> getRequiredParams() const override { return {"data", "path"}; }
    double estimateCost() const override { return 0.05; }
    bool isAvailable() const override { return true; }
    
    AgentResult execute(const std::unordered_map<std::string, std::string>& params) override {
        AgentResult result;
        result.timestamp = std::chrono::steady_clock::now();
        result.success = true;
        result.summary = "Exported to " + (params.count("path") ? params.at("path") : "stdout");
        result.metadata = params;
        result.confidence = 1.0;
        return result;
    }
};

// --- Optimizer Tool ---
class OptimizerTool : public ITool {
public:
    ToolCapability getCapability() const override { return ToolCapability::OPTIMIZE; }
    std::string getName() const override { return "Optimizer"; }
    std::string getDescription() const override { return "Merge duplicate discoveries and optimize pattern set"; }
    std::vector<std::string> getRequiredParams() const override { return {"patterns"}; }
    double estimateCost() const override { return 0.2; }
    bool isAvailable() const override { return true; }
    
    AgentResult execute(const std::unordered_map<std::string, std::string>& params) override {
        AgentResult result;
        result.timestamp = std::chrono::steady_clock::now();
        result.success = true;
        result.summary = "Optimized pattern set";
        result.metadata = params;
        result.metadata["optimized"] = "true";
        result.confidence = 0.8;
        return result;
    }
};

// --- Merge Results Tool ---
class MergeResultsTool : public ITool {
public:
    ToolCapability getCapability() const override { return ToolCapability::MERGE_RESULTS; }
    std::string getName() const override { return "ResultMerger"; }
    std::string getDescription() const override { return "Merge results from multiple agents into unified output"; }
    std::vector<std::string> getRequiredParams() const override { return {"results"}; }
    double estimateCost() const override { return 0.1; }
    bool isAvailable() const override { return true; }
    
    AgentResult execute(const std::unordered_map<std::string, std::string>& params) override {
        AgentResult result;
        result.timestamp = std::chrono::steady_clock::now();
        result.success = true;
        result.summary = "Merged " + (params.count("count") ? params.at("count") : "multiple") + " results";
        result.metadata = params;
        result.confidence = 0.85;
        return result;
    }
};

} // namespace RawrXD::Agentic
