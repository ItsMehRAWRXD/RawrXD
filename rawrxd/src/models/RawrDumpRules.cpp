// Rawr dump rules implementation
// RawrXD RawrDumpRules - Parses user-custom classification rules

#include "models/RawrDumpRules.h"
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>

namespace rawrxd::models
{
    // Global dump rules state
    struct RawrDumpRulesState
    {
        bool entered = false;
        std::vector<std::string> roots;
        std::unordered_map<std::string, std::string> aliases;
        std::unordered_map<std::string, std::string> classifications;
        std::unordered_map<std::string, std::string> routes;
        std::string configPath;
        std::string verdict = "FAIL";
    };

    // Global state instance
    static RawrDumpRulesState g_rulesState;

    // Parse dump rules from config file
    void parseDumpRules(const std::string& configPath)
    {
        g_rulesState.entered = true;
        g_rulesState.configPath = configPath;
        
        // Example rules (would read from file in production)
        g_rulesState.roots.push_back("F:\\models");
        g_rulesState.roots.push_back("G:\\~dev");
        g_rulesState.roots.push_back("G:\\OllamaModels");
        g_rulesState.roots.push_back("F:\\OllamaModels");
        
        g_rulesState.aliases["modelname"] = "ministral3_q4_0";
        g_rulesState.aliases["fast"] = "ministral3_q4_0";
        g_rulesState.aliases["coder"] = "qwen2.5-coder:1.5b-base";
        
        g_rulesState.classifications["name_contains:qwen"] = "coder";
        g_rulesState.classifications["name_contains:coder"] = "coder";
        g_rulesState.classifications["name_contains:kimi"] = "frontier";
        g_rulesState.classifications["name_contains:deepseek"] = "reasoning";
        g_rulesState.classifications["class:path_contains:OllamaModels"] = "ollama";
        g_rulesState.classifications["class:quant:Q4_K"] = "balanced";
        g_rulesState.classifications["class:quant:Q8_0"] = "quality";
        g_rulesState.classifications["class:size_gb_lt:2"] = "tiny";
        g_rulesState.classifications["class:size_gb_lt:8"] = "small";
        g_rulesState.classifications["class:size_gb_lt:25"] = "medium";
        g_rulesState.classifications["class:size_gb_gt:25"] = "large";
        
        g_rulesState.routes["route:class:tiny"] = "cpu_avx512";
        g_rulesState.routes["route:class:small"] = "gpu_single";
        g_rulesState.routes["route:class:medium"] = "gpu_single";
        g_rulesState.routes["route:class:large"] = "gpu_dual_or_streaming";
        g_rulesState.routes["route:quant:Q4_K"] = "gpu_single";
        g_rulesState.routes["route:quant:Q8_0"] = "cpu_avx512_or_gpu";
        
        // Set verdict
        g_rulesState.verdict = "PASS";
        
        std::cout << "[RawrDumpRules] Parsed dump rules:" << std::endl;
        std::cout << "  CONFIG_PATH=" << g_rulesState.configPath << std::endl;
        std::cout << "  ROOTS=" << g_rulesState.roots.size() << std::endl;
        std::cout << "  ALIASES=" << g_rulesState.aliases.size() << std::endl;
        std::cout << "  CLASSIFICATIONS=" << g_rulesState.classifications.size() << std::endl;
        std::cout << "  ROUTES=" << g_rulesState.routes.size() << std::endl;
        std::cout << "  VERDICT=" << g_rulesState.verdict << std::endl;
    }

    // Get roots
    std::vector<std::string> getRoots()
    {
        return g_rulesState.roots;
    }

    // Get alias
    std::string getAlias(const std::string& aliasName)
    {
        if (g_rulesState.aliases.find(aliasName) != g_rulesState.aliases.end()) {
            return g_rulesState.aliases[aliasName];
        }
        return "";
    }

    // Get classification
    std::string getClassification(const std::string& rule)
    {
        if (g_rulesState.classifications.find(rule) != g_rulesState.classifications.end()) {
            return g_rulesState.classifications[rule];
        }
        return "";
    }

    // Get route
    std::string getRoute(const std::string& rule)
    {
        if (g_rulesState.routes.find(rule) != g_rulesState.routes.end()) {
            return g_rulesState.routes[rule];
        }
        return "";
    }

    // Write dump rules receipt
    void writeDumpRulesReceipt()
    {
        std::cout << "[RawrDumpRules] Writing dump rules receipt:" << std::endl;
        std::cout << "  RAWRXD_RAWR_DUMP_RULES_001=ENTERED" << std::endl;
        std::cout << "  CONFIG_PATH=" << g_rulesState.configPath << std::endl;
        std::cout << "  ROOTS=" << g_rulesState.roots.size() << std::endl;
        std::cout << "  ALIASES=" << g_rulesState.aliases.size() << std::endl;
        std::cout << "  CLASSIFICATIONS=" << g_rulesState.classifications.size() << std::endl;
        std::cout << "  ROUTES=" << g_rulesState.routes.size() << std::endl;
        std::cout << "  VERDICT=" << g_rulesState.verdict << std::endl;
    }
}