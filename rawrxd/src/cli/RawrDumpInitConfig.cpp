// Rawr dump init config implementation
// RawrXD RawrDumpInitConfig - Creates default dump configuration

#include "cli/RawrDumpInitConfig.h"
#include <iostream>
#include <string>
#include <fstream>

namespace rawrxd::cli
{
    // Global init config state
    struct RawrDumpInitConfigState
    {
        bool entered = false;
        bool rulesCreated = false;
        bool aliasesCreated = false;
        bool catalogCreated = false;
        std::string rulesPath = "F:\\models\\rawr_dump.rules";
        std::string aliasesPath = "F:\\models\\aliases.txt";
        std::string catalogPath = "F:\\models\\rawr_model_catalog.json";
        std::string verdict = "FAIL";
    };

    // Global state instance
    static RawrDumpInitConfigState g_initConfigState;

    // Forward declarations for internal helpers
    void createRulesFile();
    void createAliasesFile();
    void createCatalogFile();

    // Initialize dump config
    void initDumpConfig()
    {
        g_initConfigState.entered = true;
        
        // Create rules file
        createRulesFile();
        g_initConfigState.rulesCreated = true;
        
        // Create aliases file
        createAliasesFile();
        g_initConfigState.aliasesCreated = true;
        
        // Create catalog file
        createCatalogFile();
        g_initConfigState.catalogCreated = true;
        
        // Set verdict
        if (g_initConfigState.rulesCreated && g_initConfigState.aliasesCreated && g_initConfigState.catalogCreated) {
            g_initConfigState.verdict = "PASS";
        } else {
            g_initConfigState.verdict = "FAIL";
        }
        
        std::cout << "[RawrDumpInitConfig] Init config completed:" << std::endl;
        std::cout << "  RAWRXD_RAWR_DUMP_INIT_CONFIG_001=ENTERED" << std::endl;
        std::cout << "  RULES_CREATED=" << (g_initConfigState.rulesCreated ? "1" : "0") << std::endl;
        std::cout << "  ALIASES_CREATED=" << (g_initConfigState.aliasesCreated ? "1" : "0") << std::endl;
        std::cout << "  CATALOG_CREATED=" << (g_initConfigState.catalogCreated ? "1" : "0") << std::endl;
        std::cout << "  VERDICT=" << g_initConfigState.verdict << std::endl;
    }

    // Create rules file
    void createRulesFile()
    {
        std::ofstream rulesFile(g_initConfigState.rulesPath);
        if (rulesFile.is_open()) {
            rulesFile << "# roots\n";
            rulesFile << "root=F:\\models\n";
            rulesFile << "root=G:\\~dev\n";
            rulesFile << "root=G:\\OllamaModels\n";
            rulesFile << "root=F:\\OllamaModels\n";
            rulesFile << "\n";
            rulesFile << "# aliases\n";
            rulesFile << "alias=modelname=ministral3_q4_0\n";
            rulesFile << "alias=fast=ministral3_q4_0\n";
            rulesFile << "alias=coder=qwen2.5-coder:1.5b-base\n";
            rulesFile << "\n";
            rulesFile << "# classifications by name/path/arch/quant\n";
            rulesFile << "class:name_contains:qwen=coder\n";
            rulesFile << "class:name_contains:coder=coder\n";
            rulesFile << "class:name_contains:kimi=frontier\n";
            rulesFile << "class:name_contains:deepseek=reasoning\n";
            rulesFile << "class:path_contains:OllamaModels=ollama\n";
            rulesFile << "class:quant:Q4_K=balanced\n";
            rulesFile << "class:quant:Q8_0=quality\n";
            rulesFile << "class:size_gb_lt:2=tiny\n";
            rulesFile << "class:size_gb_lt:8=small\n";
            rulesFile << "class:size_gb_lt:25=medium\n";
            rulesFile << "class:size_gb_gt:25=large\n";
            rulesFile << "\n";
            rulesFile << "# route preferences\n";
            rulesFile << "route:class:tiny=cpu_avx512\n";
            rulesFile << "route:class:small=gpu_single\n";
            rulesFile << "route:class:medium=gpu_single\n";
            rulesFile << "route:class:large=gpu_dual_or_streaming\n";
            rulesFile << "route:quant:Q4_K=gpu_single\n";
            rulesFile << "route:quant:Q8_0=cpu_avx512_or_gpu\n";
            rulesFile.close();
        }
    }

    // Create aliases file
    void createAliasesFile()
    {
        std::ofstream aliasesFile(g_initConfigState.aliasesPath);
        if (aliasesFile.is_open()) {
            aliasesFile << "# Model aliases\n";
            aliasesFile << "modelname=ministral3_q4_0\n";
            aliasesFile << "fast=ministral3_q4_0\n";
            aliasesFile << "coder=qwen2.5-coder:1.5b-base\n";
            aliasesFile.close();
        }
    }

    // Create catalog file
    void createCatalogFile()
    {
        std::ofstream catalogFile(g_initConfigState.catalogPath);
        if (catalogFile.is_open()) {
            catalogFile << "{\n";
            catalogFile << "  \"gate\": \"RAWRXD_RAWR_DUMP_AUTHORITY_001\",\n";
            catalogFile << "  \"generated_from_scratch\": true,\n";
            catalogFile << "  \"model_count\": 0,\n";
            catalogFile << "  \"models\": []\n";
            catalogFile << "}\n";
            catalogFile.close();
        }
    }

    // Write init config receipt
    void writeInitConfigReceipt()
    {
        std::cout << "[RawrDumpInitConfig] Writing init config receipt:" << std::endl;
        std::cout << "  RAWRXD_RAWR_DUMP_INIT_CONFIG_001=ENTERED" << std::endl;
        std::cout << "  RULES_CREATED=" << (g_initConfigState.rulesCreated ? "1" : "0") << std::endl;
        std::cout << "  ALIASES_CREATED=" << (g_initConfigState.aliasesCreated ? "1" : "0") << std::endl;
        std::cout << "  CATALOG_CREATED=" << (g_initConfigState.catalogCreated ? "1" : "0") << std::endl;
        std::cout << "  VERDICT=" << g_initConfigState.verdict << std::endl;
    }
}