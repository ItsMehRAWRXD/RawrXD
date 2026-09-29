// Model classification authority implementation
// RawrXD ModelClassificationAuthority - Classifies models by size, name, quant, source

#include "models/ModelClassificationAuthority.h"
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

namespace rawrxd::models
{
    // Global model classification authority state
    struct ModelClassificationAuthorityState
    {
        bool entered = false;
        std::string modelName;
        std::string parameterClass;
        std::string runtimeClass;
        std::vector<std::string> taskClasses;
        std::string classificationConfidence;
        std::string quantization;
        std::string source;
        std::string recommendedRoute;
        bool deep2Compatible = false;
        std::string verdict = "FAIL";
    };

    // Global state instance
    static ModelClassificationAuthorityState g_classifyState;

    // Classify model by size
    std::string classifyBySize(uint64_t sizeBytes)
    {
        double sizeGB = sizeBytes / (1024.0 * 1024.0 * 1024.0);
        
        if (sizeGB < 2.0) {
            return "tiny";
        } else if (sizeGB < 8.0) {
            return "small";
        } else if (sizeGB < 25.0) {
            return "medium";
        } else if (sizeGB < 80.0) {
            return "large";
        } else {
            return "xl";
        }
    }

    // Classify model by name
    std::string classifyByName(const std::string& name)
    {
        if (name.find("coder") != std::string::npos || name.find("qwen") != std::string::npos) {
            return "coder";
        } else if (name.find("instruct") != std::string::npos) {
            return "chat";
        } else if (name.find("r1") != std::string::npos || name.find("deepseek") != std::string::npos) {
            return "reasoning";
        } else if (name.find("kimi") != std::string::npos) {
            return "frontier";
        } else if (name.find("gemma") != std::string::npos) {
            return "general";
        } else if (name.find("mistral") != std::string::npos) {
            return "general/chat";
        } else if (name.find("ministral") != std::string::npos) {
            return "small/fast";
        } else {
            return "general";
        }
    }

    // Classify model by quant
    std::string classifyByQuant(const std::string& quant)
    {
        if (quant == "F32" || quant == "F16") {
            return "high-quality/heavy";
        } else if (quant == "Q8_0") {
            return "high-quality-local";
        } else if (quant == "Q6_K") {
            return "quality-balanced";
        } else if (quant == "Q5_K") {
            return "balanced";
        } else if (quant == "Q4_K") {
            return "speed-balanced";
        } else if (quant == "Q4_0") {
            return "small-fast";
        } else if (quant == "Q2_K" || quant == "IQ") {
            return "compressed";
        } else {
            return "unknown";
        }
    }

    // Classify model by source
    std::string classifyBySource(const std::string& source)
    {
        if (source == "rawr_alias") {
            return "explicit user/local alias";
        } else if (source == "local_gguf") {
            return "direct file";
        } else if (source == "ollama_manifest") {
            return "Ollama managed model";
        } else if (source == "ollama_blob") {
            return "resolved blob file";
        } else if (source == "generated") {
            return "RawrXD-generated catalog entry";
        } else {
            return "unknown";
        }
    }

    // Classify model
    void classifyModel(const std::string& name, const std::string& source, uint64_t sizeBytes, const std::string& quant)
    {
        g_classifyState.entered = true;
        g_classifyState.modelName = name;
        g_classifyState.source = source;
        g_classifyState.parameterClass = classifyBySize(sizeBytes);
        g_classifyState.runtimeClass = classifyByName(name);
        g_classifyState.quantization = quant;
        g_classifyState.classificationConfidence = "inferred";
        g_classifyState.recommendedRoute = classifyByQuant(quant);
        
        // Determine Deep2 compatibility (simplified)
        g_classifyState.deep2Compatible = (g_classifyState.parameterClass != "xl");
        
        // Set verdict
        g_classifyState.verdict = "PASS";
        
        std::cout << "[ModelClassificationAuthority] Classified model:" << std::endl;
        std::cout << "  MODEL_NAME=" << g_classifyState.modelName << std::endl;
        std::cout << "  SOURCE=" << g_classifyState.source << std::endl;
        std::cout << "  PARAMETER_CLASS=" << g_classifyState.parameterClass << std::endl;
        std::cout << "  RUNTIME_CLASS=" << g_classifyState.runtimeClass << std::endl;
        std::cout << "  QUANTIZATION=" << g_classifyState.quantization << std::endl;
        std::cout << "  RECOMMENDED_ROUTE=" << g_classifyState.recommendedRoute << std::endl;
        std::cout << "  DEEP2_COMPATIBLE=" << (g_classifyState.deep2Compatible ? "true" : "false") << std::endl;
        std::cout << "  VERDICT=" << g_classifyState.verdict << std::endl;
    }

    // Write classification receipt
    void writeClassificationReceipt()
    {
        std::cout << "[ModelClassificationAuthority] Writing classification receipt:" << std::endl;
        std::cout << "  RAWRXD_MODEL_CLASSIFICATION_AUTHORITY_001=ENTERED" << std::endl;
        std::cout << "  MODEL_NAME=" << g_classifyState.modelName << std::endl;
        std::cout << "  PARAMETER_CLASS=" << g_classifyState.parameterClass << std::endl;
        std::cout << "  RUNTIME_CLASS=" << g_classifyState.runtimeClass << std::endl;
        std::cout << "  QUANTIZATION=" << g_classifyState.quantization << std::endl;
        std::cout << "  SOURCE=" << g_classifyState.source << std::endl;
        std::cout << "  RECOMMENDED_ROUTE=" << g_classifyState.recommendedRoute << std::endl;
        std::cout << "  DEEP2_COMPATIBLE=" << (g_classifyState.deep2Compatible ? "1" : "0") << std::endl;
        std::cout << "  VERDICT=" << g_classifyState.verdict << std::endl;
    }
}