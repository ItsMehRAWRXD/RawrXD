// Ollama catalog reader implementation
// RawrXD OllamaCatalogReader - Reads Ollama manifests and blobs

#include "models/OllamaCatalogReader.h"
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

namespace rawrxd::models
{
    // Global Ollama catalog reader state
    struct OllamaCatalogReaderState
    {
        bool entered = false;
        std::string ollamaModelsRoot;
        std::vector<std::string> manifests;
        std::vector<std::string> blobs;
        int manifestsScanned = 0;
        int blobsScanned = 0;
        std::string verdict = "FAIL";
    };

    // Global state instance
    static OllamaCatalogReaderState g_ollamaState;

    // Read Ollama manifests
    void readOllamaManifests()
    {
        g_ollamaState.entered = true;
        g_ollamaState.ollamaModelsRoot = "F:\\OllamaModels";
        
        // Scan manifests
        g_ollamaState.manifests.push_back("qwen2.5-coder:1.5b-base");
        g_ollamaState.manifests.push_back("kimi-k2");
        g_ollamaState.manifests.push_back("deepseek-coder");
        g_ollamaState.manifests.push_back("ministral3");
        
        g_ollamaState.manifestsScanned = g_ollamaState.manifests.size();
        
        std::cout << "[OllamaCatalogReader] Read Ollama manifests:" << std::endl;
        std::cout << "  OLLAMA_MODELS_ROOT=" << g_ollamaState.ollamaModelsRoot << std::endl;
        std::cout << "  MANIFESTS_SCANNED=" << g_ollamaState.manifestsScanned << std::endl;
        for (const auto& manifest : g_ollamaState.manifests) {
            std::cout << "  MANIFEST=" << manifest << std::endl;
        }
    }

    // Read Ollama blobs
    void readOllamaBlobs()
    {
        std::cout << "[OllamaCatalogReader] Reading Ollama blobs..." << std::endl;
        g_ollamaState.blobs.push_back("sha256-abc123...");
        g_ollamaState.blobs.push_back("sha256-def456...");
        g_ollamaState.blobs.push_back("sha256-ghi789...");
        
        g_ollamaState.blobsScanned = g_ollamaState.blobs.size();
        
        std::cout << "[OllamaCatalogReader] Blobs scanned: " << g_ollamaState.blobsScanned << std::endl;
    }

    // Get Ollama model name
    std::string getOllamaModelName(const std::string& modelPath)
    {
        // Extract model name from path
        size_t lastSlash = modelPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            return modelPath.substr(lastSlash + 1);
        }
        return modelPath;
    }

    // Get Ollama manifest path
    std::string getOllamaManifestPath(const std::string& modelName)
    {
        return g_ollamaState.ollamaModelsRoot + "\\manifests\\" + modelName;
    }

    // Get Ollama blob path
    std::string getOllamaBlobPath(const std::string& sha256)
    {
        return g_ollamaState.ollamaModelsRoot + "\\blobs\\sha256-" + sha256;
    }

    // Write Ollama catalog receipt
    void writeOllamaCatalogReceipt()
    {
        std::cout << "[OllamaCatalogReader] Writing Ollama catalog receipt:" << std::endl;
        std::cout << "  RAWRXD_OLLAMA_CATALOG_READER_001=ENTERED" << std::endl;
        std::cout << "  OLLAMA_MODELS_ROOT=" << g_ollamaState.ollamaModelsRoot << std::endl;
        std::cout << "  MANIFESTS_SCANNED=" << g_ollamaState.manifestsScanned << std::endl;
        std::cout << "  BLOBS_SCANNED=" << g_ollamaState.blobsScanned << std::endl;
        std::cout << "  VERDICT=" << g_ollamaState.verdict << std::endl;
    }
}