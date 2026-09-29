#pragma once
#include <string>
#include <vector>

// Ollama catalog reader - Reads Ollama manifests and blobs
// This authority reads Ollama manifests and blobs to build the model catalog

namespace rawrxd::models
{
    // Read Ollama manifests
    void readOllamaManifests();
    
    // Read Ollama blobs
    void readOllamaBlobs();
    
    // Get Ollama model name
    std::string getOllamaModelName(const std::string& modelPath);
    
    // Get Ollama manifest path
    std::string getOllamaManifestPath(const std::string& modelName);
    
    // Get Ollama blob path
    std::string getOllamaBlobPath(const std::string& sha256);
    
    // Write Ollama catalog receipt
    void writeOllamaCatalogReceipt();
}
