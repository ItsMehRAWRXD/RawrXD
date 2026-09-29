#pragma once

// GGUF metadata probe - Probes GGUF metadata from model files
// This authority probes GGUF metadata from model files to extract model information

namespace rawrxd::models
{
    // Probe GGUF metadata
    void probeGgufMetadata(const std::string& modelPath);
    
    // Probe all GGUF metadata
    void probeAllGgufMetadata();
    
    // Get GGUF version
    int getGgufVersion();
    
    // Get GGUF arch
    std::string getGgufArch();
    
    // Get GGUF name
    std::string getGgufName();
    
    // Get quantization
    std::string getQuantization();
    
    // Get file size
    uint64_t getFileSizeBytes();
    
    // Write GGUF metadata probe receipt
    void writeGgufMetadataProbeReceipt();
}
