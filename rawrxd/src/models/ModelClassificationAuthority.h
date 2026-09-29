#pragma once

// Model classification authority - Classifies models by size, name, quant, source
// This authority classifies models based on size, name, quantization, and source

namespace rawrxd::models
{
    // Classify model by size
    std::string classifyBySize(uint64_t sizeBytes);
    
    // Classify model by name
    std::string classifyByName(const std::string& name);
    
    // Classify model by quant
    std::string classifyByQuant(const std::string& quant);
    
    // Classify model by source
    std::string classifyBySource(const std::string& source);
    
    // Classify model
    void classifyModel(const std::string& name, const std::string& source, uint64_t sizeBytes, const std::string& quant);
    
    // Write classification receipt
    void writeClassificationReceipt();
}
