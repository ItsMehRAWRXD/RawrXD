#pragma once

// Tensor compute authority - Gates all tensor validation and computation
// This authority ensures every tensor is explicitly validated, tracked, and measured

namespace rawrxd::compute
{
    // Validate a tensor
    void validateTensor(const std::string& tensorName, int rows, int cols, 
                       const std::string& quantType, size_t sizeBytes,
                       const std::string& fileOffset, bool mapped,
                       const std::string& backendRoute, const std::string& kernelUsed);
    
    // Record tensor use
    void recordTensorUse(const std::string& tensorName);
    
    // Record tensor failure
    void recordTensorFailure(const std::string& tensorName, const std::string& reason);
    
    // Write tensor receipt
    void writeTensorReceipt();
}