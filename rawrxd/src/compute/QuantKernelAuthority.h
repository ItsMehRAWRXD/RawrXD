#pragma once

// Quant kernel authority - Gates all quantization kernel selection and execution
// This authority ensures every quant kernel is explicitly registered, selected, and measured

namespace rawrxd::compute
{
    // Resolve quantization kernel
    void resolveKernel(const std::string& quantType, const std::string& kernel);
    
    // Execute quantization kernel
    void executeKernel(const std::string& quantType, const std::string& kernel);
    
    // Record kernel selection
    void recordKernelSelection(const std::string& quantType, const std::string& kernel, bool success);
    
    // Write quant kernel receipt
    void writeQuantKernelReceipt();
}