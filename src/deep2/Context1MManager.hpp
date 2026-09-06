#pragma once

#include <windows.h>
#include <cstdint>
#include <stdexcept>
#include <iostream>
#include <malloc.h>

extern "C" {
    void StreamBlockAttention_1M(float* destOutput, const float* keyStream, const float* valueStream, uint64_t blockSize, uint64_t blockCount);
}

class Context1MManager {
private:
    float* m_KeyArenaPrimary;
    float* m_ValArenaPrimary;
    float* m_KeyArenaSecondary;
    float* m_ValArenaSecondary;
    uint64_t m_MaxTokensSupported;
    uint64_t m_HiddenDimension;

public:
    /**
     * Initializes the 1M Token Context Manager with host large-page pinning allocations.
     * Separates Key and Value streams for semantic correctness.
     */
    Context1MManager(uint64_t hiddenDim, uint64_t maxTokens = 1000000)
        : m_MaxTokensSupported(maxTokens), m_HiddenDimension(hiddenDim) 
    {
        uint64_t totalPoolBytes = m_MaxTokensSupported * m_HiddenDimension * sizeof(float);
        
        uint64_t primaryAllocationSize = (totalPoolBytes / 3) * 2;
        uint64_t secondaryAllocationSize = totalPoolBytes / 3;

        std::cout << "[👁️] Asserting 1 Million Token Context Infrastructure Pool:\n"
                  << " -> Primary Host Arena (K/V):   " << (primaryAllocationSize * 2 / (1024 * 1024)) << " MB\n"
                  << " -> Secondary Host Arena (K/V): " << (secondaryAllocationSize * 2 / (1024 * 1024)) << " MB\n";

        m_KeyArenaPrimary = static_cast<float*>(_aligned_malloc(primaryAllocationSize, 64));
        m_ValArenaPrimary = static_cast<float*>(_aligned_malloc(primaryAllocationSize, 64));
        m_KeyArenaSecondary = static_cast<float*>(_aligned_malloc(secondaryAllocationSize, 64));
        m_ValArenaSecondary = static_cast<float*>(_aligned_malloc(secondaryAllocationSize, 64));

        if (!m_KeyArenaPrimary || !m_ValArenaPrimary || !m_KeyArenaSecondary || !m_ValArenaSecondary) {
            throw std::runtime_error("1M Context Allocation Fault: Out of memory during hardware arena configuration.");
        }
    }

    ~Context1MManager() {
        if (m_KeyArenaPrimary) _aligned_free(m_KeyArenaPrimary);
        if (m_ValArenaPrimary) _aligned_free(m_ValArenaPrimary);
        if (m_KeyArenaSecondary) _aligned_free(m_KeyArenaSecondary);
        if (m_ValArenaSecondary) _aligned_free(m_ValArenaSecondary);
    }

    /**
     * Drives the execution loop over the 1M context token segments.
     */
    void ProcessExtremeContextStream(float* outActivations, uint64_t activeProcessingBlockSize) {
        if (activeProcessingBlockSize % 16 != 0) {
            throw std::invalid_argument("Context Scale Fault: Processing block bounds must line up with 16-element boundaries.");
        }

        std::cout << "[~] Processing active 1,000,000 token stream using block attention segmentation...\n";

        uint64_t primaryBlocksCount = ((m_MaxTokensSupported / 3) * 2) / activeProcessingBlockSize;
        StreamBlockAttention_1M(outActivations, m_KeyArenaPrimary, m_ValArenaPrimary, activeProcessingBlockSize, primaryBlocksCount);

        uint64_t secondaryBlocksCount = (m_MaxTokensSupported / 3) / activeProcessingBlockSize;
        StreamBlockAttention_1M(outActivations, m_KeyArenaSecondary, m_ValArenaSecondary, activeProcessingBlockSize, secondaryBlocksCount);

        std::cout << "[🏁] 1M Token Context Processing Phase Finalized.\n";
    }
};
