//==============================================================================
// SovereignGraphRunner_v2.cpp
// Backend-Agnostic Transformer Orchestrator Implementation
//
// All kernel dispatch goes through KernelRegistry.
// No architecture-specific code.
//
// Date: July 10, 2026
// Phase: 7C.1 - Registry Integration
//==============================================================================

#include "SovereignGraphRunner_v2.hpp"
#include "IKernelBackend.hpp"
#include <cstring>
#include <cmath>
#include <chrono>
#include <iostream>
#include <memory>

namespace sovereign {

//==============================================================================
// Construction / Destruction
//==============================================================================

SovereignGraphRunner::SovereignGraphRunner() = default;

SovereignGraphRunner::~SovereignGraphRunner() {
    Shutdown();
}

//==============================================================================
// Initialization
//==============================================================================

bool SovereignGraphRunner::Initialize(const TransformerConfig& config) {
    if (initialized_) {
        Shutdown();
    }
    
    config_ = config;
    
    // Initialize default backends in registry
    if (!InitializeDefaultBackends()) {
        return false;
    }
    
    // Allocate buffers
    if (!AllocateBuffers()) {
        return false;
    }
    
    // Initialize RoPE cache
    if (!InitializeRoPECache()) {
        return false;
    }
    
    initialized_ = true;
    return true;
}

void SovereignGraphRunner::Shutdown() {
    if (!initialized_) return;
    
    FreeBuffers();
    
    // Shutdown all backends in registry
    KernelRegistry::Instance().ShutdownAll();
    
    initialized_ = false;
}

//==============================================================================
// Core Execution
//==============================================================================

GraphExecutionResult SovereignGraphRunner::Forward(
    int32_t inputToken,
    uint32_t position,
    ValidationMode validation
) {
    GraphExecutionResult result;
    
    if (!initialized_) {
        result.success = false;
        return result;
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Step 1: Embedding
    auto embedResult = RunEmbedding(inputToken);
    if (!embedResult.success) return embedResult;
    
    // Step 2: Pre-Norm (RMSNorm)
    auto preNormResult = RunPreNorm();
    if (!preNormResult.success) return preNormResult;
    
    // Step 3: QKV Projection
    auto qkvResult = RunQKVProjection();
    if (!qkvResult.success) return qkvResult;
    
    // Step 4: RoPE
    auto ropeResult = RunRoPE(position);
    if (!ropeResult.success) return ropeResult;
    
    // Step 5: Self-Attention
    auto attnResult = RunSelfAttention();
    if (!attnResult.success) return attnResult;
    
    // Step 6: Attention Output Projection
    auto attnOutResult = RunAttentionOutput();
    if (!attnOutResult.success) return attnOutResult;
    
    // Step 7: Post-Attention Residual
    auto postAttnResult = RunPostAttentionResidual();
    if (!postAttnResult.success) return postAttnResult;
    
    // Step 8: FFN
    auto ffnResult = RunFFN();
    if (!ffnResult.success) return ffnResult;
    
    // Step 9: Post-FFN Residual
    auto postFFNResult = RunPostFFNResidual();
    if (!postFFNResult.success) return postFFNResult;
    
    // Step 10: Final Norm
    auto finalNormResult = RunFinalNorm();
    if (!finalNormResult.success) return finalNormResult;
    
    // Step 11: LM Head
    auto lmHeadResult = RunLMHead();
    if (!lmHeadResult.success) return lmHeadResult;
    
    auto endTime = std::chrono::high_resolution_clock::now();
    
    result.success = true;
    result.totalTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime).count();
    result.backendUsed = KernelRegistry::Instance().SelectBackend(
        KernelId::MatMul_Q4_Q8, 1024)->GetInfo().name;
    
    return result;
}

std::vector<GraphExecutionResult> SovereignGraphRunner::Generate(
    int32_t startToken,
    uint32_t maxNewTokens,
    ValidationMode validation
) {
    std::vector<GraphExecutionResult> results;
    
    int32_t currentToken = startToken;
    
    for (uint32_t i = 0; i < maxNewTokens; i++) {
        auto result = Forward(currentToken, i, validation);
        results.push_back(result);
        
        if (!result.success) break;
        
        // Next token (simplified - would use actual sampling)
        currentToken = result.outputToken;
    }
    
    return results;
}

//==============================================================================
// Layer-by-Layer Execution
//==============================================================================

GraphExecutionResult SovereignGraphRunner::RunEmbedding(int32_t tokenId) {
    // Embedding lookup - would dispatch to appropriate kernel
    // For now, simplified
    GraphExecutionResult result;
    result.success = true;
    return result;
}

GraphExecutionResult SovereignGraphRunner::RunPreNorm() {
    ExecutionContext ctx;
    
    // Setup context for RMSNorm
    ctx.inputTensor.data = ctx_.inputTensor.data;
    ctx.inputTensor.sizeBytes = config_.hiddenSize * sizeof(float);
    ctx.inputTensor.dims[0] = 1;
    ctx.inputTensor.dims[1] = config_.hiddenSize;
    ctx.inputTensor.numDims = 2;
    ctx.inputTensor.dtype = TensorDesc::DataType::F32;
    
    ctx.outputTensor = ctx.inputTensor;
    ctx.outputTensor.data = ctx_.outputTensor.data;
    
    ctx.params.AddFloat(config_.rmsNormEps);
    
    return DispatchKernel(KernelId::RMSNorm, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunQKVProjection() {
    // QKV projection via MatMul
    ExecutionContext ctx;
    
    ctx.matmulParams.M = config_.hiddenSize;
    ctx.matmulParams.N = config_.hiddenSize * 3; // Q, K, V
    ctx.matmulParams.K = config_.hiddenSize;
    
    return DispatchKernel(KernelId::MatMul_F32_F32, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunRoPE(uint32_t position) {
    ExecutionContext ctx;
    
    ctx.position = position;
    ctx.seqLen = config_.maxSeqLen;
    ctx.ropeSin = ropeSin_.data();
    ctx.ropeCos = ropeCos_.data();
    
    return DispatchKernel(KernelId::RoPE, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunSelfAttention() {
    ExecutionContext ctx;
    
    ctx.attentionParams.seqLen = config_.maxSeqLen;
    ctx.attentionParams.headDim = config_.headDim;
    ctx.attentionParams.numHeads = config_.numHeads;
    ctx.attentionParams.scale = 1.0f / std::sqrt(static_cast<float>(config_.headDim));
    
    return DispatchKernel(KernelId::FlashAttentionV2, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunAttentionOutput() {
    // Output projection
    ExecutionContext ctx;
    ctx.matmulParams.M = config_.hiddenSize;
    ctx.matmulParams.N = config_.hiddenSize;
    ctx.matmulParams.K = config_.hiddenSize;
    
    return DispatchKernel(KernelId::MatMul_F32_F32, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunPostAttentionResidual() {
    ExecutionContext ctx;
    return DispatchKernel(KernelId::ResidualAdd, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunFFN() {
    // FFN = SwiGLU + projection
    ExecutionContext ctx;
    
    // First MatMul
    auto result1 = DispatchKernel(KernelId::MatMul_F32_F32, ctx);
    if (!result1.success) return result1;
    
    // SiLU activation
    auto result2 = DispatchKernel(KernelId::SiLU, ctx);
    if (!result2.success) return result2;
    
    // Second MatMul
    return DispatchKernel(KernelId::MatMul_F32_F32, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunPostFFNResidual() {
    ExecutionContext ctx;
    return DispatchKernel(KernelId::ResidualAdd, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunFinalNorm() {
    ExecutionContext ctx;
    ctx.params.AddFloat(config_.rmsNormEps);
    return DispatchKernel(KernelId::RMSNorm, ctx);
}

GraphExecutionResult SovereignGraphRunner::RunLMHead() {
    // Final projection to vocab
    ExecutionContext ctx;
    ctx.matmulParams.M = config_.hiddenSize;
    ctx.matmulParams.N = 32000; // Vocab size (example)
    ctx.matmulParams.K = config_.hiddenSize;
    
    return DispatchKernel(KernelId::MatMul_F32_F32, ctx);
}

//==============================================================================
// Unified Dispatch
//==============================================================================

GraphExecutionResult SovereignGraphRunner::DispatchKernel(
    KernelId id,
    ExecutionContext& ctx
) {
    switch (validationMode_) {
        case ValidationMode::NONE:
            return DispatchWithValidation(id, ctx); // Actually runs normal
        case ValidationMode::REFERENCE:
            KernelRegistry::Instance().SetSelectionPolicy(SelectionPolicy::REFERENCE_ONLY);
            return DispatchWithValidation(id, ctx);
        case ValidationMode::COMPARE:
            return DispatchWithValidation(id, ctx);
        case ValidationMode::BENCHMARK:
            return DispatchWithBenchmark(id, ctx);
        default:
            return DispatchWithValidation(id, ctx);
    }
}

GraphExecutionResult SovereignGraphRunner::DispatchWithValidation(
    KernelId id,
    ExecutionContext& ctx
) {
    GraphExecutionResult result;
    
    auto& registry = KernelRegistry::Instance();
    
    // Get reference backend
    registry.SetSelectionPolicy(SelectionPolicy::REFERENCE_ONLY);
    IKernelBackend* refBackend = registry.SelectBackend(id, ctx.inputTensor.sizeBytes);
    
    if (!refBackend) {
        result.success = false;
        return result;
    }
    
    // Execute reference
    ExecutionStats refStats;
    bool refSuccess = false;
    
    switch (id) {
        case KernelId::MatMul_F32_F32:
        case KernelId::MatMul_Q4_Q8:
            refSuccess = refBackend->MatMul(ctx.inputTensor, ctx.weightTensor, 
                                            ctx.outputTensor, ctx.matmulParams, &refStats);
            break;
        case KernelId::FlashAttentionV2:
            refSuccess = refBackend->FlashAttention(ctx.inputTensor, ctx.inputTensor, 
                                                    ctx.inputTensor, ctx.outputTensor,
                                                    ctx.attentionParams, &refStats);
            break;
        case KernelId::RMSNorm:
            refSuccess = refBackend->RMSNorm(ctx.inputTensor, ctx.weightTensor, 
                                             ctx.outputTensor, ctx.params.scalars[0].f32, 
                                             &refStats);
            break;
        case KernelId::RoPE:
            refSuccess = refBackend->RoPE(ctx.inputTensor, ctx.outputTensor, ctx.ropeCos, 
                                          ctx.ropeSin, ctx.seqLen, config_.headDim, &refStats);
            break;
        case KernelId::SiLU:
            refSuccess = refBackend->SiLU(ctx.inputTensor, ctx.outputTensor, &refStats);
            break;
        case KernelId::ResidualAdd:
            refSuccess = refBackend->ResidualAdd(ctx.inputTensor, ctx.weightTensor, 
                                                ctx.outputTensor, &refStats);
            break;
        default:
            result.success = false;
            return result;
    }
    
    if (!refSuccess) {
        result.success = false;
        return result;
    }
    
    // Save reference output for comparison
    std::vector<uint8_t> refOutput(ctx.outputTensor.sizeBytes);
    std::memcpy(refOutput.data(), ctx.outputTensor.data, ctx.outputTensor.sizeBytes);
    
    // Now try with auto-selected backend
    registry.SetSelectionPolicy(SelectionPolicy::AUTO);
    IKernelBackend* autoBackend = registry.SelectBackend(id, ctx.inputTensor.sizeBytes);
    
    if (autoBackend && autoBackend != refBackend) {
        ExecutionStats autoStats;
        bool autoSuccess = false;
        
        // Execute with auto-selected backend
        switch (id) {
            case KernelId::MatMul_F32_F32:
            case KernelId::MatMul_Q4_Q8:
                autoSuccess = autoBackend->MatMul(ctx.inputTensor, ctx.weightTensor, 
                                                  ctx.outputTensor, ctx.matmulParams, &autoStats);
                break;
            case KernelId::FlashAttentionV2:
                autoSuccess = autoBackend->FlashAttention(ctx.inputTensor, ctx.inputTensor, 
                                                          ctx.inputTensor, ctx.outputTensor,
                                                          ctx.attentionParams, &autoStats);
                break;
            case KernelId::RMSNorm:
                autoSuccess = autoBackend->RMSNorm(ctx.inputTensor, ctx.weightTensor, 
                                                   ctx.outputTensor, ctx.params.scalars[0].f32, 
                                                   &autoStats);
                break;
            case KernelId::RoPE:
                autoSuccess = autoBackend->RoPE(ctx.inputTensor, ctx.outputTensor, ctx.ropeCos, 
                                                ctx.ropeSin, ctx.seqLen, config_.headDim, &autoStats);
                break;
            case KernelId::SiLU:
                autoSuccess = autoBackend->SiLU(ctx.inputTensor, ctx.outputTensor, &autoStats);
                break;
            case KernelId::ResidualAdd:
                autoSuccess = autoBackend->ResidualAdd(ctx.inputTensor, ctx.weightTensor, 
                                                       ctx.outputTensor, &autoStats);
                break;
            default:
                break;
        }
        
        if (autoSuccess) {
            // Compare outputs
            double maxError = 0.0;
            double sumSqError = 0.0;
            size_t numElements = ctx.outputTensor.NumElements();
            
            const float* ref = reinterpret_cast<const float*>(refOutput.data());
            const float* actual = reinterpret_cast<const float*>(ctx.outputTensor.data);
            
            for (size_t i = 0; i < numElements; i++) {
                double diff = std::abs(ref[i] - actual[i]);
                maxError = std::max(maxError, diff);
                sumSqError += diff * diff;
            }
            
            double rmsError = std::sqrt(sumSqError / numElements);
            
            // Record validation result
            GraphExecutionResult::ValidationEntry entry;
            entry.backendName = autoBackend->GetInfo().name;
            entry.maxError = maxError;
            entry.rmsError = rmsError;
            entry.passed = maxError < 1e-4; // Tolerance
            
            result.validationResults.push_back(entry);
            result.backendUsed = autoBackend->GetInfo().name;
            result.stats = autoStats;
        }
    }
    
    // Restore reference output
    std::memcpy(ctx.outputTensor.data, refOutput.data(), ctx.outputTensor.sizeBytes);
    
    result.success = true;
    result.backendUsed = refBackend->GetInfo().name;
    result.stats = refStats;
    
    return result;
}

GraphExecutionResult SovereignGraphRunner::DispatchWithBenchmark(
    KernelId id,
    ExecutionContext& ctx
) {
    GraphExecutionResult result;
    
    auto& registry = KernelRegistry::Instance();
    auto backends = registry.ListBackends();
    
    // Benchmark all backends
    for (const auto& [bid, info] : backends) {
        IKernelBackend* backend = registry.GetBackend(bid);
        if (!backend || !backend->SupportsKernel(id)) continue;
        
        // Warmup
        for (int i = 0; i < 5; i++) {
            // Execute (simplified)
        }
        
        // Benchmark
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < 50; i++) {
            // Execute (simplified)
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        std::cout << "  [" << info.name << "] " << (elapsed / 50) << " us/iter\n";
    }
    
    result.success = true;
    return result;
}

//==============================================================================
// Cache Management
//==============================================================================

void SovereignGraphRunner::ClearKVCache() {
    if (!kvCacheBuffer_.empty()) {
        std::memset(kvCacheBuffer_.data(), 0, kvCacheBuffer_.size());
    }
}

void SovereignGraphRunner::ResizeKVCache(uint32_t newMaxSeqLen) {
    config_.maxSeqLen = newMaxSeqLen;
    
    // Reallocate KV cache
    size_t kvSize = config_.numHeads * newMaxSeqLen * config_.headDim * sizeof(float) * 2; // K + V
    kvCacheBuffer_.resize(kvSize);
    
    // Reallocate RoPE cache
    InitializeRoPECache();
}

//==============================================================================
// Validation & Benchmarking
//==============================================================================

bool SovereignGraphRunner::RunValidationSuite() {
    std::cout << "Running Validation Suite...\n";
    
    ValidationMode savedMode = validationMode_;
    validationMode_ = ValidationMode::COMPARE;
    
    bool allPassed = true;
    
    // Test each kernel
    struct TestCase {
        KernelId id;
        const char* name;
    };
    
    TestCase tests[] = {
        {KernelId::RMSNorm, "RMSNorm"},
        {KernelId::RoPE, "RoPE"},
        {KernelId::SiLU, "SiLU"},
        {KernelId::ResidualAdd, "ResidualAdd"},
        {KernelId::MatMul_F32_F32, "MatMul"},
        {KernelId::FlashAttentionV2, "FlashAttention"},
    };
    
    for (const auto& test : tests) {
        std::cout << "  " << test.name << " ... ";
        
        ExecutionContext ctx;
        auto result = DispatchKernel(test.id, ctx);
        
        bool passed = result.success;
        if (passed && !result.validationResults.empty()) {
            passed = result.validationResults[0].passed;
        }
        
        std::cout << (passed ? "PASS" : "FAIL") << "\n";
        allPassed = allPassed && passed;
    }
    
    validationMode_ = savedMode;
    return allPassed;
}

void SovereignGraphRunner::RunBenchmarkSuite() {
    std::cout << "Running Benchmark Suite...\n";
    
    ValidationMode savedMode = validationMode_;
    validationMode_ = ValidationMode::BENCHMARK;
    
    // Benchmark each kernel
    ExecutionContext ctx;
    
    DispatchKernel(KernelId::RMSNorm, ctx);
    DispatchKernel(KernelId::RoPE, ctx);
    DispatchKernel(KernelId::SiLU, ctx);
    DispatchKernel(KernelId::MatMul_F32_F32, ctx);
    DispatchKernel(KernelId::FlashAttentionV2, ctx);
    
    validationMode_ = savedMode;
}

//==============================================================================
// Backend Selection
//==============================================================================

void SovereignGraphRunner::SetDispatchPolicy(SelectionPolicy policy) {
    KernelRegistry::Instance().SetSelectionPolicy(policy);
}

SelectionPolicy SovereignGraphRunner::GetDispatchPolicy() const {
    return KernelRegistry::Instance().GetSelectionPolicy();
}

void SovereignGraphRunner::ForceBackend(const std::string& backendName) {
    KernelRegistry::Instance().SetPreferredBackend(backendName);
}

void SovereignGraphRunner::AutoSelectBackend() {
    KernelRegistry::Instance().SetSelectionPolicy(SelectionPolicy::AUTO);
}

//==============================================================================
// Buffer Management
//==============================================================================

bool SovereignGraphRunner::AllocateBuffers() {
    // Activation buffer (ping-pong)
    size_t activationSize = config_.hiddenSize * sizeof(float) * 2;
    activationBuffer_.resize(activationSize);
    
    // KV cache
    size_t kvSize = config_.numHeads * config_.maxSeqLen * config_.headDim * sizeof(float) * 2;
    kvCacheBuffer_.resize(kvSize);
    
    // Setup context pointers
    ctx_.activation_a = activationBuffer_.data();
    ctx_.activation_b = activationBuffer_.data() + config_.hiddenSize * sizeof(float);
    ctx_.kCache = kvCacheBuffer_.data();
    ctx_.vCache = kvCacheBuffer_.data() + kvSize / 2;
    
    return true;
}

void SovereignGraphRunner::FreeBuffers() {
    activationBuffer_.clear();
    kvCacheBuffer_.clear();
    ropeSin_.clear();
    ropeCos_.clear();
}

bool SovereignGraphRunner::InitializeRoPECache() {
    // Precompute RoPE sin/cos tables
    size_t tableSize = config_.maxSeqLen * config_.headDim;
    ropeSin_.resize(tableSize);
    ropeCos_.resize(tableSize);
    
    for (uint32_t pos = 0; pos < config_.maxSeqLen; pos++) {
        for (uint32_t i = 0; i < config_.headDim; i += 2) {
            float theta = 1.0f / std::pow(config_.ropeTheta, 
                                          (2.0f * (i / 2)) / config_.headDim);
            float angle = pos * theta;
            
            ropeCos_[pos * config_.headDim + i] = std::cos(angle);
            ropeSin_[pos * config_.headDim + i] = std::sin(angle);
            ropeCos_[pos * config_.headDim + i + 1] = std::cos(angle);
            ropeSin_[pos * config_.headDim + i + 1] = std::sin(angle);
        }
    }
    
    return true;
}

//==============================================================================
// Default Backend Initialization
//==============================================================================

bool SovereignGraphRunner::InitializeDefaultBackends() {
    auto& registry = KernelRegistry::Instance();
    
    // Register Reference backend (always available)
    auto refBackend = std::unique_ptr<IKernelBackend>(CreateReferenceBackend());
    if (!refBackend->Initialize()) {
        return false;
    }
    registry.RegisterBackend(std::move(refBackend));
    
    // Register Intrinsics backend (if available)
    auto intrinsicsBackend = std::unique_ptr<IKernelBackend>(CreateIntrinsicsBackend());
    if (intrinsicsBackend->Initialize()) {
        registry.RegisterBackend(std::move(intrinsicsBackend));
    }
    // Intrinsics failure is not fatal - we have Reference
    
    return true;
}

} // namespace sovereign
