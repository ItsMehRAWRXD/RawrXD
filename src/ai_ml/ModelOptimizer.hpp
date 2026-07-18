/**
 * ModelOptimizer.hpp
 *
 * Phase L Batch 4/5: Model Optimization & Quantization
 *
 * Model optimization techniques including quantization, pruning,
 * knowledge distillation, and hardware-specific optimizations.
 */

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace AI_ML {

// ============================================================================
// Forward Declarations
// ============================================================================

class QuantizationConfig;
class PruningConfig;
class OptimizationEngine;
class ModelConverter;

// ============================================================================
// Quantization Types
// ============================================================================

enum class QuantizationType {
    INT8,           // 8-bit integer
    INT4,           // 4-bit integer
    FP16,           // 16-bit float
    BF16,           // BFloat16
    DYNAMIC,        // Dynamic quantization
    STATIC,         // Static quantization
    QAT,            // Quantization-aware training
    GPTQ,           // GPTQ quantization
    AWQ,            // Activation-aware weight quantization
    GGUF_Q4_0,      // GGUF Q4_0
    GGUF_Q4_1,      // GGUF Q4_1
    GGUF_Q5_0,      // GGUF Q5_0
    GGUF_Q5_1,      // GGUF Q5_1
    GGUF_Q8_0,      // GGUF Q8_0
    GGML_Q4_0,      // GGML Q4_0
    GGML_Q4_1,      // GGML Q4_1
    CUSTOM
};

std::string QuantizationTypeToString(QuantizationType type);
QuantizationType QuantizationTypeFromString(const std::string& str);

// ============================================================================
// Quantization Config
// ============================================================================

/**
 * Configuration for model quantization.
 */
struct QuantizationConfig {
    QuantizationType type;
    
    // Calibration
    size_t calibrationSamples;
    std::string calibrationDataset;
    std::vector<std::string> calibrationDataPaths;
    
    // Per-layer settings
    bool perChannel;
    bool perTensor;
    std::vector<std::string> layersToQuantize;
    std::vector<std::string> layersToSkip;
    
    // Advanced settings
    bool symmetric;
    bool reduceRange;
    std::optional<float> zeroPoint;
    std::optional<float> scale;
    
    // GPTQ specific
    int32_t groupSize;
    bool useCuda;
    bool useTriton;
    
    // AWQ specific
    float bits;
    float groupSizeAwq;
    std::string version;
    
    // GGUF/GGML specific
    bool leaveOutputTensorFp16;
    bool useQKVEmbedding;
    
    // Validation
    bool validateAccuracy;
    float maxAccuracyDrop;
    std::string validationDataset;
    
    // Export
    std::string outputFormat;
    std::string outputPath;
    
    static QuantizationConfig Int8Static();
    static QuantizationConfig Int8Dynamic();
    static QuantizationConfig Fp16();
    static QuantizationConfig Gptq(int32_t groupSize = 128);
    static QuantizationConfig Awq();
    static QuantizationConfig GgufQ4_0();
    static QuantizationConfig GgufQ8_0();
};

// ============================================================================
// Pruning Config
// ============================================================================

/**
 * Configuration for model pruning.
 */
struct PruningConfig {
    enum class PruningType {
        MAGNITUDE,      // Magnitude-based pruning
        STRUCTURED,     // Structured pruning
        UNSTRUCTURED,   // Unstructured pruning
        MOVEMENT,       // Movement pruning
        LOTTERY_TICKET, // Lottery ticket hypothesis
        GRADIENT        // Gradient-based pruning
    };
    
    PruningType type;
    float sparsityTarget;
    float initialSparsity;
    uint32_t pruningSteps;
    
    // Magnitude pruning
    float threshold;
    bool pruneByPercentage;
    
    // Structured pruning
    std::vector<int32_t> filterGroups;
    bool pruneChannels;
    bool pruneFilters;
    
    // Lottery ticket
    uint32_t retrainEpochs;
    float retrainLearningRate;
    
    // Schedule
    enum class Schedule {
        LINEAR,
        EXPONENTIAL,
        COSINE
    };
    Schedule schedule;
    
    // Validation
    bool validateAccuracy;
    float maxAccuracyDrop;
    
    static PruningConfig Magnitude(float sparsity);
    static PruningConfig Structured(float sparsity);
    static PruningConfig LotteryTicket(float sparsity);
};

// ============================================================================
// Optimization Target
// ============================================================================

enum class OptimizationTarget {
    LATENCY,        // Minimize inference latency
    THROUGHPUT,     // Maximize throughput
    MEMORY,         // Minimize memory usage
    POWER,          // Minimize power consumption
    ACCURACY,       // Maximize accuracy
    BALANCED        // Balanced optimization
};

// ============================================================================
// Hardware Target
// ============================================================================

enum class HardwareTarget {
    CPU_GENERIC,
    CPU_AVX2,
    CPU_AVX512,
    GPU_CUDA,
    GPU_ROCM,
    GPU_METAL,
    GPU_VULKAN,
    NPU,
    TPU,
    FPGA,
    WEBGPU,
    WEBASSEMBLY
};

// ============================================================================
// Optimization Result
// ============================================================================

/**
 * Result of model optimization.
 */
struct OptimizationResult {
    bool success;
    std::string errorMessage;
    
    // Model info
    std::string originalModelPath;
    std::string optimizedModelPath;
    
    // Size metrics
    uint64_t originalSizeBytes;
    uint64_t optimizedSizeBytes;
    double compressionRatio;
    
    // Performance metrics
    double originalLatencyMs;
    double optimizedLatencyMs;
    double speedup;
    
    double originalThroughput;
    double optimizedThroughput;
    double throughputImprovement;
    
    // Memory metrics
    double originalMemoryMb;
    double optimizedMemoryMb;
    double memoryReduction;
    
    // Accuracy metrics
    double originalAccuracy;
    double optimizedAccuracy;
    double accuracyDrop;
    
    // Optimization details
    std::map<std::string, std::string> appliedOptimizations;
    std::chrono::seconds optimizationTime;
    
    std::string ToJson() const;
    std::string ToReport() const;
};

// ============================================================================
// Quantization Engine
// ============================================================================

/**
 * Model quantization engine.
 */
class QuantizationEngine {
public:
    explicit QuantizationEngine(const QuantizationConfig& config);
    
    // Quantization
    OptimizationResult Quantize(const std::string& inputPath,
                                 const std::string& outputPath);
    
    // Calibration
    void Calibrate(const std::string& calibrationDataPath);
    void CalibrateWithSamples(const std::vector<std::vector<float>>& samples);
    
    // Layer-wise quantization
    OptimizationResult QuantizeLayer(const std::string& layerName,
                                       const std::string& inputPath,
                                       const std::string& outputPath);
    
    // Validation
    bool ValidateAccuracy(const std::string& modelPath,
                          const std::string& validationDataset);
    
    // Analysis
    struct QuantizationAnalysis {
        std::map<std::string, float> layerSensitivity;
        std::map<std::string, float> expectedAccuracyDrop;
        std::vector<std::string> recommendedLayersToSkip;
        float estimatedCompressionRatio;
    };
    QuantizationAnalysis Analyze(const std::string& modelPath);
    
private:
    QuantizationConfig config_;
    std::vector<std::vector<float>> calibrationData_;
    
    OptimizationResult QuantizePytorch(const std::string& inputPath,
                                        const std::string& outputPath);
    OptimizationResult QuantizeOnnx(const std::string& inputPath,
                                       const std::string& outputPath);
    OptimizationResult QuantizeTensorRT(const std::string& inputPath,
                                          const std::string& outputPath);
    OptimizationResult QuantizeGGML(const std::string& inputPath,
                                     const std::string& outputPath);
    OptimizationResult QuantizeGGUF(const std::string& inputPath,
                                     const std::string& outputPath);
    OptimizationResult QuantizeGptq(const std::string& inputPath,
                                     const std::string& outputPath);
    OptimizationResult QuantizeAwq(const std::string& inputPath,
                                    const std::string& outputPath);
};

// ============================================================================
// Pruning Engine
// ============================================================================

/**
 * Model pruning engine.
 */
class PruningEngine {
public:
    explicit PruningEngine(const PruningConfig& config);
    
    // Pruning
    OptimizationResult Prune(const std::string& inputPath,
                              const std::string& outputPath);
    
    // Iterative pruning
    OptimizationResult PruneIteratively(const std::string& inputPath,
                                         const std::string& outputPath,
                                         uint32_t iterations);
    
    // Fine-tuning after pruning
    bool FineTune(const std::string& modelPath,
                  const std::string& trainingDataPath,
                  uint32_t epochs);
    
    // Lottery ticket
    OptimizationResult FindWinningTicket(const std::string& inputPath,
                                          const std::string& outputPath);
    
    // Analysis
    struct PruningAnalysis {
        std::map<std::string, float> layerImportance;
        std::map<std::string, float> sensitivityToPruning;
        float recommendedSparsity;
        std::vector<std::string> layersToPrune;
    };
    PruningAnalysis Analyze(const std::string& modelPath);
    
private:
    PruningConfig config_;
    
    void ApplyMagnitudePruning(void* model, float sparsity);
    void ApplyStructuredPruning(void* model, const std::vector<int32_t>& groups);
    void ApplyMovementPruning(void* model, uint32_t steps);
};

// ============================================================================
// Knowledge Distillation
// ============================================================================

/**
 * Knowledge distillation for model compression.
 */
class KnowledgeDistillation {
public:
    struct Config {
        std::string teacherModelPath;
        std::string studentArchitecture;
        float temperature;
        float alpha;  // Weight for soft targets
        float beta;   // Weight for hard targets
        uint32_t epochs;
        float learningRate;
        std::string trainingDataPath;
        std::string validationDataPath;
    };
    
    explicit KnowledgeDistillation(const Config& config);
    
    // Distillation
    OptimizationResult Distill(const std::string& outputPath);
    
    // Progressive distillation
    OptimizationResult DistillProgressive(const std::string& outputPath,
                                            uint32_t stages);
    
    // Analysis
    struct DistillationAnalysis {
        float teacherAccuracy;
        float studentCapacityRatio;
        float expectedAccuracy;
        std::string recommendedStudentArchitecture;
    };
    DistillationAnalysis Analyze();
    
private:
    Config config_;
    
    float ComputeDistillationLoss(const void* teacherOutputs,
                                   const void* studentOutputs,
                                   const void* targets);
};

// ============================================================================
// Optimization Engine
// ============================================================================

/**
 * Comprehensive model optimization engine.
 */
class OptimizationEngine {
public:
    struct Config {
        OptimizationTarget target;
        HardwareTarget hardware;
        std::vector<std::string> enabledOptimizations;
        float maxAccuracyDrop;
        std::chrono::seconds timeout;
        uint32_t maxIterations;
        bool enableAutoTuning;
    };
    
    explicit OptimizationEngine(const Config& config);
    
    // Optimization pipeline
    OptimizationResult Optimize(const std::string& inputPath,
                                 const std::string& outputPath);
    
    // Individual optimizations
    OptimizationResult Quantize(const std::string& inputPath,
                                 const std::string& outputPath,
                                 const QuantizationConfig& config);
    OptimizationResult Prune(const std::string& inputPath,
                                const std::string& outputPath,
                                const PruningConfig& config);
    OptimizationResult Distill(const std::string& inputPath,
                                const std::string& outputPath,
                                const KnowledgeDistillation::Config& config);
    
    // Fusion optimizations
    OptimizationResult FuseOperations(const std::string& inputPath,
                                       const std::string& outputPath);
    OptimizationResult OptimizeMemoryLayout(const std::string& inputPath,
                                             const std::string& outputPath);
    OptimizationResult OptimizeGraph(const std::string& inputPath,
                                      const std::string& outputPath);
    
    // Hardware-specific optimizations
    OptimizationResult OptimizeForCuda(const std::string& inputPath,
                                        const std::string& outputPath);
    OptimizationResult OptimizeForTensorRT(const std::string& inputPath,
                                              const std::string& outputPath);
    OptimizationResult OptimizeForOpenVINO(const std::string& inputPath,
                                              const std::string& outputPath);
    OptimizationResult OptimizeForONNXRuntime(const std::string& inputPath,
                                               const std::string& outputPath);
    OptimizationResult OptimizeForGGML(const std::string& inputPath,
                                          const std::string& outputPath);
    
    // Auto-tuning
    OptimizationResult AutoTune(const std::string& inputPath,
                                 const std::string& outputPath);
    
    // Benchmarking
    struct BenchmarkResult {
        double latencyMs;
        double throughput;
        double memoryMb;
        double accuracy;
        double powerWatts;
    };
    BenchmarkResult Benchmark(const std::string& modelPath);
    
    // Comparison
    struct ModelComparison {
        std::string baselinePath;
        std::string optimizedPath;
        std::vector<std::pair<std::string, double>> metricDifferences;
        bool isBetter;
        std::string recommendation;
    };
    ModelComparison Compare(const std::string& baselinePath,
                            const std::string& optimizedPath);
    
    // Analysis
    struct OptimizationAnalysis {
        std::map<std::string, float> optimizationPotential;
        std::vector<std::string> recommendedOptimizations;
        float estimatedMaxCompression;
        float estimatedMaxSpeedup;
    };
    OptimizationAnalysis Analyze(const std::string& modelPath);
    
private:
    Config config_;
    
    std::vector<std::function<OptimizationResult(const std::string&, const std::string&)>>
        optimizationPipeline_;
    
    void BuildOptimizationPipeline();
    bool ShouldApplyOptimization(const std::string& name);
};

// ============================================================================
// Model Converter
// ============================================================================

/**
 * Convert models between formats.
 */
class ModelConverter {
public:
    enum class SourceFormat {
        PYTORCH,
        TENSORFLOW,
        ONNX,
        TENSORRT,
        OPENVINO,
        GGML,
        GGUF,
        SAFETENSORS
    };
    
    enum class TargetFormat {
        ONNX,
        TENSORRT,
        OPENVINO,
        GGML,
        GGUF,
        TENSORFLOW_SAVEDMODEL,
        TORCHSCRIPT,
        SAFETENSORS
    };
    
    struct ConversionConfig {
        SourceFormat source;
        TargetFormat target;
        std::map<std::string, std::string> options;
        bool optimizeDuringConversion;
        bool validateAfterConversion;
    };
    
    explicit ModelConverter(const ConversionConfig& config);
    
    // Conversion
    bool Convert(const std::string& inputPath, const std::string& outputPath);
    
    // Batch conversion
    std::vector<std::pair<std::string, bool>> ConvertBatch(
        const std::vector<std::pair<std::string, std::string>>& conversions);
    
    // Validation
    bool ValidateConversion(const std::string& originalPath,
                            const std::string& convertedPath);
    
    // Analysis
    struct ConversionAnalysis {
        bool isSupported;
        std::vector<std::string> unsupportedOps;
        std::map<std::string, std::string> conversionNotes;
        float estimatedAccuracyDrop;
    };
    ConversionAnalysis Analyze(const std::string& modelPath);
    
private:
    ConversionConfig config_;
    
    bool ConvertPytorchToOnnx(const std::string& input, const std::string& output);
    bool ConvertOnnxToTensorRT(const std::string& input, const std::string& output);
    bool ConvertOnnxToOpenVINO(const std::string& input, const std::string& output);
    bool ConvertPytorchToGGML(const std::string& input, const std::string& output);
    bool ConvertSafetensorsToGGUF(const std::string& input, const std::string& output);
};

// ============================================================================
// Runtime Optimization
// ============================================================================

/**
 * Runtime optimization for inference.
 */
class RuntimeOptimizer {
public:
    struct Config {
        bool enableKernelFusion;
        bool enableMemoryPooling;
        bool enableAsyncExecution;
        bool enableGraphOptimization;
        uint32_t numThreads;
        std::string memoryLayout;
    };
    
    explicit RuntimeOptimizer(const Config& config);
    
    // Optimization
    void* OptimizeModel(void* model);
    
    // Memory management
    void* AllocateTensor(size_t size);
    void FreeTensor(void* tensor);
    void PreallocateMemory(size_t size);
    
    // Execution
    void ExecuteAsync(void* model, void* inputs, void* outputs);
    void Synchronize();
    
    // Profiling
    struct ProfileData {
        std::map<std::string, double> opLatencies;
        std::map<std::string, size_t> memoryUsage;
        std::vector<std::string> bottlenecks;
    };
    ProfileData Profile(void* model);
    
    // Tuning
    void AutoTune(void* model);
    
private:
    Config config_;
    std::map<void*, size_t> memoryPool_;
    mutable std::mutex mutex_;
};

} // namespace AI_ML
