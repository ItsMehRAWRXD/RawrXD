// Phase D.18 Batch 2/5: ML-Based Insights
// Machine learning for analytics and insights
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Analytics {

// Forward declarations
struct MLModel;
struct FeatureVector;
struct PredictionResult;

// ============================================================================
// ML Insights Types
// ============================================================================

enum class ModelType {
    CLASSIFICATION = 0,
    REGRESSION = 1,
    CLUSTERING = 2,
    ANOMALY_DETECTION = 3,
    FORECASTING = 4,
    RECOMMENDATION = 5,
    NLP = 6
};

enum class ModelFramework {
    ONNX = 0,
    TENSORFLOW = 1,
    PYTORCH = 2,
    SKLEARN = 3,
    XGBOOST = 4,
    CUSTOM = 5
};

enum class TrainingStatus {
    PENDING = 0,
    TRAINING = 1,
    COMPLETED = 2,
    FAILED = 3,
    CANCELLED = 4
};

struct MLModel {
    std::string model_id;
    std::string name;
    ModelType type;
    ModelFramework framework;
    std::vector<uint8_t> serialized_model;
    std::map<std::string, std::any> hyperparameters;
    std::map<std::string, double> metrics;
    TrainingStatus status;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point trained_at;
    std::string version;
};

struct FeatureVector {
    std::string feature_id;
    std::vector<double> values;
    std::map<std::string, std::any> metadata;
    std::chrono::steady_clock::time_point timestamp;
};

struct PredictionResult {
    std::string prediction_id;
    std::string model_id;
    std::vector<double> predictions;
    std::vector<double> probabilities;
    double confidence;
    std::chrono::steady_clock::time_point predicted_at;
    std::map<std::string, std::any> explanations;
};

// ============================================================================
// Model Registry
// ============================================================================

class ModelRegistry {
public:
    struct Config {
        std::string storage_path;
        bool version_models = true;
        int max_versions = 5;
    };
    
    explicit ModelRegistry(const Config& config);
    ~ModelRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Model registration
    std::string RegisterModel(const MLModel& model);
    bool UnregisterModel(const std::string& model_id);
    bool UpdateModel(const std::string& model_id, const MLModel& model);
    
    // Model queries
    MLModel GetModel(const std::string& model_id) const;
    std::vector<MLModel> GetModelsByType(ModelType type) const;
    std::vector<MLModel> GetModelsByFramework(ModelFramework framework) const;
    MLModel GetLatestModel(const std::string& name) const;
    
    // Versioning
    std::vector<MLModel> GetModelVersions(const std::string& name) const;
    bool SetActiveVersion(const std::string& name, const std::string& version);
    
private:
    Config config_;
    std::map<std::string, MLModel> models_;
    mutable std::mutex models_mutex_;
};

// ============================================================================
// Feature Engineering
// ============================================================================

class FeatureEngineering {
public:
    struct Config {
        bool auto_scale = true;
        bool handle_missing = true;
        bool encode_categorical = true;
        int max_features = 1000;
    };
    
    struct FeatureSet {
        std::string set_id;
        std::vector<std::string> feature_names;
        std::vector<FeatureVector> vectors;
        std::map<std::string, std::any> statistics;
    };
    
    explicit FeatureEngineering(const Config& config);
    ~FeatureEngineering();
    
    bool Initialize();
    void Shutdown();
    
    // Feature extraction
    FeatureVector ExtractFeatures(const std::map<std::string, std::any>& raw_data);
    FeatureSet ExtractFeatureSet(const std::vector<std::map<std::string, std::any>>& raw_data);
    
    // Transformations
    FeatureVector Normalize(const FeatureVector& features);
    FeatureVector Standardize(const FeatureVector& features);
    FeatureVector EncodeCategorical(const FeatureVector& features);
    
    // Feature selection
    std::vector<std::string> SelectFeatures(const FeatureSet& feature_set, int top_k);
    std::map<std::string, double> CalculateFeatureImportance(const FeatureSet& feature_set);
    
private:
    Config config_;
    std::map<std::string, double> feature_stats_;
    mutable std::mutex features_mutex_;
};

// ============================================================================
// Inference Engine
// ============================================================================

class InferenceEngine {
public:
    struct Config {
        int max_batch_size = 32;
        std::chrono::milliseconds timeout{100};
        bool enable_gpu = false;
        int num_threads = 4;
    };
    
    struct BatchResult {
        std::vector<PredictionResult> predictions;
        std::chrono::milliseconds latency;
        int batch_size;
    };
    
    explicit InferenceEngine(const Config& config);
    ~InferenceEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Model loading
    bool LoadModel(const std::string& model_id);
    bool UnloadModel(const std::string& model_id);
    bool IsModelLoaded(const std::string& model_id) const;
    
    // Inference
    PredictionResult Predict(const std::string& model_id, const FeatureVector& features);
    BatchResult PredictBatch(const std::string& model_id, const std::vector<FeatureVector>& features);
    
    // Explanations
    std::map<std::string, double> ExplainPrediction(const std::string& model_id, 
                                                      const FeatureVector& features);
    
private:
    Config config_;
    std::map<std::string, std::unique_ptr<void, std::function<void(void*)>>> loaded_models_;
    mutable std::mutex inference_mutex_;
    
    void* LoadONNXModel(const std::vector<uint8_t>& data);
    void* LoadTensorFlowModel(const std::vector<uint8_t>& data);
    void* LoadPyTorchModel(const std::vector<uint8_t>& data);
};

// ============================================================================
// Model Trainer
// ============================================================================

class ModelTrainer {
public:
    struct Config {
        int max_epochs = 100;
        double validation_split = 0.2;
        bool early_stopping = true;
        int patience = 10;
    };
    
    struct TrainingJob {
        std::string job_id;
        std::string model_id;
        std::string dataset_id;
        TrainingStatus status;
        int current_epoch;
        int total_epochs;
        double current_loss;
        double validation_loss;
        std::map<std::string, double> metrics;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
    };
    
    struct TrainingResult {
        bool success;
        MLModel trained_model;
        std::map<std::string, double> final_metrics;
        std::string error_message;
    };
    
    explicit ModelTrainer(const Config& config);
    ~ModelTrainer();
    
    bool Initialize();
    void Shutdown();
    
    // Training
    std::string StartTraining(const std::string& model_id, const std::string& dataset_id);
    bool CancelTraining(const std::string& job_id);
    TrainingJob GetTrainingStatus(const std::string& job_id) const;
    TrainingResult GetTrainingResult(const std::string& job_id) const;
    
    // Hyperparameter tuning
    std::string StartHyperparameterSearch(const std::string& model_id, 
                                           const std::string& dataset_id,
                                           const std::map<std::string, std::any>& search_space);
    
private:
    Config config_;
    std::map<std::string, TrainingJob> jobs_;
    mutable std::mutex jobs_mutex_;
    std::thread training_thread_;
    std::atomic<bool> running_{false};
    
    void TrainingLoop();
    TrainingResult ExecuteTraining(const TrainingJob& job);
};

// ============================================================================
// ML Insights Runtime
// ============================================================================

class MLInsightsRuntime {
public:
    struct Config {
        ModelRegistry::Config registry;
        FeatureEngineering::Config features;
        InferenceEngine::Config inference;
        ModelTrainer::Config training;
    };
    
    explicit MLInsightsRuntime(const Config& config);
    ~MLInsightsRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ModelRegistry* GetRegistry();
    FeatureEngineering* GetFeatureEngineering();
    InferenceEngine* GetInferenceEngine();
    ModelTrainer* GetTrainer();
    
    // High-level API
    PredictionResult Predict(const std::string& model_name, const std::map<std::string, std::any>& data);
    std::string TrainModel(const std::string& model_name, ModelType type, const std::string& dataset_id);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ModelRegistry> registry_;
    std::unique_ptr<FeatureEngineering> feature_engineering_;
    std::unique_ptr<InferenceEngine> inference_engine_;
    std::unique_ptr<ModelTrainer> trainer_;
};

} // namespace Analytics
} // namespace Sovereign
