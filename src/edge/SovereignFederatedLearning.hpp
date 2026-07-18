// Phase D.14 Batch 2/5: Federated Learning
// Distributed model training across edge devices
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
namespace Edge {

// Forward declarations
struct FederatedRound;
struct ClientUpdate;

// ============================================================================
// Federated Learning Types
// ============================================================================

enum class FLStrategy {
    FEDAVG = 0,           // Standard Federated Averaging
    FEDPROX = 1,          // Federated Proximal
    FEDOPT = 2,           // Federated Optimization
    SCAFFOLD = 3,         // Stochastic Controlled Averaging
    FEDNOVA = 4,          // Federated Normalized Averaging
    FEDYOGI = 5,          // Federated Yogi Optimizer
    FEDADAM = 6           // Federated Adam
};

enum class AggregationStatus {
    WAITING = 0,
    AGGREGATING = 1,
    COMPLETED = 2,
    FAILED = 3
};

enum class ClientStatus {
    IDLE = 0,
    TRAINING = 1,
    UPLOADING = 2,
    COMPLETED = 3,
    FAILED = 4,
    DROPPED = 5
};

struct FederatedConfig {
    FLStrategy strategy = FLStrategy::FEDAVG;
    int min_clients = 3;
    int max_clients = 100;
    int rounds = 10;
    int local_epochs = 5;
    float client_fraction = 0.1f;  // C in FedAvg
    float learning_rate = 0.01f;
    float proximal_mu = 0.01f;     // For FedProx
    float gradient_clip = 1.0f;
    bool differential_privacy = false;
    float dp_epsilon = 1.0f;
    float dp_delta = 1e-5f;
    bool secure_aggregation = true;
};

struct ClientInfo {
    std::string client_id;
    std::string device_id;
    ClientStatus status;
    int dataset_size = 0;
    float data_quality_score = 1.0f;
    std::chrono::steady_clock::time_point last_update;
    std::map<std::string, double> metrics;
    std::vector<float> current_weights;
    std::vector<float> control_variate;  // For SCAFFOLD
};

struct FederatedRound {
    int round_number;
    AggregationStatus status;
    std::vector<std::string> selected_clients;
    std::map<std::string, ClientUpdate> updates;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;
    float aggregated_loss = 0.0f;
    float aggregated_accuracy = 0.0f;
    std::vector<float> global_weights;
};

struct ClientUpdate {
    std::string client_id;
    int round_number;
    std::vector<float> weights_delta;
    int samples_count;
    float local_loss;
    float local_accuracy;
    std::chrono::steady_clock::time_point timestamp;
    std::vector<float> control_delta;  // For SCAFFOLD
};

struct TrainingResult {
    std::string training_id;
    int completed_rounds;
    float final_accuracy;
    float final_loss;
    std::map<std::string, std::vector<float>> metrics_history;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;
    std::vector<std::string> participating_clients;
};

// ============================================================================
// Federated Coordinator
// ============================================================================

class FederatedCoordinator {
public:
    struct Config {
        FederatedConfig fl_config;
        std::string model_name;
        std::string initial_model_path;
        std::string checkpoint_dir;
        std::chrono::seconds round_timeout{300};
        std::chrono::seconds client_selection_timeout{60};
    };
    
    explicit FederatedCoordinator(const Config& config);
    ~FederatedCoordinator();
    
    bool Initialize();
    void Shutdown();
    
    // Training lifecycle
    std::string StartTraining();
    bool PauseTraining(const std::string& training_id);
    bool ResumeTraining(const std::string& training_id);
    bool StopTraining(const std::string& training_id);
    
    // Round management
    bool StartRound(int round_number);
    bool CompleteRound(int round_number);
    bool FailRound(int round_number, const std::string& reason);
    
    // Client management
    bool RegisterClient(const std::string& client_id, 
                        const std::string& device_id,
                        int dataset_size);
    bool UnregisterClient(const std::string& client_id);
    std::vector<std::string> SelectClients(int round_number);
    bool UpdateClientStatus(const std::string& client_id, 
                            ClientStatus status);
    
    // Aggregation
    bool ReceiveClientUpdate(const ClientUpdate& update);
    bool AggregateUpdates(int round_number);
    std::vector<float> GetGlobalModel() const;
    
    // Results
    TrainingResult GetTrainingResult(const std::string& training_id) const;
    FederatedRound GetRoundStatus(int round_number) const;
    std::vector<ClientInfo> GetConnectedClients() const;
    
private:
    Config config_;
    std::string training_id_;
    std::map<int, FederatedRound> rounds_;
    std::map<std::string, ClientInfo> clients_;
    std::vector<float> global_weights_;
    std::vector<float> global_control_;  // For SCAFFOLD
    mutable std::mutex coordinator_mutex_;
    std::thread aggregation_thread_;
    std::atomic<bool> running_{false};
    
    void AggregationLoop();
    std::vector<float> AggregateFedAvg(const std::vector<ClientUpdate>& updates);
    std::vector<float> AggregateFedProx(const std::vector<ClientUpdate>& updates);
    std::vector<float> AggregateScaffold(const std::vector<ClientUpdate>& updates);
    std::vector<float> AggregateFedOpt(const std::vector<ClientUpdate>& updates);
};

// ============================================================================
// Federated Client
// ============================================================================

class FederatedClient {
public:
    struct Config {
        std::string client_id;
        std::string coordinator_url;
        std::string local_dataset_path;
        int local_epochs = 5;
        int batch_size = 32;
        float learning_rate = 0.01f;
        std::string device_type = "cpu";  // cpu, gpu, tpu
    };
    
    explicit FederatedClient(const Config& config);
    ~FederatedClient();
    
    bool Initialize();
    void Shutdown();
    
    // Connection
    bool ConnectToCoordinator();
    bool Disconnect();
    bool IsConnected() const;
    
    // Training
    bool JoinTraining(const std::string& training_id);
    bool LeaveTraining();
    ClientUpdate TrainLocal(const std::vector<float>& global_weights,
                            int round_number);
    
    // Local training
    bool LoadLocalDataset();
    float TrainEpoch(const std::vector<float>& weights);
    std::vector<float> ComputeWeightDelta(const std::vector<float>& global_weights);
    
    // Upload
    bool UploadUpdate(const ClientUpdate& update);
    
    // Status
    ClientStatus GetStatus() const;
    int GetDatasetSize() const;
    std::map<std::string, double> GetLocalMetrics() const;
    
private:
    Config config_;
    std::string current_training_id_;
    ClientStatus status_ = ClientStatus::IDLE;
    std::vector<float> current_weights_;
    std::vector<float> control_variate_;  // For SCAFFOLD
    int dataset_size_ = 0;
    std::map<std::string, double> local_metrics_;
    mutable std::mutex client_mutex_;
};

// ============================================================================
// Secure Aggregation
// ============================================================================

class SecureAggregation {
public:
    struct Config {
        int num_clients;
        int threshold;  // Minimum clients for reconstruction
        std::string encryption_scheme = "paillier";  // paillier, ckks, bfv
        int key_size = 2048;
    };
    
    explicit SecureAggregation(const Config& config);
    
    // Key generation
    struct KeyPair {
        std::string public_key;
        std::string private_key;
    };
    KeyPair GenerateKeyPair();
    
    // Masking
    std::vector<float> GenerateMask(int seed, size_t size);
    std::vector<float> ApplyMask(const std::vector<float>& weights,
                                  const std::vector<float>& mask);
    std::vector<float> RemoveMask(const std::vector<float>& masked_weights,
                                     const std::vector<float>& mask);
    
    // Secure aggregation protocol
    bool SetupSecureChannel(const std::string& client_id);
    std::vector<float> EncryptUpdate(const std::vector<float>& update,
                                      const std::string& public_key);
    std::vector<float> AggregateEncrypted(
        const std::vector<std::vector<float>>& encrypted_updates);
    std::vector<float> DecryptAggregate(const std::vector<float>& encrypted_aggregate,
                                         const std::string& private_key);
    
    // Differential privacy
    std::vector<float> AddNoise(const std::vector<float>& weights,
                                 float epsilon,
                                 float delta,
                                 int sensitivity);
    
private:
    Config config_;
    std::map<std::string, KeyPair> client_keys_;
};

// ============================================================================
// Federated Evaluation
// ============================================================================

class FederatedEvaluation {
public:
    struct EvaluationConfig {
        std::string test_dataset_path;
        std::vector<std::string> metrics = {"accuracy", "precision", "recall", "f1"};
        bool evaluate_on_clients = true;
        bool evaluate_on_server = true;
    };
    
    struct EvaluationResult {
        std::string client_id;
        std::map<std::string, float> metrics;
        std::chrono::steady_clock::time_point evaluated_at;
        int test_samples = 0;
    };
    
    explicit FederatedEvaluation(const EvaluationConfig& config);
    
    // Evaluation
    EvaluationResult EvaluateLocal(const std::string& client_id,
                                    const std::vector<float>& model_weights);
    std::vector<EvaluationResult> EvaluateAllClients(
        const std::vector<std::string>& client_ids,
        const std::vector<float>& model_weights);
    
    // Aggregation
    std::map<std::string, float> AggregateEvaluations(
        const std::vector<EvaluationResult>& results);
    
    // Comparison
    std::map<std::string, float> CompareRounds(int round1, int round2);
    bool DetectDrift(const std::vector<EvaluationResult>& history);
    
private:
    EvaluationConfig config_;
};

// ============================================================================
// Federated Learning Runtime
// ============================================================================

class FederatedLearningRuntime {
public:
    struct Config {
        FederatedCoordinator::Config coordinator;
        FederatedClient::Config client;
        SecureAggregation::Config security;
        bool is_coordinator = false;
    };
    
    explicit FederatedLearningRuntime(const Config& config);
    ~FederatedLearningRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Mode-dependent access
    FederatedCoordinator* GetCoordinator();
    FederatedClient* GetClient();
    SecureAggregation* GetSecureAggregation();
    FederatedEvaluation* GetEvaluation();
    
    // High-level API
    std::string StartFederatedTraining(const FederatedConfig& fl_config,
                                        const std::string& model_name);
    bool JoinFederatedTraining(const std::string& training_id,
                                const std::string& coordinator_url);
    TrainingResult GetTrainingResults(const std::string& training_id) const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<FederatedCoordinator> coordinator_;
    std::unique_ptr<FederatedClient> client_;
    std::unique_ptr<SecureAggregation> secure_agg_;
    std::unique_ptr<FederatedEvaluation> evaluation_;
};

} // namespace Edge
} // namespace Sovereign
