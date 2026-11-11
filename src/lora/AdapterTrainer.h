#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <chrono>
#include <memory>
#include <filesystem>

// Forward declarations for LoRAContext beacon
namespace RawrXD::MASM {
    struct LoRAContext;
}

namespace RawrXD {

// Forward declarations
struct AdapterWeights;
class AdapterRegistry;
struct AdapterState;

// Training sample from WAL (Write-Ahead Log) of user interactions
struct TrainingSample {
    std::vector<float> input_embedding;   // Token embedding before LoRA
    std::vector<float> target_embedding;  // Desired output (from accepted completion)
    float weight = 1.0f;                  // Importance weight
    std::chrono::system_clock::time_point timestamp;
    std::string context_hash;             // Hash of surrounding code context
};

// Configuration for adapter training
struct AdapterTrainerConfig {
    uint32_t rank = 8;                    // LoRA rank
    float learning_rate = 1e-4f;          // SGD learning rate
    uint32_t batch_size = 32;             // Samples per gradient update
    uint32_t max_epochs = 100;          // Training epochs
    float l2_regularization = 0.01f;      // Weight decay
    float convergence_threshold = 1e-5f;  // Stop when loss change < threshold
    uint32_t checkpoint_interval = 10;    // Save every N epochs
    uint32_t hidden_dim = 768;            // Base model hidden dimension
    
    // Adaptive learning rate
    bool use_lr_decay = true;
    float lr_decay_rate = 0.95f;
    uint32_t lr_decay_steps = 10;
    
    // Phase 18C.3: Shadow buffer config
    uint32_t beacon_swap_interval = 50;   // Steps between beacon swaps
    bool use_shadow_buffer = true;          // Enable atomic swap pattern
};

// Training progress callback
using TrainingCallback = std::function<void(
    uint32_t epoch,
    float loss,
    float learning_rate,
    bool is_complete
)>;

// Phase 18C.3: Shadow buffer for thread-safe updates
struct ShadowBuffer {
    std::vector<float> matrix_A;           // Shadow A matrix
    std::vector<float> matrix_B;           // Shadow B matrix
    std::atomic<bool> ready{false};        // Ready for beacon swap
    uint32_t version = 0;                   // Version counter
    
    void allocate(uint32_t rank, uint32_t hidden_dim);
    void copy_from(const std::vector<float>& A, const std::vector<float>& B);
    void swap_to_loRAContext(MASM::LoRAContext* context, float alpha);
};

// Background trainer for LoRA adapters
// Implements SGD with momentum for updating A and B matrices
// Phase 18C.3: Shadow-buffer pattern for MASM beacon integration
class AdapterTrainer {
public:
    AdapterTrainer();
    ~AdapterTrainer();
    
    // Initialize trainer with config
    void initialize(const AdapterTrainerConfig& config);
    
    // Add training sample to queue
    void enqueue_sample(const TrainingSample& sample);
    
    // Start training loop in background thread
    // target_name: Name for the output adapter (e.g., "python-data-science")
    void start_training(const std::string& target_name);
    
    // Stop training gracefully
    void stop_training();
    
    // Check if training is active
    bool is_training() const { return m_is_training.load(); }
    
    // Get current training metrics
    struct Metrics {
        uint32_t current_epoch = 0;
        float current_loss = 0.0f;
        float current_learning_rate = 0.0f;
        uint64_t samples_processed = 0;
        uint64_t samples_queued = 0;
        bool is_converged = false;
        uint32_t beacon_swaps = 0;        // Phase 18C.3: Swap counter
    };
    Metrics get_metrics() const;
    
    // Set progress callback
    void set_callback(TrainingCallback callback);
    
    // Export current weights to registry
    bool export_adapter(const std::string& name);
    
    // Load checkpoint for continued training
    bool load_checkpoint(const std::string& name);
    
    // Phase 18C.3: Force immediate beacon swap
    bool force_beacon_swap();
    
    // Phase 18C.3: Get shadow buffer pointer (for debugging)
    const ShadowBuffer* get_shadow_buffer() const { return m_shadow_buffer.get(); }

private:
    void training_loop(const std::string& target_name);
    
    // SGD update step
    void update_weights(const std::vector<TrainingSample>& batch);
    
    // Phase 18C.3: Shadow buffer operations
    void initialize_shadow_buffer();
    void sync_to_shadow();
    void perform_beacon_swap();
    bool is_shadow_ready() const;
    
    // Compute loss for a batch
    float compute_loss(const std::vector<TrainingSample>& batch);
    
    // Forward pass: output = B * A * input
    std::vector<float> forward(const std::vector<float>& input);
    
    // Backward pass: compute gradients
    void backward(
        const std::vector<float>& input,
        const std::vector<float>& output,
        const std::vector<float>& target,
        std::vector<float>& grad_A,
        std::vector<float>& grad_B
    );
    
    // Save checkpoint
    void save_checkpoint(const std::string& name, uint32_t epoch);
    
    // Initialize A and B with random values (Xavier initialization)
    void initialize_weights();
    
    // Initialize momentum buffers
    void initialize_momentum_buffers();

private:
    AdapterTrainerConfig m_config;
    std::atomic<bool> m_is_training{false};
    std::atomic<bool> m_should_stop{false};
    
    // Weight matrices (A: rank x hidden, B: hidden x rank)
    std::vector<float> m_A;
    std::vector<float> m_B;
    
    // Momentum buffers
    std::vector<float> m_velocity_A;
    std::vector<float> m_velocity_B;
    
    // Training sample queue
    std::queue<TrainingSample> m_sample_queue;
    mutable std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    
    // Metrics
    mutable std::mutex m_metrics_mutex;
    Metrics m_metrics;
    
    // Background thread
    std::unique_ptr<std::thread> m_training_thread;
    
    // Callback
    TrainingCallback m_callback;
    mutable std::mutex m_callback_mutex;
    
    // Checkpoint directory
    std::filesystem::path m_checkpoint_dir;
    
    // Phase 18C.3: Shadow buffer for atomic beacon swaps
    std::unique_ptr<ShadowBuffer> m_shadow_buffer;
    mutable std::mutex m_shadow_mutex;
    MASM::LoRAContext* m_lora_context = nullptr;  // Beacon pointer
    uint32_t m_steps_since_swap = 0;
};

// Factory for creating pre-configured trainers
class AdapterTrainerFactory {
public:
    // Create trainer optimized for specific domains
    static std::unique_ptr<AdapterTrainer> create_python_trainer();
    static std::unique_ptr<AdapterTrainer> create_cpp_trainer();
    static std::unique_ptr<AdapterTrainer> create_web_trainer();
    static std::unique_ptr<AdapterTrainer> create_embedded_trainer();
    
    // Create with custom config
    static std::unique_ptr<AdapterTrainer> create(const AdapterTrainerConfig& config);
};

} // namespace RawrXD
