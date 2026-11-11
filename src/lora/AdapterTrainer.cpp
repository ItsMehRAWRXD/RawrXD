#include "AdapterTrainer.h"
#include "AdapterRegistry.h"
#include "LoRAAdapterManager.h"
#include "../fusion/kernels/LoRAContext.h"
#include <random>
#include <cmath>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <intrin.h>  // For _mm_sfence

namespace RawrXD {

// ============================================================================
// ShadowBuffer Implementation (Phase 18C.3)
// ============================================================================

void ShadowBuffer::allocate(uint32_t rank, uint32_t hidden_dim) {
    matrix_A.resize(rank * hidden_dim);
    matrix_B.resize(hidden_dim * rank);
    ready.store(false);
}

void ShadowBuffer::copy_from(const std::vector<float>& A, const std::vector<float>& B) {
    matrix_A = A;
    matrix_B = B;
    version++;
}

void ShadowBuffer::swap_to_loRAContext(MASM::LoRAContext* context, float alpha) {
    if (!context || matrix_A.empty() || matrix_B.empty()) return;
    
    // Update context pointers atomically
    context->alpha = alpha;
    context->matrix_A = matrix_A.data();
    context->matrix_B = matrix_B.data();
    
    // Memory fence to ensure ordering
    _mm_sfence();
    
    // Mark as active
    context->active = 1;
}

// ============================================================================
// AdapterTrainer Implementation
// ============================================================================

AdapterTrainer::AdapterTrainer() {
    // Default checkpoint directory
    const char* user_profile = std::getenv("USERPROFILE");
    if (user_profile) {
        m_checkpoint_dir = std::filesystem::path(user_profile) / ".rawrxd" / "checkpoints";
    } else {
        m_checkpoint_dir = std::filesystem::temp_directory_path() / "rawrxd_checkpoints";
    }
    std::filesystem::create_directories(m_checkpoint_dir);
}

AdapterTrainer::~AdapterTrainer() {
    stop_training();
}

void AdapterTrainer::initialize(const AdapterTrainerConfig& config) {
    m_config = config;
    initialize_weights();
    
    // Phase 18C.3: Initialize shadow buffer if enabled
    if (m_config.use_shadow_buffer) {
        initialize_shadow_buffer();
    }
}

void AdapterTrainer::initialize_weights() {
    // Xavier initialization: weights ~ U(-sqrt(6/(in+out)), sqrt(6/(in+out)))
    std::random_device rd;
    std::mt19937 gen(rd());
    
    float limit = std::sqrt(6.0f / (m_config.hidden_dim + m_config.rank));
    std::uniform_real_distribution<float> dist(-limit, limit);
    
    // Initialize A: rank x hidden_dim
    m_A.resize(m_config.rank * m_config.hidden_dim);
    for (auto& w : m_A) {
        w = dist(gen);
    }
    
    // Initialize B: hidden_dim x rank (start with zeros for stability)
    m_B.resize(m_config.hidden_dim * m_config.rank, 0.0f);
    
    // Phase 18C.3: Initialize shadow buffer
    if (m_shadow_buffer) {
        m_shadow_buffer->allocate(m_config.rank, m_config.hidden_dim);
        m_shadow_buffer->copy_from(m_A, m_B);
    }
}

// Phase 18C.3: Shadow buffer initialization
void AdapterTrainer::initialize_shadow_buffer() {
    m_shadow_buffer = std::make_unique<ShadowBuffer>();
    m_shadow_buffer->allocate(m_config.rank, m_config.hidden_dim);
    
    // Get or create LoRAContext beacon
    auto& beacon_mgr = MASM::LoRABeaconManager::instance();
    if (!beacon_mgr.isActive()) {
        // Create a new context for this trainer
        static MASM::LoRAContext context{};
        context.alpha = m_config.learning_rate * 100; // Scaling factor
        context.rank = m_config.rank;
        context.input_dim = m_config.hidden_dim;
        context.flags = MASM::LoRAContext::FLAG_VALID | 
                       MASM::LoRAContext::FLAG_READY |
                       MASM::LoRAContext::FLAG_FMA3;
        beacon_mgr.updateBeacon(&context);
        m_lora_context = &context;
    } else {
        m_lora_context = const_cast<MASM::LoRAContext*>(beacon_mgr.getContext());
    }
}

// Phase 18C.3: Sync training weights to shadow buffer
void AdapterTrainer::sync_to_shadow() {
    if (!m_shadow_buffer || !m_config.use_shadow_buffer) return;
    
    std::lock_guard<std::mutex> lock(m_shadow_mutex);
    m_shadow_buffer->copy_from(m_A, m_B);
    m_shadow_buffer->ready.store(true);
}

// Phase 18C.3: Perform atomic beacon swap
void AdapterTrainer::perform_beacon_swap() {
    if (!m_shadow_buffer || !m_lora_context) return;
    
    std::lock_guard<std::mutex> lock(m_shadow_mutex);
    if (m_shadow_buffer->ready.load()) {
        m_shadow_buffer->swap_to_loRAContext(m_lora_context, 16.0f); // alpha=16.0
        m_shadow_buffer->ready.store(false);
        
        // Update metrics
        std::lock_guard<std::mutex> metrics_lock(m_metrics_mutex);
        m_metrics.beacon_swaps++;
    }
}

// Phase 18C.3: Check if shadow is ready
bool AdapterTrainer::is_shadow_ready() const {
    return m_shadow_buffer && m_shadow_buffer->ready.load();
}

// Phase 18C.3: Force immediate beacon swap
bool AdapterTrainer::force_beacon_swap() {
    if (!m_config.use_shadow_buffer) return false;
    
    sync_to_shadow();
    perform_beacon_swap();
    return true;
}

void AdapterTrainer::initialize_momentum_buffers() {
    // Initialize momentum buffers
    m_velocity_A.resize(m_A.size(), 0.0f);
    m_velocity_B.resize(m_B.size(), 0.0f);
}

void AdapterTrainer::enqueue_sample(const TrainingSample& sample) {
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_sample_queue.push(sample);
    }
    m_queue_cv.notify_one();
    
    std::lock_guard<std::mutex> metrics_lock(m_metrics_mutex);
    m_metrics.samples_queued++;
}

void AdapterTrainer::start_training(const std::string& target_name) {
    if (m_is_training.load()) {
        return; // Already training
    }
    
    m_should_stop.store(false);
    m_is_training.store(true);
    
    // Reset metrics
    {
        std::lock_guard<std::mutex> lock(m_metrics_mutex);
        m_metrics = Metrics{};
    }
    
    m_training_thread = std::make_unique<std::thread>(
        &AdapterTrainer::training_loop, this, target_name
    );
}

void AdapterTrainer::stop_training() {
    m_should_stop.store(true);
    m_queue_cv.notify_all();
    
    if (m_training_thread && m_training_thread->joinable()) {
        m_training_thread->join();
    }
    
    m_is_training.store(false);
}

AdapterTrainer::Metrics AdapterTrainer::get_metrics() const {
    std::lock_guard<std::mutex> lock(m_metrics_mutex);
    return m_metrics;
}

void AdapterTrainer::set_callback(TrainingCallback callback) {
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_callback = callback;
}

void AdapterTrainer::training_loop(const std::string& target_name) {
    std::vector<TrainingSample> batch;
    batch.reserve(m_config.batch_size);
    
    float prev_loss = std::numeric_limits<float>::max();
    float current_lr = m_config.learning_rate;
    
    for (uint32_t epoch = 0; epoch < m_config.max_epochs && !m_should_stop.load(); ++epoch) {
        batch.clear();
        
        // Collect batch from queue
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            while (batch.size() < m_config.batch_size && !m_should_stop.load()) {
                if (!m_sample_queue.empty()) {
                    batch.push_back(m_sample_queue.front());
                    m_sample_queue.pop();
                } else {
                    // Wait for more samples or timeout
                    m_queue_cv.wait_for(lock, std::chrono::seconds(1));
                    if (m_sample_queue.empty()) break;
                }
            }
        }
        
        if (batch.empty()) {
            continue; // No samples available
        }
        
        // Compute loss before update
        float loss = compute_loss(batch);
        
        // SGD update
        update_weights(batch);
        
        // Phase 18C.3: Shadow buffer sync and beacon swap
        if (m_config.use_shadow_buffer) {
            m_steps_since_swap++;
            
            // Sync to shadow buffer
            sync_to_shadow();
            
            // Perform beacon swap at interval
            if (m_steps_since_swap >= m_config.beacon_swap_interval) {
                perform_beacon_swap();
                m_steps_since_swap = 0;
            }
        }
        
        // Update learning rate with decay
        if (m_config.use_lr_decay && epoch > 0 && epoch % m_config.lr_decay_steps == 0) {
            current_lr *= m_config.lr_decay_rate;
        }
        
        // Update metrics
        {
            std::lock_guard<std::mutex> lock(m_metrics_mutex);
            m_metrics.current_epoch = epoch;
            m_metrics.current_loss = loss;
            m_metrics.current_learning_rate = current_lr;
            m_metrics.samples_processed += batch.size();
            
            // Check convergence
            float loss_change = std::abs(prev_loss - loss);
            m_metrics.is_converged = loss_change < m_config.convergence_threshold;
        }
        
        // Invoke callback
        {
            std::lock_guard<std::mutex> lock(m_callback_mutex);
            if (m_callback) {
                m_callback(epoch, loss, current_lr, m_should_stop.load());
            }
        }
        
        // Checkpoint
        if (epoch % m_config.checkpoint_interval == 0) {
            save_checkpoint(target_name, epoch);
        }
        
        // Check convergence
        if (m_metrics.is_converged) {
            break;
        }
        
        prev_loss = loss;
    }
    
    // Final export
    export_adapter(target_name);
    m_is_training.store(false);
}

std::vector<float> AdapterTrainer::forward(const std::vector<float>& input) {
    // Compute: output = B * A * input
    // Step 1: temp = A * input (rank x 1)
    std::vector<float> temp(m_config.rank, 0.0f);
    for (uint32_t r = 0; r < m_config.rank; ++r) {
        float sum = 0.0f;
        for (uint32_t i = 0; i < m_config.hidden_dim; ++i) {
            sum += m_A[r * m_config.hidden_dim + i] * input[i];
        }
        temp[r] = sum;
    }
    
    // Step 2: output = B * temp (hidden_dim x 1)
    std::vector<float> output(m_config.hidden_dim, 0.0f);
    for (uint32_t o = 0; o < m_config.hidden_dim; ++o) {
        float sum = 0.0f;
        for (uint32_t r = 0; r < m_config.rank; ++r) {
            sum += m_B[o * m_config.rank + r] * temp[r];
        }
        output[o] = sum;
    }
    
    return output;
}

float AdapterTrainer::compute_loss(const std::vector<TrainingSample>& batch) {
    float total_loss = 0.0f;
    
    for (const auto& sample : batch) {
        auto output = forward(sample.input_embedding);
        
        // MSE loss: ||output - target||^2
        float sample_loss = 0.0f;
        for (size_t i = 0; i < output.size() && i < sample.target_embedding.size(); ++i) {
            float diff = output[i] - sample.target_embedding[i];
            sample_loss += diff * diff;
        }
        
        // L2 regularization
        float l2_penalty = 0.0f;
        for (const auto& w : m_A) l2_penalty += w * w;
        for (const auto& w : m_B) l2_penalty += w * w;
        
        total_loss += sample_loss * sample.weight + m_config.l2_regularization * l2_penalty;
    }
    
    return total_loss / batch.size();
}

void AdapterTrainer::backward(
    const std::vector<float>& input,
    const std::vector<float>& output,
    const std::vector<float>& target,
    std::vector<float>& grad_A,
    std::vector<float>& grad_B
) {
    // Compute gradients for MSE loss
    // dL/dy = 2 * (y - target)
    std::vector<float> d_output(m_config.hidden_dim);
    for (uint32_t i = 0; i < m_config.hidden_dim; ++i) {
        d_output[i] = 2.0f * (output[i] - target[i]);
    }
    
    // Step 1: Compute temp = A * input (needed for B grad)
    std::vector<float> temp(m_config.rank);
    for (uint32_t r = 0; r < m_config.rank; ++r) {
        float sum = 0.0f;
        for (uint32_t i = 0; i < m_config.hidden_dim; ++i) {
            sum += m_A[r * m_config.hidden_dim + i] * input[i];
        }
        temp[r] = sum;
    }
    
    // Step 2: dL/dB = dL/dy * temp^T
    grad_B.resize(m_B.size(), 0.0f);
    for (uint32_t o = 0; o < m_config.hidden_dim; ++o) {
        for (uint32_t r = 0; r < m_config.rank; ++r) {
            grad_B[o * m_config.rank + r] = d_output[o] * temp[r];
        }
    }
    
    // Step 3: dL/dtemp = B^T * dL/dy
    std::vector<float> d_temp(m_config.rank);
    for (uint32_t r = 0; r < m_config.rank; ++r) {
        float sum = 0.0f;
        for (uint32_t o = 0; o < m_config.hidden_dim; ++o) {
            sum += m_B[o * m_config.rank + r] * d_output[o];
        }
        d_temp[r] = sum;
    }
    
    // Step 4: dL/dA = dL/dtemp * input^T
    grad_A.resize(m_A.size(), 0.0f);
    for (uint32_t r = 0; r < m_config.rank; ++r) {
        for (uint32_t i = 0; i < m_config.hidden_dim; ++i) {
            grad_A[r * m_config.hidden_dim + i] = d_temp[r] * input[i];
        }
    }
}

void AdapterTrainer::update_weights(const std::vector<TrainingSample>& batch) {
    std::vector<float> grad_A(m_A.size(), 0.0f);
    std::vector<float> grad_B(m_B.size(), 0.0f);
    
    // Accumulate gradients over batch
    for (const auto& sample : batch) {
        auto output = forward(sample.input_embedding);
        
        std::vector<float> sample_grad_A, sample_grad_B;
        backward(sample.input_embedding, output, sample.target_embedding, 
                 sample_grad_A, sample_grad_B);
        
        for (size_t i = 0; i < grad_A.size(); ++i) {
            grad_A[i] += sample_grad_A[i] * sample.weight;
        }
        for (size_t i = 0; i < grad_B.size(); ++i) {
            grad_B[i] += sample_grad_B[i] * sample.weight;
        }
    }
    
    // Average gradients
    for (auto& g : grad_A) g /= batch.size();
    for (auto& g : grad_B) g /= batch.size();
    
    // Add L2 regularization gradient
    for (size_t i = 0; i < m_A.size(); ++i) {
        grad_A[i] += 2.0f * m_config.l2_regularization * m_A[i];
    }
    for (size_t i = 0; i < m_B.size(); ++i) {
        grad_B[i] += 2.0f * m_config.l2_regularization * m_B[i];
    }
    
    // SGD with momentum update
    float lr = m_metrics.current_learning_rate > 0 ? m_metrics.current_learning_rate : m_config.learning_rate;
    float momentum = 0.9f;
    
    for (size_t i = 0; i < m_A.size(); ++i) {
        m_velocity_A[i] = momentum * m_velocity_A[i] - lr * grad_A[i];
        m_A[i] += m_velocity_A[i];
    }
    
    for (size_t i = 0; i < m_B.size(); ++i) {
        m_velocity_B[i] = momentum * m_velocity_B[i] - lr * grad_B[i];
        m_B[i] += m_velocity_B[i];
    }
}

void AdapterTrainer::save_checkpoint(const std::string& name, uint32_t epoch) {
    std::filesystem::path checkpoint_path = m_checkpoint_dir / (name + "_epoch" + std::to_string(epoch) + ".lora");
    
    std::ofstream file(checkpoint_path, std::ios::binary);
    if (!file) return;
    
    // Header
    file.write("RAWRLORA", 8);
    uint32_t version = 1;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    
    // Dimensions
    file.write(reinterpret_cast<const char*>(&m_config.rank), sizeof(m_config.rank));
    file.write(reinterpret_cast<const char*>(&m_config.hidden_dim), sizeof(m_config.hidden_dim));
    file.write(reinterpret_cast<const char*>(&m_config.hidden_dim), sizeof(m_config.hidden_dim));
    
    // Weights
    file.write(reinterpret_cast<const char*>(m_A.data()), m_A.size() * sizeof(float));
    file.write(reinterpret_cast<const char*>(m_B.data()), m_B.size() * sizeof(float));
}

bool AdapterTrainer::export_adapter(const std::string& name) {
    // Save to registry cache directory
    auto& registry = AdapterRegistry::instance();
    std::filesystem::path adapter_path = registry.get_adapter_cache_dir() / (name + ".lora");
    
    std::ofstream file(adapter_path, std::ios::binary);
    if (!file) return false;
    
    // Header
    file.write("RAWRLORA", 8);
    uint32_t version = 1;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    
    // Dimensions
    file.write(reinterpret_cast<const char*>(&m_config.rank), sizeof(m_config.rank));
    file.write(reinterpret_cast<const char*>(&m_config.hidden_dim), sizeof(m_config.hidden_dim));
    file.write(reinterpret_cast<const char*>(&m_config.hidden_dim), sizeof(m_config.hidden_dim));
    
    // Weights
    file.write(reinterpret_cast<const char*>(m_A.data()), m_A.size() * sizeof(float));
    file.write(reinterpret_cast<const char*>(m_B.data()), m_B.size() * sizeof(float));
    
    // Create manifest
    AdapterManifest manifest;
    manifest.name = name;
    manifest.version = "1.0.0";
    manifest.rank = m_config.rank;
    manifest.trained_samples = m_metrics.samples_processed;
    manifest.training_loss = m_metrics.current_loss;
    manifest.modified_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    std::filesystem::path manifest_path = registry.get_adapter_cache_dir() / (name + ".json");
    std::ofstream manifest_file(manifest_path);
    if (manifest_file) {
        manifest_file << manifest.to_json();
    }
    
    return true;
}

bool AdapterTrainer::load_checkpoint(const std::string& name) {
    // Find latest checkpoint
    std::filesystem::path latest_checkpoint;
    uint32_t latest_epoch = 0;
    
    for (const auto& entry : std::filesystem::directory_iterator(m_checkpoint_dir)) {
        std::string filename = entry.path().filename().string();
        if (filename.find(name + "_epoch") == 0 && filename.ends_with(".lora")) {
            // Parse epoch number
            size_t start = filename.find("epoch") + 5;
            size_t end = filename.find(".lora");
            uint32_t epoch = std::stoul(filename.substr(start, end - start));
            if (epoch > latest_epoch) {
                latest_epoch = epoch;
                latest_checkpoint = entry.path();
            }
        }
    }
    
    if (latest_checkpoint.empty()) {
        return false;
    }
    
    // Load weights (reuse registry parser logic)
    std::ifstream file(latest_checkpoint, std::ios::binary);
    if (!file) return false;
    
    char header[8];
    file.read(header, 8);
    if (std::memcmp(header, "RAWRLORA", 8) != 0) return false;
    
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 1) return false;
    
    uint32_t rank, in_features, out_features;
    file.read(reinterpret_cast<char*>(&rank), sizeof(rank));
    file.read(reinterpret_cast<char*>(&in_features), sizeof(in_features));
    file.read(reinterpret_cast<char*>(&out_features), sizeof(out_features));
    
    m_config.rank = rank;
    m_config.hidden_dim = out_features;
    
    m_A.resize(rank * in_features);
    m_B.resize(out_features * rank);
    
    file.read(reinterpret_cast<char*>(m_A.data()), m_A.size() * sizeof(float));
    file.read(reinterpret_cast<char*>(m_B.data()), m_B.size() * sizeof(float));
    
    // Reinitialize velocity buffers
    m_velocity_A.resize(m_A.size(), 0.0f);
    m_velocity_B.resize(m_B.size(), 0.0f);
    
    return true;
}

// ============================================================================
// AdapterTrainerFactory Implementation
// ============================================================================

std::unique_ptr<AdapterTrainer> AdapterTrainerFactory::create_python_trainer() {
    AdapterTrainerConfig config;
    config.rank = 16;              // Higher rank for Python's diversity
    config.learning_rate = 5e-5f;  // Conservative for stability
    config.batch_size = 64;        // Larger batches for Python
    config.l2_regularization = 0.005f;
    
    auto trainer = std::make_unique<AdapterTrainer>();
    trainer->initialize(config);
    return trainer;
}

std::unique_ptr<AdapterTrainer> AdapterTrainerFactory::create_cpp_trainer() {
    AdapterTrainerConfig config;
    config.rank = 8;               // Lower rank for C++ patterns
    config.learning_rate = 1e-4f;  // Faster convergence
    config.batch_size = 32;
    config.l2_regularization = 0.01f;
    
    auto trainer = std::make_unique<AdapterTrainer>();
    trainer->initialize(config);
    return trainer;
}

std::unique_ptr<AdapterTrainer> AdapterTrainerFactory::create_web_trainer() {
    AdapterTrainerConfig config;
    config.rank = 12;              // Medium rank for web stack
    config.learning_rate = 8e-5f;
    config.batch_size = 48;
    config.l2_regularization = 0.008f;
    
    auto trainer = std::make_unique<AdapterTrainer>();
    trainer->initialize(config);
    return trainer;
}

std::unique_ptr<AdapterTrainer> AdapterTrainerFactory::create_embedded_trainer() {
    AdapterTrainerConfig config;
    config.rank = 4;               // Minimal rank for constrained envs
    config.learning_rate = 2e-4f;  // Fast adaptation
    config.batch_size = 16;        // Small batches
    config.l2_regularization = 0.02f;
    
    auto trainer = std::make_unique<AdapterTrainer>();
    trainer->initialize(config);
    return trainer;
}

std::unique_ptr<AdapterTrainer> AdapterTrainerFactory::create(const AdapterTrainerConfig& config) {
    auto trainer = std::make_unique<AdapterTrainer>();
    trainer->initialize(config);
    return trainer;
}

} // namespace RawrXD
