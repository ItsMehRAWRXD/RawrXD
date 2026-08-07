// persistent_gpu_loop.cpp - Implementation of zero-dispatch persistent GPU execution
// Part of the Copilot-like inference pipeline.

#include "persistent_gpu_loop.h"
#include <algorithm>
#include <cmath>
#include "vulkan_compute.h"

namespace RawrXD {

PersistentGPULoop::PersistentGPULoop(VulkanCompute* vulkan)
    : vulkan_(vulkan)
{
    stats_ = {};
}

PersistentGPULoop::~PersistentGPULoop() {
    Stop();
}

bool PersistentGPULoop::Initialize(int max_tokens, int kernel_mode) {
    // Initialize persistent state
    state_.max_tokens = max_tokens;
    state_.kernel_mode = kernel_mode;
    state_.current_token = 0;
    state_.generating.store(false);
    state_.stop_requested.store(false);
    
    // Initialize ring buffer
    for (auto& entry : ring_.entries) {
        entry.ready.store(false);
        entry.submitted.store(false);
        entry.completed.store(false);
    }
    ring_.write_index.store(0);
    ring_.read_index.store(0);
    ring_.pending.store(0);
    
    // Initialize Vulkan resources using VulkanCompute
    if (vulkan_) {
        // Calculate buffer sizes based on max tokens and kernel mode
        size_t token_buffer_size = max_tokens * sizeof(uint32_t);
        size_t logits_buffer_size = max_tokens * 32000 * sizeof(float); // vocab_size = 32000
        size_t kv_buffer_size = max_tokens * 4096 * sizeof(float); // head_dim * num_heads
        
        // Allocate persistent buffers
        VkBuffer token_buffer = VK_NULL_HANDLE;
        VkDeviceMemory token_memory = VK_NULL_HANDLE;
        if (!vulkan_->AllocateBuffer(token_buffer_size, token_buffer, token_memory)) {
            fprintf(stderr, "[PersistentGPULoop] Failed to allocate token buffer\n");
            return false;
        }
        
        VkBuffer logits_buffer = VK_NULL_HANDLE;
        VkDeviceMemory logits_memory = VK_NULL_HANDLE;
        if (!vulkan_->AllocateBuffer(logits_buffer_size, logits_buffer, logits_memory)) {
            fprintf(stderr, "[PersistentGPULoop] Failed to allocate logits buffer\n");
            return false;
        }
        
        VkBuffer kv_buffer = VK_NULL_HANDLE;
        VkDeviceMemory kv_memory = VK_NULL_HANDLE;
        if (!vulkan_->AllocateBuffer(kv_buffer_size, kv_buffer, kv_memory)) {
            fprintf(stderr, "[PersistentGPULoop] Failed to allocate KV buffer\n");
            return false;
        }
        
        // Store buffer handles in state
        state_.input_buffer = token_buffer;
        state_.output_buffer = logits_buffer;
        state_.kv_cache_buffer = kv_buffer;
        state_.input_buffer_size = token_buffer_size;
        state_.output_buffer_size = logits_buffer_size;
        state_.kv_cache_buffer_size = kv_buffer_size;
        
        // Initialize command buffer ring entries
        // Note: In a full implementation, we'd create actual Vulkan command buffers here
        // For now, we use the VulkanCompute's command buffer pool
        for (auto& entry : ring_.entries) {
            entry.command_buffer = nullptr; // Will be acquired from pool during execution
            entry.ready.store(false);
            entry.submitted.store(false);
            entry.completed.store(false);
        }
        
        printf("[PersistentGPULoop] Vulkan resources initialized successfully\n");
        printf("  Token buffer: %zu bytes\n", token_buffer_size);
        printf("  Logits buffer: %zu bytes\n", logits_buffer_size);
        printf("  KV buffer: %zu bytes\n", kv_buffer_size);
    } else {
        printf("[PersistentGPULoop] Running in CPU fallback mode (no Vulkan)\n");
    }
    
    return true;
}

void PersistentGPULoop::Start() {
    if (running_.load()) {
        return;
    }
    
    running_.store(true);
    stop_flag_.store(false);
    
    // Start main loop thread
    loop_thread_ = std::thread(&PersistentGPULoop::LoopThread, this);
}

void PersistentGPULoop::Stop() {
    if (!running_.load()) {
        return;
    }
    
    stop_flag_.store(true);
    running_.store(false);
    
    // Notify all condition variables
    batch_cv_.notify_all();
    result_cv_.notify_all();
    
    // Wait for loop thread
    if (loop_thread_.joinable()) {
        loop_thread_.join();
    }
}

bool PersistentGPULoop::SubmitBatch(const TokenBatch& batch) {
    if (!running_.load()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(batch_mutex_);
    batch_queue_.push(batch);
    batch_cv_.notify_one();
    
    return true;
}

bool PersistentGPULoop::GetNextToken(uint32_t& token, float& confidence) {
    std::lock_guard<std::mutex> lock(result_mutex_);
    
    if (result_queue_.empty()) {
        return false;
    }
    
    auto [t, c] = result_queue_.front();
    result_queue_.pop();
    
    token = t;
    confidence = c;
    
    return true;
}

bool PersistentGPULoop::WaitForNextToken(
    uint32_t& token,
    float& confidence,
    std::chrono::milliseconds timeout
) {
    std::unique_lock<std::mutex> lock(result_mutex_);
    
    bool has_token = result_cv_.wait_for(lock, timeout, [this]() {
        return !result_queue_.empty() || stop_flag_.load();
    });
    
    if (!has_token || result_queue_.empty()) {
        return false;
    }
    
    auto [t, c] = result_queue_.front();
    result_queue_.pop();
    
    token = t;
    confidence = c;
    
    return true;
}

void PersistentGPULoop::SetKernelMode(int mode) {
    state_.kernel_mode = mode;
}

void PersistentGPULoop::LoopThread() {
    while (!stop_flag_.load()) {
        // Get next batch
        TokenBatch batch;
        {
            std::unique_lock<std::mutex> lock(batch_mutex_);
            
            bool has_batch = batch_cv_.wait_for(lock, std::chrono::milliseconds(1), [this]() {
                return !batch_queue_.empty() || stop_flag_.load();
            });
            
            if (!has_batch || batch_queue_.empty()) {
                continue;
            }
            
            batch = batch_queue_.front();
            batch_queue_.pop();
        }
        
        // Process batch
        for (int i = 0; i < batch.count; i++) {
            if (stop_flag_.load()) {
                break;
            }
            
            // Get next ring buffer entry
            CommandBufferRing::Entry* entry = ring_.NextWrite();
            
            // Wait if ring is full
            while (ring_.IsFull() && !stop_flag_.load()) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            
            if (stop_flag_.load()) {
                break;
            }
            
            // Prepare command buffer
            auto prep_start = std::chrono::steady_clock::now();
            PrepareCommandBuffer(entry);
            
            // Mark as ready
            entry->ready.store(true);
            entry->submitted.store(false);
            entry->completed.store(false);
            
            // Submit to GPU
            auto submit_start = std::chrono::steady_clock::now();
            SubmitCommandBuffer(entry);
            entry->submit_time = submit_start;
            
            // Update stats
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.total_dispatches++;
                
                auto prep_latency = std::chrono::duration_cast<std::chrono::microseconds>(
                    submit_start - prep_start);
                stats_.avg_dispatch_latency = (stats_.avg_dispatch_latency * (stats_.total_dispatches - 1) + 
                                                 prep_latency) / stats_.total_dispatches;
            }
            
            // Wait for completion
            WaitForCompletion(entry);
            entry->complete_time = std::chrono::steady_clock::now();
            
            // Process result
            // Read output buffer from GPU and process logits
            // This requires GPU memory readback and logit processing
            
            // GPU buffer readback for output tensor
            float* logits = nullptr;
            int vocab_size = config_.vocab_size;
            
            if (vulkan_context_.device && vulkan_context_.output_buffer.buffer != VK_NULL_HANDLE) {
                // Create staging buffer for readback
                VkBufferCreateInfo stagingInfo = {};
                stagingInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
                stagingInfo.size = vocab_size * sizeof(float);
                stagingInfo.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
                stagingInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
                
                VkBuffer stagingBuffer;
                VmaAllocation stagingAlloc;
                vmaCreateBuffer(vma_allocator_, &stagingInfo, 
                               &VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                               &stagingBuffer, &stagingAlloc, nullptr);
                
                // Copy from GPU buffer to staging buffer
                VkCommandBuffer copyCmd = BeginOneTimeCommandBuffer();
                VkBufferCopy copyRegion = {};
                copyRegion.size = vocab_size * sizeof(float);
                vkCmdCopyBuffer(copyCmd, vulkan_context_.output_buffer.buffer, stagingBuffer, 1, &copyRegion);
                EndOneTimeCommandBuffer(copyCmd);
                
                // Map staging buffer and read data
                void* mappedData = nullptr;
                vmaMapMemory(vma_allocator_, stagingAlloc, &mappedData);
                
                // Allocate CPU memory for logits
                logits = new float[vocab_size];
                std::memcpy(logits, mappedData, vocab_size * sizeof(float));
                
                vmaUnmapMemory(vma_allocator_, stagingAlloc);
                vmaDestroyBuffer(vma_allocator_, stagingBuffer, stagingAlloc);
            }
            
            float confidence;
            uint32_t token = SampleToken(logits, vocab_size, confidence);
            
            // Clean up logits
            if (logits) {
                delete[] logits;
            }
            
            // Add to result queue
            {
                std::lock_guard<std::mutex> lock(result_mutex_);
                result_queue_.push({token, confidence});
            }
            result_cv_.notify_one();
            
            // Update stats
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.total_tokens++;
                
                auto token_latency = std::chrono::duration_cast<std::chrono::microseconds>(
                    entry->complete_time - entry->submit_time);
                stats_.avg_token_latency = (stats_.avg_token_latency * (stats_.total_tokens - 1) + 
                                            token_latency) / stats_.total_tokens;
                
                // Calculate GPU idle time
                if (last_complete_time_.time_since_epoch().count() > 0) {
                    auto idle_time = std::chrono::duration_cast<std::chrono::microseconds>(
                        entry->submit_time - last_complete_time_);
                    stats_.avg_gpu_idle_time = (stats_.avg_gpu_idle_time * (stats_.total_tokens - 1) + 
                                                idle_time) / stats_.total_tokens;
                }
                
                last_complete_time_ = entry->complete_time;
            }
            
            state_.current_token++;
        }
    }
}

void PersistentGPULoop::PrepareCommandBuffer(CommandBufferRing::Entry* entry) {
    // Prepare Vulkan command buffer for inference
    // This involves:
    // - Resetting the command buffer to initial state
    // - Binding the compute pipeline for token generation
    // - Binding descriptor sets (input/output buffers)
    // - Updating push constants with current token and kernel mode
    // - Dispatching the compute shader with appropriate workgroup size
    
    if (!entry || !vulkan_context_.device) {
        entry->ready.store(true);
        return;
    }
    
    // Reset command buffer
    VkCommandBufferResetFlags resetFlags = 0;
    vkResetCommandBuffer(entry->command_buffer, resetFlags);
    
    // Begin command buffer recording
    VkCommandBufferBeginInfo beginInfo = {};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    
    if (vkBeginCommandBuffer(entry->command_buffer, &beginInfo) != VK_SUCCESS) {
        entry->ready.store(true);
        return;
    }
    
    // Bind compute pipeline
    if (vulkan_context_.compute_pipeline) {
        vkCmdBindPipeline(entry->command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, 
                         vulkan_context_.compute_pipeline);
    }
    
    // Bind descriptor sets (input/output buffers)
    if (vulkan_context_.descriptor_set) {
        vkCmdBindDescriptorSets(entry->command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE,
                               vulkan_context_.pipeline_layout, 0, 1,
                               &vulkan_context_.descriptor_set, 0, nullptr);
    }
    
    // Update push constants with current token position
    struct PushConstants {
        uint32_t token_position;
        uint32_t kernel_mode;
        float temperature;
    } pushConstants = {
        state_.current_token,
        state_.kernel_mode,
        config_.temperature
    };
    
    vkCmdPushConstants(entry->command_buffer, vulkan_context_.pipeline_layout,
                        VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pushConstants),
                        &pushConstants);
    
    // Dispatch compute shader
    // Workgroup size should match shader configuration
    uint32_t workgroupSizeX = 256;  // Typical for token generation
    uint32_t dispatchX = (state_.batch_size + workgroupSizeX - 1) / workgroupSizeX;
    vkCmdDispatch(entry->command_buffer, dispatchX, 1, 1);
    
    // End command buffer recording
    vkEndCommandBuffer(entry->command_buffer);
    
    entry->ready.store(true);
}

void PersistentGPULoop::SubmitCommandBuffer(CommandBufferRing::Entry* entry) {
    if (!entry || !vulkan_context_.device || !vulkan_context_.compute_queue) {
        entry->submitted.store(true);
        return;
    }
    
    // Submit command buffer to GPU queue
    VkSubmitInfo submitInfo = {};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &entry->command_buffer;
    
    // Use fence for synchronization
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence fence;
    vkCreateFence(vulkan_context_.device, &fenceInfo, nullptr, &fence);
    entry->fence = fence;
    
    VkResult result = vkQueueSubmit(vulkan_context_.compute_queue, 1, &submitInfo, fence);
    if (result != VK_SUCCESS) {
        // Handle submission failure
        vkDestroyFence(vulkan_context_.device, fence, nullptr);
    }
    
    entry->submitted.store(true);
    ring_.pending.fetch_add(1);
}

void PersistentGPULoop::WaitForCompletion(CommandBufferRing::Entry* entry) {
    if (!entry || !vulkan_context_.device) {
        entry->completed.store(true);
        return;
    }
    
    // Wait for GPU command buffer completion using fence
    if (entry->fence) {
        // Wait with timeout (1 second)
        VkResult result = vkWaitForFences(vulkan_context_.device, 1, &entry->fence, 
                                         VK_TRUE, 1000000000ULL);  // 1 second in nanoseconds
        
        if (result == VK_SUCCESS) {
            // Reset fence for reuse
            vkResetFences(vulkan_context_.device, 1, &entry->fence);
        }
        
        // Destroy fence
        vkDestroyFence(vulkan_context_.device, entry->fence, nullptr);
        entry->fence = VK_NULL_HANDLE;
    } else {
        // Fallback: small sleep if no fence available
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    entry->completed.store(true);
    ring_.pending.fetch_sub(1);
}

void PersistentGPULoop::ProcessCompletedToken(const float* logits, int vocab_size) {
    // Sample token from logits
    float confidence;
    uint32_t token = SampleToken(logits, vocab_size, confidence);
    
    // Add to result queue
    {
        std::lock_guard<std::mutex> lock(result_mutex_);
        result_queue_.push({token, confidence});
    }
    result_cv_.notify_one();
}

uint32_t PersistentGPULoop::SampleToken(const float* logits, int vocab_size, float& confidence) {
    // Temperature, top-k, and top-p sampling implementation
    
    // Get sampling parameters
    float temperature = config_.temperature;
    int top_k = config_.top_k;
    float top_p = config_.top_p;
    
    // Apply temperature scaling
    std::vector<float> scaled_logits(vocab_size);
    if (temperature > 0.0f && temperature != 1.0f) {
        for (int i = 0; i < vocab_size; i++) {
            scaled_logits[i] = logits[i] / temperature;
        }
    } else {
        scaled_logits.assign(logits, logits + vocab_size);
    }
    
    // Softmax to get probabilities
    std::vector<float> probs(vocab_size);
    float max_logit = *std::max_element(scaled_logits.begin(), scaled_logits.end());
    float sum = 0.0f;
    
    for (int i = 0; i < vocab_size; i++) {
        probs[i] = std::exp(scaled_logits[i] - max_logit);
        sum += probs[i];
    }
    
    for (auto& p : probs) p /= sum;
    
    // Top-k filtering
    if (top_k > 0 && top_k < vocab_size) {
        // Find k-th largest probability
        std::vector<float> sorted_probs = probs;
        std::nth_element(sorted_probs.begin(), 
                         sorted_probs.begin() + top_k - 1,
                         sorted_probs.end(),
                         std::greater<float>());
        float kth_prob = sorted_probs[top_k - 1];
        
        // Zero out probabilities below threshold
        for (int i = 0; i < vocab_size; i++) {
            if (probs[i] < kth_prob) {
                probs[i] = 0.0f;
            }
        }
        
        // Renormalize
        sum = std::accumulate(probs.begin(), probs.end(), 0.0f);
        if (sum > 0.0f) {
            for (auto& p : probs) p /= sum;
        }
    }
    
    // Top-p (nucleus) filtering
    if (top_p > 0.0f && top_p < 1.0f) {
        // Sort probabilities in descending order
        std::vector<std::pair<float, int>> indexed_probs;
        indexed_probs.reserve(vocab_size);
        for (int i = 0; i < vocab_size; i++) {
            indexed_probs.push_back({probs[i], i});
        }
        
        std::sort(indexed_probs.begin(), indexed_probs.end(),
                  [](const auto& a, const auto& b) { return a.first > b.first; });
        
        // Find cutoff for top-p
        float cumsum = 0.0f;
        size_t cutoff = vocab_size;
        for (size_t i = 0; i < indexed_probs.size(); i++) {
            cumsum += indexed_probs[i].first;
            if (cumsum >= top_p) {
                cutoff = i + 1;
                break;
            }
        }
        
        // Zero out probabilities outside nucleus
        std::vector<float> new_probs(vocab_size, 0.0f);
        for (size_t i = 0; i < cutoff; i++) {
            new_probs[indexed_probs[i].second] = indexed_probs[i].first;
        }
        
        probs = std::move(new_probs);
        
        // Renormalize
        sum = std::accumulate(probs.begin(), probs.end(), 0.0f);
        if (sum > 0.0f) {
            for (auto& p : probs) p /= sum;
        }
    }
    
    // Sample from the filtered distribution
    std::random_device rd;
    std::mt19937 gen(rd());
    std::discrete_distribution<> dist(probs.begin(), probs.end());
    
    int sampled_idx = dist(gen);
    
    // Calculate confidence as the probability of the sampled token
    confidence = probs[sampled_idx];
    
    return static_cast<uint32_t>(sampled_idx);
}

} // namespace RawrXD

