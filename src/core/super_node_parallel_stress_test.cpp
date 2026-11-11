// =============================================================================
// super_node_parallel_stress_test.cpp
// Parallel Stress Test for Sovereign Super-Node Architecture
// Tests worker isolation with poison patterns, guard bands, and telemetry
// =============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <random>
#include <algorithm>
#include <numeric>
#include <string>
#include <immintrin.h>

#include "sovereign_super_node_types.h"

using namespace Sovereign;

// =============================================================================
// Poison Pattern Isolation Canary
// Each worker gets a unique 64-bit pattern written throughout its window
// =============================================================================

static constexpr uint64_t WORKER_POISON_PATTERNS[8] = {
    0x1111111111111111ULL,  // Worker 0
    0x2222222222222222ULL,  // Worker 1
    0x3333333333333333ULL,  // Worker 2
    0x4444444444444444ULL,  // Worker 3
    0x5555555555555555ULL,  // Worker 4
    0x6666666666666666ULL,  // Worker 5
    0x7777777777777777ULL,  // Worker 6
    0x8888888888888888ULL   // Worker 7
};

class IsolationCanary {
public:
    static void InitializePoisonPatterns(uint8_t* window, size_t size, int worker_id) {
        uint64_t pattern = WORKER_POISON_PATTERNS[worker_id % 8];
        size_t num_qwords = size / sizeof(uint64_t);
        uint64_t* ptr = reinterpret_cast<uint64_t*>(window);
        
        for (size_t i = 0; i < num_qwords; i++) {
            ptr[i] = pattern;
        }
        
        // Flush to ensure visibility
        _mm_mfence();
    }
    
    static void InitializePoisonPatterns(void* window, size_t size, int worker_id) {
        InitializePoisonPatterns(static_cast<uint8_t*>(window), size, worker_id);
    }
    
    static bool VerifyIsolation(uint8_t* window, size_t size, int worker_id) {
        uint64_t expected = WORKER_POISON_PATTERNS[worker_id % 8];
        size_t num_qwords = size / sizeof(uint64_t);
        uint64_t* ptr = reinterpret_cast<uint64_t*>(window);
        
        size_t contamination_count = 0;
        for (size_t i = 0; i < num_qwords; i++) {
            if (ptr[i] != expected) {
                contamination_count++;
            }
        }
        
        return contamination_count == 0;
    }
};

// =============================================================================
// Stress Test Configuration
// =============================================================================

struct StressTestConfig {
    enum class SubmissionMode {
        LegacyCopy,
        DirectZeroCopy,
        SharedIngress
    };

    int num_workers = 8;
    int warmup_iterations = 100;
    int measurement_iterations = 1000;
    int batch_size = 32;
    bool verify_isolation = true;
    bool verify_guard_bands = true;
    bool collect_telemetry = true;
    SubmissionMode submission_mode = SubmissionMode::LegacyCopy;
    bool dirty_memory_mode = false;
    uint32_t worker_pre_read_delay_us = 0;
};

static const char* SubmissionModeName(StressTestConfig::SubmissionMode mode) {
    switch (mode) {
    case StressTestConfig::SubmissionMode::LegacyCopy:
        return "legacy-copy";
    case StressTestConfig::SubmissionMode::DirectZeroCopy:
        return "zero-copy";
    case StressTestConfig::SubmissionMode::SharedIngress:
        return "shared-ingress";
    }
    return "unknown";
}

static bool ParseSubmissionMode(const char* value, StressTestConfig::SubmissionMode& mode) {
    if (!value) {
        return false;
    }

    if (_stricmp(value, "copy") == 0 || _stricmp(value, "legacy") == 0 || _stricmp(value, "legacy-copy") == 0) {
        mode = StressTestConfig::SubmissionMode::LegacyCopy;
        return true;
    }
    if (_stricmp(value, "zero") == 0 || _stricmp(value, "zero-copy") == 0 || _stricmp(value, "direct") == 0) {
        mode = StressTestConfig::SubmissionMode::DirectZeroCopy;
        return true;
    }
    if (_stricmp(value, "shared") == 0 || _stricmp(value, "shared-ingress") == 0 || _stricmp(value, "ingress") == 0) {
        mode = StressTestConfig::SubmissionMode::SharedIngress;
        return true;
    }
    return false;
}

static bool ParseBoolFlag(const char* value, bool& enabled) {
    if (!value) {
        return false;
    }

    if (_stricmp(value, "1") == 0 || _stricmp(value, "true") == 0 || _stricmp(value, "on") == 0 || _stricmp(value, "yes") == 0 || _stricmp(value, "dirty") == 0) {
        enabled = true;
        return true;
    }
    if (_stricmp(value, "0") == 0 || _stricmp(value, "false") == 0 || _stricmp(value, "off") == 0 || _stricmp(value, "no") == 0 || _stricmp(value, "clean") == 0) {
        enabled = false;
        return true;
    }
    return false;
}

struct StressTestResults {
    double total_time_ms;
    double tokens_per_second;
    double avg_latency_us;
    double p99_latency_us;
    bool isolation_passed;
    bool guard_bands_passed;
    bool validation_passed;
    uint64_t total_tokens_generated;
    uint64_t validation_failures;
    std::vector<WorkerMetrics> worker_metrics;
};

// =============================================================================
// Mock SuperNodeEngine for Testing
// =============================================================================

class MockSuperNodeEngine {
public:
    std::vector<LogicalWorker> workers;
    std::vector<uint8_t> arena;
    size_t arena_size;
    size_t window_size;
    std::vector<std::unique_ptr<SharedIngressBuffer<1024, 4096>>> ingress_buffers;
    std::atomic<uint32_t> worker_pre_read_delay_us{0};
    
    bool Initialize(const SuperNodeConfig& config) {
        arena_size = config.memory_pool_gb * 1024ULL * 1024ULL * 1024ULL;
        arena.resize(arena_size);
        
        // Calculate window size with guard bands
        size_t guard_total = config.logical_workers * GUARD_BAND_SIZE;
        window_size = (arena_size - guard_total) / config.logical_workers;
        
        workers.resize(config.logical_workers);
        ingress_buffers.resize(config.logical_workers);
        
        for (int i = 0; i < config.logical_workers; i++) {
            workers[i].id = i;
            workers[i].arena_window_ptr = reinterpret_cast<uint8_t*>(arena.data()) + (i * (window_size + GUARD_BAND_SIZE));
            workers[i].arena_window_size = window_size;
            workers[i].batch_request_queue = new LockFreeRingBuffer<BatchRequest, 1024>();
            workers[i].batch_response_queue = new LockFreeRingBuffer<BatchResponse, 1024>();
            workers[i].running.store(true);
            ingress_buffers[i] = std::make_unique<SharedIngressBuffer<1024, 4096>>();
            
            // Initialize guard bands
            if (config.guard_config.enable_guard_bands) {
                uint8_t* guard_start = reinterpret_cast<uint8_t*>(workers[i].arena_window_ptr) + window_size;
                uint64_t* guard_ptr = reinterpret_cast<uint64_t*>(guard_start);
                for (size_t g = 0; g < GUARD_BAND_SIZE / sizeof(uint64_t); g++) {
                    guard_ptr[g] = GUARD_PATTERN;
                }
            }
            
            // Initialize poison patterns for isolation testing
            IsolationCanary::InitializePoisonPatterns(
                reinterpret_cast<uint8_t*>(workers[i].arena_window_ptr), window_size, i);
            
            // Start worker thread
            workers[i].thread = std::thread(&MockSuperNodeEngine::WorkerLoop, this, i);
        }
        
        return true;
    }
    
    void Shutdown() {
        for (auto& worker : workers) {
            worker.running.store(false);
            if (worker.thread.joinable()) {
                worker.thread.join();
            }
            delete worker.batch_request_queue;
            delete worker.batch_response_queue;
            worker.batch_request_queue = nullptr;
            worker.batch_response_queue = nullptr;
        }
    }
    
    bool SubmitBatchToWorker(int worker_id, const BatchRequest& request) {
        if (worker_id < 0 || worker_id >= (int)workers.size()) return false;
        
        auto& worker = workers[worker_id];
        BatchRequest prepared_request = request;

        if (prepared_request.use_shared_ingress) {
            if (!prepared_request.input_tokens_ptr || prepared_request.input_token_count == 0) {
                worker.metrics.ingress_stage_failures.fetch_add(1);
                return false;
            }

            if (!ingress_buffers[worker_id]) {
                worker.metrics.ingress_stage_failures.fetch_add(1);
                return false;
            }

            uint16_t ingress_slot = 0;
            const uint32_t* staged_tokens = nullptr;
            if (!ingress_buffers[worker_id]->Stage(ingress_slot,
                                                   prepared_request.input_tokens_ptr,
                                                   prepared_request.input_token_count,
                                                   staged_tokens)) {
                worker.metrics.ingress_stage_failures.fetch_add(1);
                worker.metrics.ingress_slot_wait_cycles.fetch_add(1);
                return false;
            }
            prepared_request.ingress_slot = ingress_slot;
            prepared_request.input_tokens_ptr = staged_tokens;
        }
        
        // Track queue occupancy before push
        size_t current_occupancy = worker.batch_request_queue->size();
        uint64_t prev_max = worker.metrics.max_queue_occupancy.load();
        if (current_occupancy > prev_max) {
            worker.metrics.max_queue_occupancy.compare_exchange_strong(prev_max, current_occupancy);
        }
        
        bool pushed = worker.batch_request_queue->push(prepared_request);
        
        if (pushed) {
            worker.metrics.tokens_submitted.fetch_add(prepared_request.TokenCount());
            if (prepared_request.use_shared_ingress) {
                worker.metrics.shared_ingress_batches.fetch_add(1);
            } else if (prepared_request.use_zero_copy_input) {
                worker.metrics.direct_zero_copy_batches.fetch_add(1);
            } else {
                worker.metrics.legacy_copy_batches.fetch_add(1);
            }
        } else {
            worker.metrics.queue_full_events.fetch_add(1);
            worker.metrics.queue_push_failures.fetch_add(1);
            if (prepared_request.use_shared_ingress && ingress_buffers[worker_id]) {
                ingress_buffers[worker_id]->Release(prepared_request.ingress_slot);
            }
        }
        
        return pushed;
    }
    
    bool CollectBatchFromWorker(int worker_id, BatchResponse& response) {
        if (worker_id < 0 || worker_id >= (int)workers.size()) return false;
        return workers[worker_id].batch_response_queue->pop(response);
    }
    
    uint8_t* GetWorkerWindowPtr(int worker_id) {
        if (worker_id < 0 || worker_id >= (int)workers.size()) return nullptr;
        return reinterpret_cast<uint8_t*>(workers[worker_id].arena_window_ptr);
    }
    
    size_t GetWorkerWindowSize(int worker_id) {
        if (worker_id < 0 || worker_id >= (int)workers.size()) return 0;
        return workers[worker_id].arena_window_size;
    }
    
    bool VerifyGuardBands() {
        for (size_t i = 0; i < workers.size(); i++) {
            if (!CheckGuardBand((int)i)) return false;
        }
        return true;
    }
    
    bool CheckGuardBand(int worker_id) {
        uint8_t* guard_start = reinterpret_cast<uint8_t*>(workers[worker_id].arena_window_ptr) + window_size;
        uint64_t* guard_ptr = reinterpret_cast<uint64_t*>(guard_start);
        
        for (size_t g = 0; g < GUARD_BAND_SIZE / sizeof(uint64_t); g++) {
            if (guard_ptr[g] != GUARD_PATTERN) {
                printf("[GUARD BAND VIOLATION] Worker %d: guard[%zu] = 0x%016llX (expected 0x%016llX)\n",
                       worker_id, g, guard_ptr[g], GUARD_PATTERN);
                return false;
            }
        }
        return true;
    }
    
    std::vector<WorkerMetrics> CollectMetrics() {
        std::vector<WorkerMetrics> result;
        for (auto& worker : workers) {
            WorkerMetrics m;
            m.tokens_submitted.store(worker.metrics.tokens_submitted.load());
            m.tokens_generated.store(worker.metrics.tokens_generated.load());
            m.queue_full_events.store(worker.metrics.queue_full_events.load());
            m.batches_processed.store(worker.metrics.batches_processed.load());
            m.avg_latency_us.store(worker.metrics.avg_latency_us.load());
            m.queue_push_failures.store(worker.metrics.queue_push_failures.load());
            m.max_queue_occupancy.store(worker.metrics.max_queue_occupancy.load());
            m.total_processing_time_us.store(worker.metrics.total_processing_time_us.load());
            m.context_switches.store(worker.metrics.context_switches.load());
            m.ingress_slot_wait_cycles.store(worker.metrics.ingress_slot_wait_cycles.load());
            m.ingress_stage_failures.store(worker.metrics.ingress_stage_failures.load());
            m.legacy_copy_batches.store(worker.metrics.legacy_copy_batches.load());
            m.direct_zero_copy_batches.store(worker.metrics.direct_zero_copy_batches.load());
            m.shared_ingress_batches.store(worker.metrics.shared_ingress_batches.load());
            result.push_back(m);
        }
        return result;
    }

private:
    void WorkerLoop(int worker_id) {
        auto& worker = workers[worker_id];
        BatchRequest request;
        uint64_t loop_iterations = 0;
        
        while (worker.running.load()) {
            loop_iterations++;
            
            if (worker.batch_request_queue->pop(request)) {
                auto start = std::chrono::high_resolution_clock::now();

                const uint32_t pre_read_delay = worker_pre_read_delay_us.load(std::memory_order_relaxed);
                if (pre_read_delay > 0) {
                    std::this_thread::sleep_for(std::chrono::microseconds(pre_read_delay));
                }
                
                // Simulate inference work
                BatchResponse response;
                response.request_id = request.request_id;
                response.status = RingStatus::OK;
                response.processing_time_us = 100; // Simulated 100us per token

                const uint32_t* request_tokens = request.TokenData();
                const uint32_t request_token_count = request.TokenCount();
                if (request.use_shared_ingress && (!request_tokens || request_token_count == 0)) {
                    worker.metrics.ingress_slot_wait_cycles.fetch_add(1);
                    std::this_thread::yield();
                    continue;
                }
                
                // Generate output tokens (simulated)
                for (size_t i = 0; i < 10 && i < request_token_count; i++) {
                    response.output_tokens.push_back(request_tokens[i] + 1);
                }
                
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
                
                // Update telemetry
                worker.metrics.tokens_generated.fetch_add(response.output_tokens.size());
                worker.metrics.batches_processed.fetch_add(1);
                worker.metrics.total_processing_time_us.fetch_add(duration);
                
                // Update average latency (simple EMA)
                uint64_t current_avg = worker.metrics.avg_latency_us.load();
                uint64_t new_avg = (current_avg == 0) ? duration : (current_avg + duration) / 2;
                worker.metrics.avg_latency_us.store(new_avg);
                
                response.processing_time_us = duration;
                worker.batch_response_queue->push(response);
                if (request.use_shared_ingress && ingress_buffers[worker_id]) {
                    ingress_buffers[worker_id]->Release(request.ingress_slot);
                }
            } else {
                std::this_thread::yield();
                // Approximate context switch when yielding
                if (loop_iterations % 1000 == 0) {
                    worker.metrics.context_switches.fetch_add(1);
                }
            }
        }
    }
};

// =============================================================================
// Stress Test Implementation
// =============================================================================

class ParallelStressTest {
public:
    ParallelStressTest(MockSuperNodeEngine* engine, const StressTestConfig& config)
        : engine_(engine), config_(config) {}
    
    StressTestResults Run() {
        StressTestResults results;
        
        printf("[STRESS TEST] Starting parallel stress test\n");
        printf("  Workers: %d\n", config_.num_workers);
        printf("  Warmup: %d iterations\n", config_.warmup_iterations);
        printf("  Measurement: %d iterations\n", config_.measurement_iterations);
        printf("  Batch size: %d\n", config_.batch_size);
        printf("  Submission mode: %s\n", SubmissionModeName(config_.submission_mode));
        printf("  Dirty memory mode: %s\n", config_.dirty_memory_mode ? "enabled" : "disabled");
        printf("  Worker pre-read delay: %u us\n", config_.worker_pre_read_delay_us);
        
        // Warmup phase
        printf("\n[WARMUP] Running %d iterations...\n", config_.warmup_iterations);
        FloodWorkers(config_.warmup_iterations);
        
        // Reset metrics after warmup
        for (auto& worker : engine_->workers) {
            worker.metrics.Reset();
        }
        
        // Measurement phase
        printf("[MEASUREMENT] Running %d iterations...\n", config_.measurement_iterations);
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<double> latencies = FloodWorkers(config_.measurement_iterations);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto total_duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        results.total_time_ms = static_cast<double>(total_duration_us) / 1000.0;
        results.total_tokens_generated = 0;
        
        // Collect telemetry
        results.worker_metrics = engine_->CollectMetrics();
        for (const auto& m : results.worker_metrics) {
            results.total_tokens_generated += m.tokens_generated.load();
        }
        
        // Calculate throughput
        results.tokens_per_second = (results.total_time_ms > 0.0)
            ? ((results.total_tokens_generated * 1000.0) / results.total_time_ms)
            : 0.0;
        
        // Calculate latency statistics
        if (!latencies.empty()) {
            results.avg_latency_us = std::accumulate(latencies.begin(), latencies.end(), 0.0) / latencies.size();
            std::sort(latencies.begin(), latencies.end());
            size_t p99_idx = static_cast<size_t>(latencies.size() * 0.99);
            results.p99_latency_us = latencies[p99_idx];
        }

        results.validation_failures = last_validation_failures_;
        results.validation_passed = (results.validation_failures == 0);
        
        // Verify isolation
        if (config_.verify_isolation) {
            printf("\n[ISOLATION CHECK] Verifying poison patterns...\n");
            results.isolation_passed = true;
            for (int i = 0; i < config_.num_workers; i++) {
                uint8_t* window = engine_->GetWorkerWindowPtr(i);
                size_t size = engine_->GetWorkerWindowSize(i);
                if (!IsolationCanary::VerifyIsolation(window, size, i)) {
                    printf("  [FAIL] Worker %d: Poison pattern contamination detected!\n", i);
                    results.isolation_passed = false;
                } else {
                    printf("  [PASS] Worker %d: No contamination\n", i);
                }
            }
        }
        
        // Verify guard bands
        if (config_.verify_guard_bands) {
            printf("\n[GUARD BAND CHECK] Verifying guard band integrity...\n");
            results.guard_bands_passed = engine_->VerifyGuardBands();
            if (results.guard_bands_passed) {
                printf("  [PASS] All guard bands intact\n");
            } else {
                printf("  [FAIL] Guard band corruption detected!\n");
            }
        }
        
        return results;
    }

private:
    std::vector<double> FloodWorkers(int iterations) {
        std::vector<double> latencies;
        latencies.reserve(iterations * config_.num_workers);
        
        std::atomic<uint64_t> completed_count{0};
        std::atomic<uint64_t> validation_failures{0};
        std::vector<std::thread> submitters;
        std::vector<std::thread> collectors;
        std::vector<std::vector<std::vector<uint32_t>>> stable_payloads(
            config_.num_workers,
            std::vector<std::vector<uint32_t>>(iterations, std::vector<uint32_t>(config_.batch_size)));
        std::vector<std::vector<std::vector<uint32_t>>> expected_outputs(
            config_.num_workers,
            std::vector<std::vector<uint32_t>>(iterations));

        engine_->worker_pre_read_delay_us.store(config_.worker_pre_read_delay_us, std::memory_order_relaxed);
        
        // Launch submitter threads
        for (int w = 0; w < config_.num_workers; w++) {
            submitters.emplace_back([this, w, iterations, &stable_payloads, &expected_outputs]() {
                std::mt19937 rng(w);
                std::uniform_int_distribution<uint32_t> token_dist(0, 10000);
                
                for (int i = 0; i < iterations; i++) {
                    BatchRequest request;
                    request.request_id = (uint64_t)w * 1000000ULL + i;
                    request.deadline_us = 1000000; // 1 second
                    
                    std::vector<uint32_t>& payload = stable_payloads[w][i];
                    for (int b = 0; b < config_.batch_size; b++) {
                        payload[b] = token_dist(rng);
                    }

                    std::vector<uint32_t>& expected = expected_outputs[w][i];
                    expected.clear();
                    const size_t expected_count = std::min<size_t>(10, payload.size());
                    expected.reserve(expected_count);
                    for (size_t token_index = 0; token_index < expected_count; ++token_index) {
                        expected.push_back(payload[token_index] + 1);
                    }

                    switch (config_.submission_mode) {
                    case StressTestConfig::SubmissionMode::LegacyCopy:
                        request.input_tokens = payload;
                        break;
                    case StressTestConfig::SubmissionMode::DirectZeroCopy:
                        request.use_zero_copy_input = true;
                        request.input_tokens_ptr = payload.data();
                        request.input_token_count = static_cast<uint32_t>(payload.size());
                        break;
                    case StressTestConfig::SubmissionMode::SharedIngress:
                        request.use_zero_copy_input = true;
                        request.use_shared_ingress = true;
                        request.input_tokens_ptr = payload.data();
                        request.input_token_count = static_cast<uint32_t>(payload.size());
                        break;
                    }
                    
                    while (!engine_->SubmitBatchToWorker(w, request)) {
                        std::this_thread::yield();
                    }

                    if (config_.dirty_memory_mode && config_.submission_mode != StressTestConfig::SubmissionMode::LegacyCopy) {
                        std::fill(payload.begin(), payload.end(), 0xDEADu);
                    }
                }
            });
        }
        
        // Launch collector threads
        for (int w = 0; w < config_.num_workers; w++) {
            collectors.emplace_back([this, w, iterations, &completed_count, &latencies, &expected_outputs, &validation_failures]() {
                int collected = 0;
                while (collected < iterations) {
                    BatchResponse response;
                    if (engine_->CollectBatchFromWorker(w, response)) {
                        const uint32_t iteration_index = static_cast<uint32_t>(response.request_id % 1000000ULL);
                        if (iteration_index < expected_outputs[w].size()) {
                            const auto& expected = expected_outputs[w][iteration_index];
                            const size_t compare_count = std::min(expected.size(), response.output_tokens.size());
                            bool valid = (expected.size() == response.output_tokens.size());
                            for (size_t token_index = 0; token_index < compare_count && valid; ++token_index) {
                                if (expected[token_index] != response.output_tokens[token_index]) {
                                    valid = false;
                                }
                            }
                            if (!valid) {
                                validation_failures.fetch_add(1, std::memory_order_relaxed);
                            }
                        }
                        latencies.push_back(static_cast<double>(response.processing_time_us));
                        collected++;
                        completed_count.fetch_add(1);
                    } else {
                        std::this_thread::yield();
                    }
                }
            });
        }
        
        // Wait for completion
        for (auto& t : submitters) t.join();
        for (auto& t : collectors) t.join();

        last_validation_failures_ = validation_failures.load(std::memory_order_relaxed);
        
        return latencies;
    }
    
    MockSuperNodeEngine* engine_;
    StressTestConfig config_;
    uint64_t last_validation_failures_ = 0;
};

// =============================================================================
// Main Entry Point
// =============================================================================

int main(int argc, char* argv[]) {
    printf("=================================================================\n");
    printf("  Sovereign Super-Node Parallel Stress Test\n");
    printf("=================================================================\n\n");
    
    // Parse command line arguments
    StressTestConfig config;
    if (argc > 1) config.num_workers = std::atoi(argv[1]);
    if (argc > 2) config.measurement_iterations = std::atoi(argv[2]);
    if (argc > 3) config.batch_size = std::atoi(argv[3]);
    if (argc > 4 && !ParseSubmissionMode(argv[4], config.submission_mode)) {
        printf("[ERROR] Unknown submission mode '%s'\n", argv[4]);
        printf("Usage: sovereign_super_node_stress [workers] [iterations] [batch_size] [copy|zero-copy|shared-ingress] [dirty=true|false] [worker_pre_read_delay_us]\n");
        return 2;
    }
    if (argc > 5 && !ParseBoolFlag(argv[5], config.dirty_memory_mode)) {
        printf("[ERROR] Unknown dirty-memory flag '%s'\n", argv[5]);
        printf("Usage: sovereign_super_node_stress [workers] [iterations] [batch_size] [copy|zero-copy|shared-ingress] [dirty=true|false] [worker_pre_read_delay_us]\n");
        return 2;
    }
    if (argc > 6) config.worker_pre_read_delay_us = static_cast<uint32_t>(std::atoi(argv[6]));
    
    // Initialize engine
    SuperNodeConfig engine_config;
    engine_config.logical_workers = config.num_workers;
    engine_config.memory_pool_gb = 2;  // 2GB arena
    engine_config.guard_config.enable_guard_bands = true;
    engine_config.guard_config.verify_post_test = true;
    
    MockSuperNodeEngine engine;
    if (!engine.Initialize(engine_config)) {
        printf("[ERROR] Failed to initialize engine\n");
        return 1;
    }
    
    // Run stress test
    ParallelStressTest stress_test(&engine, config);
    StressTestResults results = stress_test.Run();
    
    // Print results
    printf("\n=================================================================\n");
    printf("  RESULTS\n");
    printf("=================================================================\n");
    printf("Total Time:        %.2f ms\n", results.total_time_ms);
    printf("Total Tokens:      %llu\n", results.total_tokens_generated);
    printf("Throughput:        %.2f tokens/sec\n", results.tokens_per_second);
    printf("Avg Latency:       %.2f us\n", results.avg_latency_us);
    printf("P99 Latency:       %.2f us\n", results.p99_latency_us);
    printf("Validation Check:  %s\n", results.validation_passed ? "PASSED" : "FAILED");
    printf("Validation Errors: %llu\n", results.validation_failures);
    printf("Isolation Check:   %s\n", results.isolation_passed ? "PASSED" : "FAILED");
    printf("Guard Band Check:  %s\n", results.guard_bands_passed ? "PASSED" : "FAILED");
    
    printf("\nPer-Worker Telemetry:\n");
    for (size_t i = 0; i < results.worker_metrics.size(); i++) {
        const auto& m = results.worker_metrics[i];
        printf("  Worker %zu:\n", i);
        printf("    submitted=%llu generated=%llu batches=%llu\n",
               m.tokens_submitted.load(), m.tokens_generated.load(), m.batches_processed.load());
        printf("    queue_full=%llu push_failures=%llu max_occupancy=%llu\n",
               m.queue_full_events.load(), m.queue_push_failures.load(), m.max_queue_occupancy.load());
        printf("    avg_lat=%llu us total_proc=%llu us ctx_switches=%llu\n",
               m.avg_latency_us.load(), m.total_processing_time_us.load(), m.context_switches.load());
         printf("    ingress_wait=%llu ingress_stage_fail=%llu\n",
             m.ingress_slot_wait_cycles.load(), m.ingress_stage_failures.load());
         printf("    mode_counts copy=%llu zero=%llu shared=%llu\n",
             m.legacy_copy_batches.load(), m.direct_zero_copy_batches.load(), m.shared_ingress_batches.load());
    }
    
    // Cleanup
    engine.Shutdown();
    
    // Return success/failure
    bool all_passed = results.validation_passed && results.isolation_passed && results.guard_bands_passed;
    printf("\n=================================================================\n");
    printf("  OVERALL: %s\n", all_passed ? "PASSED" : "FAILED");
    printf("=================================================================\n");
    
    return all_passed ? 0 : 1;
}
