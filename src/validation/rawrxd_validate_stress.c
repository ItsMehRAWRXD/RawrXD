//=============================================================================
// rawrxd_validate_stress.c
// Stress Testing Implementation
//=============================================================================

#include "rawrxd_validate.h"
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>

static u64 get_memory_usage(void) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
}

static double get_time_sec(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}

#else
#include <sys/resource.h>
#include <time.h>

static u64 get_memory_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return usage.ru_maxrss * 1024;
    }
    return 0;
}

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
#endif

//=============================================================================
// Load/Unload Stress
//=============================================================================

rawrxd_stress_validation* rawrxd_validate_stress_load_unload(
    const char* model_path,
    u32 iterations
) {
    if (!model_path || iterations == 0) return NULL;
    
    rawrxd_stress_validation* val = rawrxd_alloc(sizeof(rawrxd_stress_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->initial_memory = get_memory_usage();
    
    printf("[STRESS] Load/Unload Test: %u iterations\n", iterations);
    printf("  Initial memory: %llu bytes\n", (unsigned long long)val->initial_memory);
    
    double start_time = get_time_sec();
    
    for (u32 i = 0; i < iterations; i++) {
        // Simulate model load
        rawrxd_model* model = NULL;
        rawrxd_result result = rawrxd_model_load(model_path, &model);
        
        if (result != RAWRXD_OK || !model) {
            val->load_errors++;
            val->iterations_failed++;
            printf("  [FAIL] Iteration %u: Load failed (%s)\n", 
                   i + 1, rawrxd_result_string(result));
            continue;
        }
        
        // Verify loaded
        if (!rawrxd_model_is_loaded(model)) {
            val->load_errors++;
            val->iterations_failed++;
            rawrxd_model_free(model);
            printf("  [FAIL] Iteration %u: Model not loaded\n", i + 1);
            continue;
        }
        
        // Simulate unload
        rawrxd_model_free(model);
        
        val->iterations_completed++;
        
        // Progress report every 100 iterations
        if ((i + 1) % 100 == 0) {
            u64 current_mem = get_memory_usage();
            printf("  Progress: %u/%u, Memory: %llu bytes\n", 
                   i + 1, iterations, (unsigned long long)current_mem);
        }
    }
    
    double end_time = get_time_sec();
    val->duration_sec = end_time - start_time;
    val->final_memory = get_memory_usage();
    val->memory_leak_bytes = (val->final_memory > val->initial_memory) ? 
                               (val->final_memory - val->initial_memory) : 0;
    val->stable = (val->load_errors == 0 && val->memory_leak_bytes < 1024 * 1024);
    
    printf("  Completed: %u/%u\n", val->iterations_completed, iterations);
    printf("  Failed: %u\n", val->iterations_failed);
    printf("  Load errors: %u\n", val->load_errors);
    printf("  Duration: %.2f sec\n", val->duration_sec);
    printf("  Memory leak: %llu bytes\n", (unsigned long long)val->memory_leak_bytes);
    printf("  Status: %s\n", val->stable ? "STABLE" : "UNSTABLE");
    
    return val;
}

//=============================================================================
// Inference Stress
//=============================================================================

rawrxd_stress_validation* rawrxd_validate_stress_inference(
    const char* model_path,
    u32 iterations
) {
    if (!model_path || iterations == 0) return NULL;
    
    rawrxd_stress_validation* val = rawrxd_alloc(sizeof(rawrxd_stress_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->initial_memory = get_memory_usage();
    
    printf("[STRESS] Inference Test: %u iterations\n", iterations);
    
    // Load model once
    rawrxd_model* model = NULL;
    rawrxd_result result = rawrxd_model_load(model_path, &model);
    if (result != RAWRXD_OK || !model) {
        strncpy(val->error_msg, "Failed to load model", sizeof(val->error_msg));
        val->load_errors++;
        return val;
    }
    
    printf("  Model loaded successfully\n");
    
    const char* test_prompts[] = {
        "Hello",
        "The quick brown fox",
        "1+1=",
        "What is the capital of France?",
        "Explain quantum computing:"
    };
    u32 num_prompts = sizeof(test_prompts) / sizeof(test_prompts[0]);
    
    double start_time = get_time_sec();
    
    for (u32 i = 0; i < iterations; i++) {
        const char* prompt = test_prompts[i % num_prompts];
        
        rawrxd_inference_params params = {
            .max_tokens = 10,
            .temperature = 0.7f,
            .top_p = 0.9f,
            .seed = i
        };
        
        rawrxd_inference_result* inf_result = NULL;
        result = rawrxd_inference_generate(model, prompt, &params, &inf_result);
        
        if (result != RAWRXD_OK || !inf_result) {
            val->inference_errors++;
            val->iterations_failed++;
            printf("  [FAIL] Iteration %u: Inference failed\n", i + 1);
            continue;
        }
        
        // Verify output
        if (!inf_result->text || strlen(inf_result->text) == 0) {
            val->inference_errors++;
            val->iterations_failed++;
            rawrxd_inference_result_free(inf_result);
            printf("  [FAIL] Iteration %u: Empty output\n", i + 1);
            continue;
        }
        
        rawrxd_inference_result_free(inf_result);
        val->iterations_completed++;
        
        // Progress report
        if ((i + 1) % 100 == 0) {
            printf("  Progress: %u/%u\n", i + 1, iterations);
        }
    }
    
    double end_time = get_time_sec();
    val->duration_sec = end_time - start_time;
    
    // Cleanup
    rawrxd_model_free(model);
    
    val->final_memory = get_memory_usage();
    val->memory_leak_bytes = (val->final_memory > val->initial_memory) ? 
                               (val->final_memory - val->initial_memory) : 0;
    val->stable = (val->inference_errors == 0 && val->memory_leak_bytes < 1024 * 1024);
    
    printf("  Completed: %u/%u\n", val->iterations_completed, iterations);
    printf("  Failed: %u\n", val->iterations_failed);
    printf("  Inference errors: %u\n", val->inference_errors);
    printf("  Duration: %.2f sec\n", val->duration_sec);
    printf("  Throughput: %.2f iter/sec\n", val->iterations_completed / val->duration_sec);
    printf("  Memory leak: %llu bytes\n", (unsigned long long)val->memory_leak_bytes);
    printf("  Status: %s\n", val->stable ? "STABLE" : "UNSTABLE");
    
    return val;
}

//=============================================================================
// Streaming Stress
//=============================================================================

rawrxd_stress_validation* rawrxd_validate_stress_streaming(
    const char* model_path,
    u32 iterations
) {
    if (!model_path || iterations == 0) return NULL;
    
    rawrxd_stress_validation* val = rawrxd_alloc(sizeof(rawrxd_stress_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->initial_memory = get_memory_usage();
    
    printf("[STRESS] Streaming Test: %u iterations\n", iterations);
    printf("  (Simulated - streaming API not yet implemented)\n");
    
    // For now, simulate streaming with regular loads
    double start_time = get_time_sec();
    
    for (u32 i = 0; i < iterations; i++) {
        // Simulate start streaming
        rawrxd_stream* stream = NULL;
        rawrxd_result result = rawrxd_stream_open(model_path, &stream);
        
        if (result != RAWRXD_OK) {
            val->stream_errors++;
            val->iterations_failed++;
            continue;
        }
        
        // Simulate cancel at random point (30% chance)
        if ((i % 10) < 3) {
            rawrxd_stream_cancel(stream);
        } else {
            // Let complete
            rawrxd_stream_wait(stream, 5000);
        }
        
        rawrxd_stream_close(stream);
        val->iterations_completed++;
    }
    
    double end_time = get_time_sec();
    val->duration_sec = end_time - start_time;
    val->final_memory = get_memory_usage();
    val->memory_leak_bytes = (val->final_memory > val->initial_memory) ? 
                               (val->final_memory - val->initial_memory) : 0;
    val->stable = (val->stream_errors == 0);
    
    printf("  Completed: %u/%u\n", val->iterations_completed, iterations);
    printf("  Stream errors: %u\n", val->stream_errors);
    printf("  Duration: %.2f sec\n", val->duration_sec);
    printf("  Status: %s\n", val->stable ? "STABLE" : "UNSTABLE");
    
    return val;
}

//=============================================================================
// Memory Pressure Stress
//=============================================================================

rawrxd_stress_validation* rawrxd_validate_stress_memory(
    const char* model_path,
    u32 duration_sec
) {
    if (!model_path || duration_sec == 0) return NULL;
    
    rawrxd_stress_validation* val = rawrxd_alloc(sizeof(rawrxd_stress_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->initial_memory = get_memory_usage();
    
    printf("[STRESS] Memory Pressure Test: %u seconds\n", duration_sec);
    
    // Allocate memory pressure (50% of available)
    size_t pressure_size = 1024 * 1024 * 1024;  // 1GB placeholder
    void* pressure = rawrxd_alloc(pressure_size);
    if (pressure) {
        memset(pressure, 0xAB, pressure_size);
        printf("  Allocated %zu bytes for pressure\n", pressure_size);
    }
    
    double start_time = get_time_sec();
    u32 iterations = 0;
    
    while ((u32)(get_time_sec() - start_time) < duration_sec) {
        // Try to load model under pressure
        rawrxd_model* model = NULL;
        rawrxd_result result = rawrxd_model_load(model_path, &model);
        
        if (result == RAWRXD_OK && model) {
            // Quick inference
            rawrxd_inference_params params = {
                .max_tokens = 5,
                .temperature = 0.7f
            };
            
            rawrxd_inference_result* inf_result = NULL;
            rawrxd_inference_generate(model, "Test", &params, &inf_result);
            
            if (inf_result) {
                rawrxd_inference_result_free(inf_result);
            }
            
            rawrxd_model_free(model);
            val->iterations_completed++;
        } else {
            val->load_errors++;
            val->iterations_failed++;
        }
        
        iterations++;
        
        // Progress every 10 seconds
        if (iterations % 10 == 0) {
            u64 current_mem = get_memory_usage();
            printf("  Progress: %u sec, Memory: %llu bytes\n",
                   (u32)(get_time_sec() - start_time),
                   (unsigned long long)current_mem);
        }
    }
    
    // Cleanup pressure
    if (pressure) {
        rawrxd_free(pressure, pressure_size);
    }
    
    val->duration_sec = get_time_sec() - start_time;
    val->final_memory = get_memory_usage();
    val->memory_leak_bytes = (val->final_memory > val->initial_memory) ? 
                               (val->final_memory - val->initial_memory) : 0;
    val->stable = (val->load_errors < iterations / 10);  // Allow some failures under pressure
    
    printf("  Completed: %u iterations\n", val->iterations_completed);
    printf("  Failed: %u\n", val->iterations_failed);
    printf("  Load errors: %u\n", val->load_errors);
    printf("  Duration: %.2f sec\n", val->duration_sec);
    printf("  Memory leak: %llu bytes\n", (unsigned long long)val->memory_leak_bytes);
    printf("  Status: %s\n", val->stable ? "STABLE" : "UNSTABLE");
    
    return val;
}
