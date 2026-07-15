// ============================================================================
// RawrXD Mock Inference Stress Test
// Stress-tests the Epoch-RCU router by creating reader contention scenarios
// ============================================================================
// This test creates:
// - 4-8 worker threads simulating token generation
// - Random jitter after acquiring model pointer (maximizes race window)
// - Canary values to detect use-after-free
// - Aggressive hotpatching while readers are active
// ============================================================================

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

// External router functions
extern "C" {
    uint64_t RawrXD_RequestHotpatch(void* modelDescriptor, uint64_t gpuFence);
    uint64_t RawrXD_CheckEpochSwap();
    uint64_t RawrXD_WaitForHotpatchComplete(uint32_t timeoutMs);
    uint64_t RawrXD_InitHotpatchSystem();
    
    // Status query functions
    extern uint64_t g_EpochCounter;
    extern uint64_t g_ActiveModelDescriptor;
    extern uint64_t g_PendingModelDescriptor;
}

// Test configuration
#define NUM_WORKER_THREADS      8
#define ITERATIONS_PER_THREAD   1000
#define JITTER_MIN_MS           1
#define JITTER_MAX_MS           50
#define CANARY_MAGIC            0xDEADBEEFCAFEBABEULL

// Model descriptor with canary for use-after-free detection
struct TestModelDescriptor {
    uint64_t canary;            // Magic value to detect corruption
    uint64_t modelId;           // Unique ID for this model
    uint64_t generationCount;   // Incremented by readers
    uint64_t lastReaderId;      // ID of last reader thread
    uint64_t checksum;          // Simple checksum of data
    uint8_t  data[1024];        // Simulated tensor data
};

// Thread context
struct WorkerContext {
    int threadId;
    uint64_t iterationsCompleted;
    uint64_t canaryFailures;
    uint64_t nullModelCount;
    uint64_t epochRotationsSeen;
    uint64_t lastEpoch;
    bool     running;
};

static WorkerContext g_Workers[NUM_WORKER_THREADS];
static volatile LONG g_TotalHotpatches = 0;
static volatile LONG g_ActiveReaders = 0;
static volatile LONG g_MaxConcurrentReaders = 0;

// Get current time in microseconds
static uint64_t GetTimeUs() {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000ULL) / freq.QuadPart;
}

// Induce jitter to maximize race window
static void InduceJitter() {
    // Random sleep between JITTER_MIN_MS and JITTER_MAX_MS
    int jitterMs = JITTER_MIN_MS + (rand() % (JITTER_MAX_MS - JITTER_MIN_MS + 1));
    
    // 50% chance to Sleep, 50% chance to SwitchToThread (yield)
    if (rand() % 2 == 0) {
        Sleep(jitterMs);
    } else {
        // Yield multiple times to force context switch
        for (int i = 0; i < 10 + (rand() % 20); i++) {
            SwitchToThread();
        }
    }
}

// Calculate simple checksum
static uint64_t CalculateChecksum(const TestModelDescriptor* desc) {
    uint64_t sum = desc->canary + desc->modelId;
    // Only hash the first 64 bytes of data for performance
    for (int i = 0; i < 64; i++) {
        sum += desc->data[i];
    }
    return sum;
}

// Initialize model data with deterministic pattern
static void InitializeModelData(TestModelDescriptor* desc) {
    // Fill data with deterministic pattern based on modelId
    for (int i = 0; i < 1024; i++) {
        desc->data[i] = (uint8_t)((desc->modelId * 7 + i * 3) % 256);
    }
}

// Worker thread - simulates token generation
static DWORD WINAPI WorkerThread(LPVOID param) {
    WorkerContext* ctx = (WorkerContext*)param;
    ctx->running = true;
    
    printf("[Worker %d] Started\n", ctx->threadId);
    
    for (int iter = 0; iter < ITERATIONS_PER_THREAD && ctx->running; iter++) {
        // Get current epoch
        uint64_t currentEpoch = g_EpochCounter;
        if (currentEpoch != ctx->lastEpoch) {
            ctx->epochRotationsSeen++;
            ctx->lastEpoch = currentEpoch;
        }
        
        // Get active model (this is the critical RCU read)
        TestModelDescriptor* model = (TestModelDescriptor*)g_ActiveModelDescriptor;
        
        if (!model) {
            ctx->nullModelCount++;
            // No model active yet, just wait
            Sleep(10);
            continue;
        }
        
        // Track concurrent readers
        LONG currentReaders = InterlockedIncrement(&g_ActiveReaders);
        LONG maxReaders = g_MaxConcurrentReaders;
        if (currentReaders > maxReaders) {
            InterlockedCompareExchange(&g_MaxConcurrentReaders, currentReaders, maxReaders);
        }
        
        // CRITICAL: Induce jitter while holding the model reference
        // This maximizes the race window for stale reader detection
        InduceJitter();
        
        // Validate canary - detects use-after-free
        if (model->canary != CANARY_MAGIC) {
            ctx->canaryFailures++;
            printf("[Worker %d] CANARY FAILURE! Expected 0x%016llX, got 0x%016llX\n",
                   ctx->threadId, CANARY_MAGIC, model->canary);
            InterlockedDecrement(&g_ActiveReaders);
            break;
        }
        
        // Validate checksum - detects memory corruption
        uint64_t expectedChecksum = CalculateChecksum(model);
        if (model->checksum != expectedChecksum) {
            ctx->canaryFailures++;
            printf("[Worker %d] CHECKSUM FAILURE! Model %llu corrupted\n",
                   ctx->threadId, model->modelId);
            InterlockedDecrement(&g_ActiveReaders);
            break;
        }
        
        // Simulate token generation work
        model->generationCount++;
        model->lastReaderId = ctx->threadId;
        
        // Release reader reference
        InterlockedDecrement(&g_ActiveReaders);
        
        ctx->iterationsCompleted++;
        
        // Small delay between iterations
        if (iter % 10 == 0) {
            Sleep(1);
        }
    }
    
    ctx->running = false;
    printf("[Worker %d] Completed %llu iterations, %llu canary failures\n",
           ctx->threadId, ctx->iterationsCompleted, ctx->canaryFailures);
    return 0;
}

// Hotpatch thread - aggressively rotates models
static DWORD WINAPI HotpatchThread(LPVOID param) {
    printf("[Hotpatch] Thread started\n");
    
    // Create pool of test models
    const int NUM_MODELS = 5;
    TestModelDescriptor* models[NUM_WORKER_THREADS];
    
    for (int i = 0; i < NUM_MODELS; i++) {
        models[i] = (TestModelDescriptor*)HeapAlloc(GetProcessHeap(), 
                                                      HEAP_ZERO_MEMORY, 
                                                      sizeof(TestModelDescriptor));
        models[i]->canary = CANARY_MAGIC;
        models[i]->modelId = i + 1;
        models[i]->generationCount = 0;
        InitializeModelData(models[i]);  // Fill with deterministic pattern
        models[i]->checksum = CalculateChecksum(models[i]);
        printf("[Hotpatch] Created model %d at %p (checksum: %llu)\n", i + 1, models[i], models[i]->checksum);
    }
    
    int hotpatchCount = 0;
    int modelIndex = 0;
    
    while (hotpatchCount < 100) {
        // Wait for some readers to be active
        Sleep(50);
        
        // Select next model
        TestModelDescriptor* newModel = models[modelIndex];
        modelIndex = (modelIndex + 1) % NUM_MODELS;
        
        // Update checksum before hotpatch
        newModel->checksum = CalculateChecksum(newModel);
        
        // Request hotpatch
        uint64_t result = RawrXD_RequestHotpatch(newModel, 0);
        
        if (result == 0) {
            // Complete the swap
            RawrXD_CheckEpochSwap();
            
            hotpatchCount++;
            InterlockedIncrement(&g_TotalHotpatches);
            
            printf("[Hotpatch] #%d: Model %llu activated (epoch: %llu, readers: %d)\n",
                   hotpatchCount, newModel->modelId, g_EpochCounter, g_ActiveReaders);
        } else if (result == 1) {
            // Already pending, wait and retry
            RawrXD_WaitForHotpatchComplete(100);
        } else {
            printf("[Hotpatch] Failed with code %llu\n", result);
        }
        
        // Random delay between hotpatches
        Sleep(10 + (rand() % 100));
    }
    
    printf("[Hotpatch] Completed %d hotpatches\n", hotpatchCount);
    
    // Cleanup models
    for (int i = 0; i < NUM_MODELS; i++) {
        HeapFree(GetProcessHeap(), 0, models[i]);
    }
    
    return 0;
}

int main() {
    printf("========================================\n");
    printf("RawrXD Mock Inference Stress Test\n");
    printf("========================================\n");
    printf("Workers: %d threads x %d iterations\n", NUM_WORKER_THREADS, ITERATIONS_PER_THREAD);
    printf("Jitter: %d-%dms + context switches\n", JITTER_MIN_MS, JITTER_MAX_MS);
    printf("Canary: 0x%016llX\n", CANARY_MAGIC);
    printf("========================================\n\n");
    
    // Seed RNG
    srand((unsigned)time(NULL));
    
    // Initialize router
    RawrXD_InitHotpatchSystem();
    printf("[Main] Router initialized\n");
    
    // Create worker threads
    HANDLE workerHandles[NUM_WORKER_THREADS];
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        memset(&g_Workers[i], 0, sizeof(WorkerContext));
        g_Workers[i].threadId = i;
        g_Workers[i].lastEpoch = g_EpochCounter;
        
        workerHandles[i] = CreateThread(NULL, 0, WorkerThread, &g_Workers[i], 0, NULL);
    }
    
    // Create hotpatch thread
    HANDLE hotpatchHandle = CreateThread(NULL, 0, HotpatchThread, NULL, 0, NULL);
    
    printf("[Main] All threads started\n\n");
    
    // Wait for completion
    WaitForSingleObject(hotpatchHandle, INFINITE);
    
    // Signal workers to stop
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        g_Workers[i].running = false;
    }
    
    // Wait for workers
    WaitForMultipleObjects(NUM_WORKER_THREADS, workerHandles, TRUE, 5000);
    
    // Cleanup handles
    CloseHandle(hotpatchHandle);
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        CloseHandle(workerHandles[i]);
    }
    
    // Print results
    printf("\n========================================\n");
    printf("Results\n");
    printf("========================================\n");
    
    uint64_t totalIterations = 0;
    uint64_t totalCanaryFailures = 0;
    uint64_t totalNullModels = 0;
    
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        printf("Worker %d: %llu iterations, %llu canary failures, %llu null models, %llu epoch rotations\n",
               i, g_Workers[i].iterationsCompleted, g_Workers[i].canaryFailures,
               g_Workers[i].nullModelCount, g_Workers[i].epochRotationsSeen);
        totalIterations += g_Workers[i].iterationsCompleted;
        totalCanaryFailures += g_Workers[i].canaryFailures;
        totalNullModels += g_Workers[i].nullModelCount;
    }
    
    printf("\n");
    printf("Total iterations:     %llu\n", totalIterations);
    printf("Total hotpatches:       %d\n", g_TotalHotpatches);
    printf("Max concurrent readers: %d\n", g_MaxConcurrentReaders);
    printf("Final epoch:            %llu\n", g_EpochCounter);
    printf("Canary failures:        %llu\n", totalCanaryFailures);
    printf("Null model accesses:    %llu\n", totalNullModels);
    
    if (totalCanaryFailures == 0) {
        printf("\n✓ STRESS TEST PASSED - No use-after-free detected\n");
        return 0;
    } else {
        printf("\n✗ STRESS TEST FAILED - %llu canary failures detected\n", totalCanaryFailures);
        return 1;
    }
}
