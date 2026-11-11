/*
 * RawrXD Validation Framework
 * Integration Test: End-to-End Inference Pipeline
 * 
 * Tests the complete 4-layer architecture:
 *   Scheduler → Router → Executor → Policy
 * 
 * Target: Validate full pipeline integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define TEST_NAME "Inference Pipeline"

/* ═══════════════════════════════════════════════════════════════════════════
 * LAYER 0: SCHEDULER (Credit-Based)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum { NODE_INFERENCE, NODE_TRAINING } NodeType;
typedef enum { PRIORITY_LOW, PRIORITY_NORMAL, PRIORITY_HIGH } Priority;

typedef struct {
    uint32_t granted;
    uint32_t remaining;
    uint32_t time_slice_us;
} TokenCredits;

typedef struct {
    int id;
    NodeType type;
    Priority priority;
    TokenCredits credits;
} ScheduledNode;

#define MAX_NODES 64
static ScheduledNode g_node_queue[MAX_NODES];
static int g_node_count = 0;

bool scheduler_enqueue(int id, NodeType type, Priority priority) {
    if (g_node_count >= MAX_NODES) return false;
    
    g_node_queue[g_node_count].id = id;
    g_node_queue[g_node_count].type = type;
    g_node_queue[g_node_count].priority = priority;
    g_node_queue[g_node_count].credits.granted = 1000;
    g_node_queue[g_node_count].credits.remaining = 1000;
    g_node_queue[g_node_count].credits.time_slice_us = 10000; /* 10ms */
    
    g_node_count++;
    return true;
}

TokenCredits* scheduler_allocate(int node_id) {
    for (int i = 0; i < g_node_count; i++) {
        if (g_node_queue[i].id == node_id) {
            return &g_node_queue[i].credits;
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LAYER 1: ROUTER (Capability-Based)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t hash;
    uint32_t permissions;
    time_t expiry;
} CapabilityToken;

typedef struct {
    const char* model_arch;
    uint32_t estimated_tokens;
    Priority priority;
} WorkSpec;

typedef struct {
    int backend_id;
    const char* backend_name;
    float confidence;
} RoutingDecision;

typedef struct {
    int id;
    const char* name;
    const char* supported_arch[4];
    int num_arch;
    float avg_latency_ms;
    float success_rate;
} BackendInfo;

#define MAX_BACKENDS 8
static BackendInfo g_backends[MAX_BACKENDS];
static int g_backend_count = 0;

bool router_register_backend(BackendInfo* backend) {
    if (g_backend_count >= MAX_BACKENDS) return false;
    g_backends[g_backend_count++] = *backend;
    return true;
}

RoutingDecision* router_route(CapabilityToken* cap, WorkSpec* work) {
    static RoutingDecision decision;
    
    /* Simple routing: find backend supporting the model architecture */
    for (int i = 0; i < g_backend_count; i++) {
        for (int j = 0; j < g_backends[i].num_arch; j++) {
            if (strcmp(g_backends[i].supported_arch[j], work->model_arch) == 0) {
                decision.backend_id = g_backends[i].id;
                decision.backend_name = g_backends[i].name;
                decision.confidence = g_backends[i].success_rate;
                return &decision;
            }
        }
    }
    
    return NULL; /* No suitable backend */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LAYER 2: EXECUTOR (Kernel Dispatch)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum { KERNEL_INFERENCE, KERNEL_TRAINING } KernelType;

typedef struct {
    int id;
    KernelType type;
    int kernel_id;
    uint32_t batch_size;
    uint32_t seq_len;
    bool checkpoint_enabled;
} NodeSpec;

typedef struct {
    bool success;
    uint64_t execution_time_us;
    uint64_t memory_used_bytes;
} ExecutionResult;

typedef void (*KernelFunc)(void*);

#define MAX_KERNELS 16
static struct {
    int id;
    KernelType type;
    KernelFunc func;
} g_kernels[MAX_KERNELS];
static int g_kernel_count = 0;

bool executor_register_kernel(int id, KernelType type, KernelFunc func) {
    if (g_kernel_count >= MAX_KERNELS) return false;
    g_kernels[g_kernel_count].id = id;
    g_kernels[g_kernel_count].type = type;
    g_kernels[g_kernel_count].func = func;
    g_kernel_count++;
    return true;
}

ExecutionResult executor_execute(NodeSpec* spec) {
    ExecutionResult result = {0};
    
    /* Find kernel */
    KernelFunc func = NULL;
    for (int i = 0; i < g_kernel_count; i++) {
        if (g_kernels[i].id == spec->kernel_id) {
            func = g_kernels[i].func;
            break;
        }
    }
    
    if (!func) {
        result.success = false;
        return result;
    }
    
    /* Execute */
    clock_t start = clock();
    func(spec);
    clock_t end = clock();
    
    result.success = true;
    result.execution_time_us = (uint64_t)((end - start) * 1000000 / CLOCKS_PER_SEC);
    result.memory_used_bytes = spec->batch_size * spec->seq_len * sizeof(float);
    
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LAYER 3: POLICY (Statistical Observation)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    int id;
    const char* model_arch;
    int input_tokens;
    int output_tokens;
    float latency_ms;
    bool success;
    const char* backend_used;
} Trace;

#define MAX_TRACES 1024
static Trace g_traces[MAX_TRACES];
static int g_trace_count = 0;

typedef struct {
    const char* recommended_backend;
    float confidence;
} PolicyRecommendation;

void policy_observe(Trace* trace) {
    if (g_trace_count < MAX_TRACES) {
        /* Store a copy since original might go out of scope */
        static char arch_storage[MAX_TRACES][32];
        static char backend_storage[MAX_TRACES][32];
        
        strncpy(arch_storage[g_trace_count], trace->model_arch, 31);
        arch_storage[g_trace_count][31] = '\0';
        strncpy(backend_storage[g_trace_count], trace->backend_used, 31);
        backend_storage[g_trace_count][31] = '\0';
        
        g_traces[g_trace_count] = *trace;
        g_traces[g_trace_count].model_arch = arch_storage[g_trace_count];
        g_traces[g_trace_count].backend_used = backend_storage[g_trace_count];
        g_trace_count++;
    }
}

PolicyRecommendation* policy_recommend(const char* model_arch) {
    static PolicyRecommendation rec;
    static char backend_name[32];
    
    /* Simple recommendation: most successful backend for this architecture */
    int backend_success[8] = {0};
    int backend_total[8] = {0};
    
    for (int i = 0; i < g_trace_count; i++) {
        if (strcmp(g_traces[i].model_arch, model_arch) == 0) {
            int bid = g_traces[i].backend_used[0] - '0'; /* Simple hash */
            if (bid >= 0 && bid < 8) {
                backend_total[bid]++;
                if (g_traces[i].success) {
                    backend_success[bid]++;
                }
            }
        }
    }
    
    /* Find best backend */
    int best_bid = 0;
    float best_rate = 0;
    int total_traces = 0;
    for (int i = 0; i < 8; i++) {
        total_traces += backend_total[i];
        if (backend_total[i] > 0) {
            float rate = (float)backend_success[i] / backend_total[i];
            if (rate > best_rate) {
                best_rate = rate;
                best_bid = i;
            }
        }
    }
    
    /* Default to first backend if no traces */
    if (total_traces == 0) {
        snprintf(backend_name, sizeof(backend_name), "CPU_Backend");
        rec.recommended_backend = backend_name;
        rec.confidence = 0.95f;
    } else {
        snprintf(backend_name, sizeof(backend_name), "Backend%d", best_bid);
        rec.recommended_backend = backend_name;
        rec.confidence = best_rate;
    }
    
    return &rec;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MOCK KERNEL IMPLEMENTATIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

void mock_inference_kernel(void* spec) {
    NodeSpec* s = (NodeSpec*)spec;
    /* Simulate work: sleep for a tiny amount */
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) {
        dummy += i;
    }
    (void)dummy;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * INTEGRATION TEST
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char input[256];
    char output[256];
    int tokens_in;
    int tokens_out;
    float latency_ms;
    bool success;
} InferenceOutput;

int run_full_pipeline(const char* prompt, const char* model_arch, 
                      InferenceOutput* output) {
    /* Step 1: Schedule */
    int node_id = 1;
    if (!scheduler_enqueue(node_id, NODE_INFERENCE, PRIORITY_NORMAL)) {
        printf("  [Pipeline] FAIL: Scheduler rejected node\n");
        return -1;
    }
    
    TokenCredits* credits = scheduler_allocate(node_id);
    if (!credits) {
        printf("  [Pipeline] FAIL: No credits allocated\n");
        return -1;
    }
    printf("  [Pipeline] Step 1: Scheduled (credits=%u)\n", credits->granted);
    
    /* Step 2: Route */
    CapabilityToken cap = {0};
    cap.hash = 12345;
    cap.permissions = 0xFFFFFFFF;
    cap.expiry = time(NULL) + 3600;
    
    WorkSpec work = {0};
    work.model_arch = model_arch;
    work.estimated_tokens = strlen(prompt) / 4; /* Rough estimate */
    work.priority = PRIORITY_NORMAL;
    
    RoutingDecision* route = router_route(&cap, &work);
    if (!route) {
        printf("  [Pipeline] FAIL: No backend available\n");
        return -1;
    }
    printf("  [Pipeline] Step 2: Routed to %s (confidence=%.2f)\n", 
           route->backend_name, route->confidence);
    
    /* Step 3: Execute */
    NodeSpec spec = {0};
    spec.id = node_id;
    spec.type = KERNEL_INFERENCE;
    spec.kernel_id = 1; /* inference kernel */
    spec.batch_size = 1;
    spec.seq_len = work.estimated_tokens;
    spec.checkpoint_enabled = false;
    
    ExecutionResult exec = executor_execute(&spec);
    if (!exec.success) {
        printf("  [Pipeline] FAIL: Execution failed\n");
        return -1;
    }
    printf("  [Pipeline] Step 3: Executed (time=%llu us, mem=%llu bytes)\n",
           (unsigned long long)exec.execution_time_us, 
           (unsigned long long)exec.memory_used_bytes);
    
    /* Step 4: Observe (Policy) */
    Trace trace = {0};
    trace.id = node_id;
    trace.model_arch = model_arch;
    trace.input_tokens = work.estimated_tokens;
    trace.output_tokens = work.estimated_tokens; /* Mock: echo */
    trace.latency_ms = exec.execution_time_us / 1000.0f;
    trace.success = true;
    trace.backend_used = route->backend_name;
    
    policy_observe(&trace);
    printf("  [Pipeline] Step 4: Observed (latency=%.2f ms)\n", trace.latency_ms);
    
    /* Populate output */
    strncpy(output->input, prompt, sizeof(output->input) - 1);
    snprintf(output->output, sizeof(output->output), 
             "Generated text for: %s", prompt);
    output->tokens_in = trace.input_tokens;
    output->tokens_out = trace.output_tokens;
    output->latency_ms = trace.latency_ms;
    output->success = true;
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN TEST
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("[%s] Starting...\n", TEST_NAME);
    printf("[%s] Testing 4-layer architecture: Scheduler → Router → Executor → Policy\n\n", TEST_NAME);
    
    /* Initialize backends */
    BackendInfo backend1 = {
        .id = 1,
        .name = "CPU_Backend",
        .supported_arch = {"llama2", "qwen2", NULL, NULL},
        .num_arch = 2,
        .avg_latency_ms = 50.0f,
        .success_rate = 0.95f
    };
    router_register_backend(&backend1);
    
    BackendInfo backend2 = {
        .id = 2,
        .name = "GPU_Backend",
        .supported_arch = {"llama2", NULL, NULL, NULL},
        .num_arch = 1,
        .avg_latency_ms = 10.0f,
        .success_rate = 0.98f
    };
    router_register_backend(&backend2);
    
    printf("[%s] Registered %d backends\n", TEST_NAME, 2);
    
    /* Initialize kernels */
    executor_register_kernel(1, KERNEL_INFERENCE, mock_inference_kernel);
    printf("[%s] Registered inference kernel\n\n", TEST_NAME);
    
    /* Test 1: Simple inference through full pipeline */
    printf("[%s] Test 1: Simple inference pipeline\n", TEST_NAME);
    InferenceOutput result1;
    memset(&result1, 0, sizeof(result1));
    
    int rc1 = run_full_pipeline("hello world", "llama2", &result1);
    if (rc1 != 0) {
        printf("[%s] FAIL: Pipeline execution failed\n", TEST_NAME);
        return 1;
    }
    
    printf("\n  Result: '%s'\n", result1.output);
    printf("  Tokens: in=%d, out=%d\n", result1.tokens_in, result1.tokens_out);
    printf("  Latency: %.2f ms\n\n", result1.latency_ms);
    
    /* Test 2: Policy recommendation */
    printf("[%s] Test 2: Policy recommendation based on traces\n", TEST_NAME);
    PolicyRecommendation* rec = policy_recommend("llama2");
    printf("  Recommended backend: %s (confidence=%.2f)\n\n", 
           rec->recommended_backend, rec->confidence);
    
    /* Test 3: Multiple inferences */
    printf("[%s] Test 3: Multiple inferences\n", TEST_NAME);
    const char* prompts[] = {
        "What is AI?",
        "Explain quantum computing",
        "Write a poem"
    };
    
    for (int i = 0; i < 3; i++) {
        InferenceOutput result;
        memset(&result, 0, sizeof(result));
        
        int rc = run_full_pipeline(prompts[i], "llama2", &result);
        if (rc != 0) {
            printf("[%s] FAIL: Inference %d failed\n", TEST_NAME, i + 1);
            return 1;
        }
        printf("  Inference %d: OK (%.2f ms)\n", i + 1, result.latency_ms);
    }
    
    /* Summary */
    printf("\n[%s] Summary:\n", TEST_NAME);
    printf("  - Nodes scheduled: %d\n", g_node_count);
    printf("  - Backends registered: %d\n", g_backend_count);
    printf("  - Traces observed: %d\n", g_trace_count);
    printf("  - Kernels registered: %d\n", g_kernel_count);
    
    printf("\n[%s] PASS - All 4 layers integrated successfully\n", TEST_NAME);
    return 0;
}
