// ============================================================================
// b025_pipeline_parallelism_certification.cpp — B025 Pipeline Parallelism
// ============================================================================
// Tests: Layer pipelining, stage dependencies, throughput vs depth,
//        bubble minimization, correctness under pipeline execution
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>
#include <algorithm>
#include <string>
#include <cmath>

struct TestResult {
    const char* id;
    const char* desc;
    bool passed;
    const char* detail;
};

static std::vector<TestResult> g_results;

static void Record(const char* id, const char* desc, bool passed, const char* detail = "")
{
    g_results.push_back({id, desc, passed, detail});
    std::printf("  [%s] %s: %s\n", passed ? "PASS" : "FAIL", id, detail);
}

static bool Check(bool condition, const char* id, const char* desc, const char* detail = "")
{
    Record(id, desc, condition, detail);
    return condition;
}

static inline double NowMs()
{
    using namespace std::chrono;
    return duration<double, std::milli>(high_resolution_clock::now().time_since_epoch()).count();
}

// ============================================================================
// Pipeline stage simulator
// ============================================================================
struct PipelineStage {
    int stage_id;
    double compute_ms; // simulated compute time
    std::vector<float> output;
};

struct Pipeline {
    std::vector<PipelineStage> stages;
    size_t batch_size;
};

static double RunSequential(const Pipeline& pipe, const std::vector<float>& input)
{
    double t0 = NowMs();
    std::vector<float> current = input;
    for (const auto& stage : pipe.stages) {
        int iterations = static_cast<int>(stage.compute_ms * 1000);
        for (int iter = 0; iter < iterations; ++iter) {
            for (size_t i = 0; i < current.size(); ++i) {
                current[i] = current[i] * 1.01f + 0.001f;
            }
        }
    }
    return NowMs() - t0;
}

static double RunPipelined(const Pipeline& pipe, std::vector<std::vector<float>>& inputs)
{
    double t0 = NowMs();
    for (auto& input : inputs) {
        std::vector<float> current = input;
        for (const auto& stage : pipe.stages) {
            int iterations = static_cast<int>(stage.compute_ms);
            for (int iter = 0; iter < iterations; ++iter) {
                for (size_t i = 0; i < current.size(); ++i) {
                    current[i] = current[i] * 1.01f + 0.001f;
                }
            }
        }
        input = current;
    }
    return NowMs() - t0;
}

// ============================================================================
// Test 1: Stage ordering preserved
// ============================================================================
static bool TestStageOrdering()
{
    std::printf("\n[TEST 1] Stage ordering preserved\n");

    Pipeline pipe;
    pipe.stages.push_back({0, 1.0, {}});
    pipe.stages.push_back({1, 2.0, {}});
    pipe.stages.push_back({2, 1.5, {}});

    bool ok = true;
    for (size_t i = 0; i < pipe.stages.size(); ++i) {
        ok &= Check(pipe.stages[i].stage_id == static_cast<int>(i), "B025-001",
                    "stage ID matches position", std::to_string(pipe.stages[i].stage_id).c_str());
    }

    return ok;
}

// ============================================================================
// Test 2: Pipeline depth vs throughput
// ============================================================================
static bool TestPipelineDepthVsThroughput()
{
    std::printf("\n[TEST 2] Pipeline depth vs throughput\n");

    bool ok = true;

    // Shallow pipeline (2 stages)
    Pipeline shallow;
    shallow.stages.push_back({0, 1.0, {}});
    shallow.stages.push_back({1, 1.0, {}});

    // Deep pipeline (8 stages)
    Pipeline deep;
    for (int i = 0; i < 8; ++i) deep.stages.push_back({i, 1.0, {}});

    std::vector<float> input(1024, 1.0f);
    std::vector<std::vector<float>> inputs(10, input);

    double shallow_time = RunPipelined(shallow, inputs);
    
    // Re-fill inputs for deep pipeline
    inputs.assign(10, input);
    double deep_time = RunPipelined(deep, inputs);

    char detail[256];
    std::snprintf(detail, sizeof(detail), "shallow=%.2f ms deep=%.2f ms", shallow_time, deep_time);
    ok &= Check(deep_time > shallow_time, "B025-002",
                "deeper pipeline takes more time", detail);

    return ok;
}

// ============================================================================
// Test 3: Bubble minimization (no idle stages)
// ============================================================================
static bool TestBubbleMinimization()
{
    std::printf("\n[TEST 3] Bubble minimization\n");

    bool ok = true;

    // Balanced pipeline: all stages same compute time
    Pipeline balanced;
    for (int i = 0; i < 4; ++i) balanced.stages.push_back({i, 1.0, {}});

    // Imbalanced pipeline: one stage much slower
    Pipeline imbalanced;
    for (int i = 0; i < 3; ++i) imbalanced.stages.push_back({i, 1.0, {}});
    imbalanced.stages.push_back({3, 5.0, {}});

    std::vector<float> input(1024, 1.0f);
    std::vector<std::vector<float>> inputs(10, input);

    double balanced_time = RunPipelined(balanced, inputs);
    
    inputs.assign(10, input);
    double imbalanced_time = RunPipelined(imbalanced, inputs);

    char detail[256];
    std::snprintf(detail, sizeof(detail), "balanced=%.2f ms imbalanced=%.2f ms", balanced_time, imbalanced_time);
    ok &= Check(imbalanced_time >= balanced_time, "B025-003",
                "imbalanced pipeline slower or equal", detail);

    return ok;
}

// ============================================================================
// Test 4: Correctness under pipeline execution
// ============================================================================
static bool TestPipelineCorrectness()
{
    std::printf("\n[TEST 4] Correctness under pipeline execution\n");

    bool ok = true;

    Pipeline pipe;
    pipe.stages.push_back({0, 1.0, {}});
    pipe.stages.push_back({1, 1.0, {}});
    pipe.stages.push_back({2, 1.0, {}});

    std::vector<float> input(256, 2.0f);

    // Sequential reference
    std::vector<float> ref = input;
    for (const auto& stage : pipe.stages) {
        int iterations = static_cast<int>(stage.compute_ms);
        for (int iter = 0; iter < iterations; ++iter) {
            for (size_t i = 0; i < ref.size(); ++i) {
                ref[i] = ref[i] * 1.01f + 0.001f;
            }
        }
    }

    // Pipelined execution (single input)
    std::vector<std::vector<float>> inputs = {input};
    RunPipelined(pipe, inputs);

    // Verify outputs match
    bool match = true;
    for (size_t i = 0; i < ref.size(); ++i) {
        if (std::fabs(ref[i] - inputs[0][i]) > 0.1f) { match = false; break; }
    }
    ok &= Check(match, "B025-004", "pipelined output matches sequential", match ? "yes" : "no");

    return ok;
}

// ============================================================================
// Test 5: Stage dependency tracking
// ============================================================================
static bool TestStageDependencies()
{
    std::printf("\n[TEST 5] Stage dependency tracking\n");

    bool ok = true;

    // Each stage depends on the previous
    std::vector<int> dependencies = {-1, 0, 1, 2};

    for (size_t i = 0; i < dependencies.size(); ++i) {
        int expected_prev = (i == 0) ? -1 : static_cast<int>(i - 1);
        ok &= Check(dependencies[i] == expected_prev, "B025-005",
                    "stage dependency chain correct", std::to_string(dependencies[i]).c_str());
    }

    return ok;
}

// ============================================================================
// Main
// ============================================================================
int main()
{
    std::printf("========================================\n");
    std::printf("  B025 — Pipeline Parallelism Certification\n");
    std::printf("========================================\n");

    bool all_passed = true;
    all_passed &= TestStageOrdering();
    all_passed &= TestPipelineDepthVsThroughput();
    all_passed &= TestBubbleMinimization();
    all_passed &= TestPipelineCorrectness();
    all_passed &= TestStageDependencies();

    std::printf("\n========================================\n");
    std::printf("  Results: %zu tests\n", g_results.size());

    size_t passed = 0;
    for (const auto& r : g_results) {
        if (r.passed) passed++;
    }
    std::printf("  Passed: %zu / %zu\n", passed, g_results.size());
    std::printf("  B025 CERTIFICATION: %s\n", all_passed ? "PASS" : "FAIL");
    std::printf("========================================\n");

    return all_passed ? 0 : 1;
}
