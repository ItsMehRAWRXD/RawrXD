// moe_timing.cpp — MoE timing state + C accessors (benchmark package 6).
// Standalone (no ggml/Vulkan deps) so the benchmark links the production engine
// without pulling the graph executor. The RAII guards in
// runtime_graph_executor.cpp reference these via extern.
#include <cstdio>

// Global-namespace copies for the extern "C" benchmark accessors. The namespaced
// RawrXD::Deep2::RuntimeGraph copies (used by runtime_graph_executor.cpp) live in
// moe_timing_graph.cpp; keep these global so the two TUs never double-define.
double g_moe_router_ms = 0.0;
double g_moe_expert_ms = 0.0;
unsigned long g_moe_router_calls = 0;
unsigned long g_moe_expert_calls = 0;

extern "C" double Deep2Bench_MoeRouterMs(void)           { return g_moe_router_ms; }
extern "C" double Deep2Bench_MoeExpertMs(void)           { return g_moe_expert_ms; }
extern "C" unsigned long Deep2Bench_MoeRouterCalls(void) { return g_moe_router_calls; }
extern "C" unsigned long Deep2Bench_MoeExpertCalls(void) { return g_moe_expert_calls; }