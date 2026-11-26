// moe_timing.cpp — MoE timing state + C accessors (benchmark package 6).
// Standalone (no ggml/Vulkan deps) so the benchmark links the production engine
// without pulling the graph executor. The RAII guards in
// runtime_graph_executor.cpp reference these via extern.
#include <cstdio>

// These globals are declared `extern` inside namespace
// RawrXD::Deep2::RuntimeGraph in runtime_graph_executor.cpp, so they MUST be
// defined in that same namespace or the link fails with unresolved externals
// (mangled name ...@RuntimeGraph@Deep2@RawrXD@@). Keep them here (standalone,
// no ggml/Vulkan deps) so the benchmark links without the graph executor.
namespace RawrXD { namespace Deep2 { namespace RuntimeGraph {
double g_moe_router_ms = 0.0;
double g_moe_expert_ms = 0.0;
unsigned long g_moe_router_calls = 0;
unsigned long g_moe_expert_calls = 0;
} } }

extern "C" double Deep2Bench_MoeRouterMs(void)           { return RawrXD::Deep2::RuntimeGraph::g_moe_router_ms; }
extern "C" double Deep2Bench_MoeExpertMs(void)           { return RawrXD::Deep2::RuntimeGraph::g_moe_expert_ms; }
extern "C" unsigned long Deep2Bench_MoeRouterCalls(void) { return RawrXD::Deep2::RuntimeGraph::g_moe_router_calls; }
extern "C" unsigned long Deep2Bench_MoeExpertCalls(void) { return RawrXD::Deep2::RuntimeGraph::g_moe_expert_calls; }