// moe_timing_graph.cpp -- namespaced MoE timing state for the graph executor.
//
// runtime_graph_executor.cpp declares these four counters `extern` from inside
// namespace RawrXD::Deep2::RuntimeGraph (its RAII MoeTimingGuard/MoeTimingPrinter
// reference the namespaced names). moe_timing.cpp defines the *global*-namespace
// copies for the C benchmark accessors. A target that links the graph executor
// (e.g. the CLI's Strata path) must provide the namespaced definitions or the
// link fails with unresolved externals. This TU supplies exactly those, and only
// those, so it can be added to any target that compiles runtime_graph_executor.cpp
// without touching shared engine sources.

namespace RawrXD {
namespace Deep2 {
namespace RuntimeGraph {

double g_moe_router_ms = 0.0;
double g_moe_expert_ms = 0.0;
unsigned long g_moe_router_calls = 0;
unsigned long g_moe_expert_calls = 0;

}  // namespace RuntimeGraph
}  // namespace Deep2
}  // namespace RawrXD