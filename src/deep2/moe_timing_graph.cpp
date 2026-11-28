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

// The namespaced definitions now live in runtime_graph_executor.cpp (so every target that
// compiles the executor resolves them). This TU is kept as a non-defining reference so
// targets that list it still link; it intentionally defines nothing.
namespace RawrXD {
namespace Deep2 {
namespace RuntimeGraph {

extern double g_moe_router_ms;
extern double g_moe_expert_ms;
extern unsigned long g_moe_router_calls;
extern unsigned long g_moe_expert_calls;

}  // namespace RuntimeGraph
}  // namespace Deep2
}  // namespace RawrXD