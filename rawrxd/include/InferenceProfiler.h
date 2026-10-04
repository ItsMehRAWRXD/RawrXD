// ============================================================================
// include/InferenceProfiler.h -- Minimal inference operation profiler
// ============================================================================
// Declares the RawrXD::InferenceProfiler singleton. Its only definitions live in
// src/core/gold_inference_profiler_minimal.cpp.
//
// ----------------------------------------------------------------------------
// WHY THIS FILE EXISTS NOW (RAWRXD_MISSING_SOURCE_001)
// ----------------------------------------------------------------------------
// src/core/gold_inference_profiler_minimal.cpp has always been in the
// RawrXD_Gold source list and has always failed to compile, because the header
// it opens with was never written:
//
//     src\core\gold_inference_profiler_minimal.cpp(2,10): error C1083: Cannot
//         open include file: 'InferenceProfiler.h': No such file or directory
//
// The build-graph census (RAWRXD_BUILD_GRAPH_CENSUS_001) cannot see this class of
// absence: it scans CMakeLists.txt for declared SOURCES, and a missing #include
// is not a source-list entry. A declared translation unit that cannot compile is
// therefore counted PRESENT and is invisible to every build-graph gate.
//
// This declaration set is reconstructed from the implementation, not specified.
// Each declaration below names the definition in
// gold_inference_profiler_minimal.cpp that forces it, so a disagreement between
// this header and that file is a compile error rather than a silent mismatch.
//
// SCOPE LIMIT, STATED PLAINLY. The implementation is four empty-bodied methods
// plus a GetPrometheusText() that returns a fixed string, so this class
// records nothing. It exists to satisfy a link requirement for RawrXD_Gold and
// BackendOrchestrator -- the .cpp says so in its own first line. Nothing here
// should be read as profiling capability, and GetPrometheusText() will report no
// samples no matter how much inference has run.
// ============================================================================

#pragma once

#include <string>

namespace RawrXD {

// ============================================================================
// Inference Profiler Singleton
// ============================================================================
// The constructor is private so Instance() is the only way to obtain one; the
// implementation instantiates it as a function-local static, which is why a
// private constructor is legal there and does not need a friend declaration.
class InferenceProfiler {
public:
    static InferenceProfiler& Instance();

    // Operation span. `opName` identifies the operation and `tokenIndex` the
    // decode step within it. EndOp's two doubles are the measured duration and
    // the measured cost for that span; both are discarded by the current
    // implementation, which is why they are unnamed parameters there.
    void BeginOp(const std::string& opName, int tokenIndex);
    void EndOp(const std::string& opName, int tokenIndex,
               double durationMs, double cost);

    // Prometheus text exposition. Returns a fixed placeholder string today.
    std::string GetPrometheusText() const;

private:
    InferenceProfiler() = default;
    ~InferenceProfiler() = default;

    InferenceProfiler(const InferenceProfiler&)            = delete;
    InferenceProfiler& operator=(const InferenceProfiler&) = delete;
};

} // namespace RawrXD