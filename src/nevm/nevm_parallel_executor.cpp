//============================================================================
// nevm_parallel_executor.cpp
// RawrXD N-EVM - Parallel Gate Execution Implementation
//============================================================================

#include "nevm_parallel_executor.hpp"
#include <iostream>

namespace RawrXD {
namespace NEVM {

// Implementation is header-only for templates
// This file exists for build system consistency

void PrintParallelExecutionStats(const ParallelGateExecutor::ExecutionStats& stats) {
    std::cout << "\n=== Parallel Execution Statistics ===\n";
    std::cout << "Total Duration: " << stats.total_duration_ms << " ms\n";
    std::cout << "Gates Executed: " << stats.gates_executed << "\n";
    std::cout << "Gates Parallelized: " << stats.gates_parallelized << "\n";
    std::cout << "Parallel Speedup: " << std::fixed << std::setprecision(2) 
              << stats.parallel_speedup << "x\n\n";
}

} // namespace NEVM
} // namespace RawrXD
