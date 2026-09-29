#pragma once

// Compute benchmark authority - Gates all compute benchmark execution
// This authority ensures every compute benchmark is explicitly named, timed, and measured

namespace rawrxd::bench
{
    // Run compute benchmark
    void runComputeBench(const std::string& benchmarkName, long long durationMs, double tps);
    
    // Write benchmark receipt
    void writeBenchmarkReceipt();
}
