// The cost of a supervisor's shutdown, with the default configuration.
//
// The supervisor's metrics loop and healing loop each wait for their
// interval. The defaults are a second and half a second, and both loops
// are on by default, so a supervisor that is created and shut down without
// overriding the configuration waits for the waits to finish.
//
// The supervisor is left running for a moment before it is shut down,
// because that is the case that matters: a supervisor that is shut down in
// the same instant it was created has not reached its wait yet, and the
// cost of the wait is not visible.
//
// Usage: supervisor_teardown_cost [iterations] [settle_ms]

#include "../src/agentic/AgenticSupervisor.hpp"
using namespace RawrXD::Agentic;

#include <chrono>
#include <cstdio>

int main(int argc, char** argv) {
    const int iterations = (argc > 1) ? std::atoi(argv[1]) : 5;
    const int settleMs = (argc > 2) ? std::atoi(argv[2]) : 200;

    double worst = 0.0;
    double total = 0.0;
    for (int i = 0; i < iterations; ++i) {
        AgenticSupervisor::Config config;      // the defaults
        AgenticSupervisor::Instance().Initialize(config);

        // Let the supervisor run, so the loops are inside their waits when
        // the shutdown arrives.
        std::this_thread::sleep_for(std::chrono::milliseconds(settleMs));

        const auto start = std::chrono::steady_clock::now();
        AgenticSupervisor::Instance().Shutdown();
        const double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();
        if (ms > worst) worst = ms;
        total += ms;
        std::printf("[TEARDOWN] iteration %d: %.1f ms\n", i + 1, ms);
    }
    std::printf("[TEARDOWN] mean %.1f ms, worst %.1f ms over %d iteration(s)\n",
                total / (double)iterations, worst, iterations);
    return 0;
}
