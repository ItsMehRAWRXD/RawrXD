/**
 * @file health_probe.cpp
 * @brief Standalone production health probe for RawrXD.
 *
 * Answers liveness and readiness probes without starting the GUI, so
 * supervisors, CI and load balancers can observe the process in a headless
 * environment. This is the same call sequence the IDE's own `--health-check`
 * path performs, isolated so it can be verified on its own.
 *
 * Usage:
 *   rawrxd_health_probe                 # single-line status
 *   rawrxd_health_probe --json          # full per-component report
 *
 * Exit codes:
 *   0  healthy
 *   1  degraded or not ready
 *   2  the probe itself failed
 */

#include "ProductionRuntime.hpp"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    using namespace Sovereign::Production;

    const bool json_output = argc > 1 && std::string(argv[1]) == "--json";

    try {
        ProductionRuntime::Options options;
        // A probe reports the state it finds; gating or installing a global
        // crash handler would be wrong for a diagnostic command.
        options.enforce_gates = false;
        options.install_signal_handlers = false;
        if (!ProductionRuntime::init(options)) {
            std::cerr << "probe: runtime reported not ready\n";
        }

        HealthRegistry::instance().run_all();
        const bool live = ProductionRuntime::probe_liveness();
        const bool ready = ProductionRuntime::probe_readiness();

        if (json_output) {
            std::cout << ProductionRuntime::health_json() << std::endl;
        } else {
            std::cout << HealthRegistry::instance().probe_body()
                      << " (liveness=" << (live ? "true" : "false")
                      << " readiness=" << (ready ? "true" : "false") << ")"
                      << std::endl;
        }
        if (!live || !ready) {
            std::cerr << ProductionRuntime::health_json() << std::endl;
        }
        ProductionRuntime::shutdown();
        return (live && ready) ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "probe failed: " << e.what() << std::endl;
        ProductionRuntime::shutdown();
        return 2;
    }
}
