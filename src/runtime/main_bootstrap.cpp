/**
 * main_bootstrap.cpp
 * 
 * Phase B.5: Unified Sovereign Runtime Bootstrap Entry Point
 * 
 * Single executable that bootstraps the complete stack:
 * SEG → Engine → Swarm → Telemetry → Execution Graph → Adaptive Scheduler → Dashboard
 */

#include "SovereignRuntimeBootstrap.hpp"

int main(int argc, char* argv[]) {
    return Sovereign::SovereignBootstrapCLI::Run(argc, argv);
}
