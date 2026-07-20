/*===========================================================================
 * test_simulator.cpp
 *
 * Standalone test runner for RPC Simulator
 *
 * Usage: test_simulator.exe
 *===========================================================================*/

#include "SovereignRPC_Simulator.hpp"
#include <iostream>

using namespace RawrXD::RPC;

int main() {
    std::cout << "========================================\n";
    std::cout << "  SovereignRPC Simulator Test Suite\n";
    std::cout << "========================================\n\n";

    // Initialize simulator
    RPCSimulator::Instance().Initialize();

    // Run all tests
    RPCSimulator::Instance().RunAllTests();

    // Generate report
    RPCSimulator::Instance().GenerateReport("simulator_test_report.txt");

    std::cout << "\nReport saved to: simulator_test_report.txt\n";

    return 0;
}
