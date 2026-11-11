/*===========================================================================
 * test_simulator.cpp
 *
 * Standalone test runner for RPC Simulator
 *
 * Usage: test_simulator.exe
 *===========================================================================*/

#include "SovereignRPC_Simulator.hpp"
#include <iostream>
#include <thread>

using namespace RawrXD::RPC;

int main() {
    std::cout << "========================================\n";
    std::cout << "  SovereignRPC Simulator Test Suite\n";
    std::cout << "========================================\n\n";

    // Calibrate TSC timer
    std::cout << "Calibrating TSC timer...\n";
    TscCalibration::Instance().Calibrate();
    std::cout << "TSC Frequency: " << TscCalibration::Instance().tscFrequency << " Hz\n\n";

    // Initialize telemetry ring buffer
    TelemetryRingBuffer::Instance().Initialize();

    // Initialize simulator
    RPCSimulator::Instance().Initialize();

    // Run all tests
    RPCSimulator::Instance().RunAllTests();

    // Generate report
    RPCSimulator::Instance().GenerateReport("simulator_test_report.txt");

    // Print telemetry report
    RPCSimulator::Instance().PrintTelemetryReport();

    // Export telemetry to CSV
    RPCSimulator::Instance().ExportTelemetryCSV("lease_telemetry.csv");

    std::cout << "\nReports saved:\n";
    std::cout << "  - simulator_test_report.txt\n";
    std::cout << "  - lease_telemetry.csv\n";

    return 0;
}
