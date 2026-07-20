/*===========================================================================
 * test_simulator_standalone.cpp
 *
 * Minimal standalone test for lease telemetry
 *===========================================================================*/

#include <iostream>
#include <cstdint>
#include <chrono>
#include <thread>
#include <vector>
#include <algorithm>

// Use std::chrono for portable high-resolution timing
using Clock = std::chrono::high_resolution_clock;
using TimePoint = Clock::time_point;

inline TimePoint GetTimestamp() { return Clock::now(); }

inline double ToMicroseconds(TimePoint start, TimePoint end) {
    return std::chrono::duration<double, std::micro>(end - start).count();
}

struct LeaseTelemetry {
    uint64_t leaseId;
    TimePoint t_requestSent;
    TimePoint t_grantReceived;
    TimePoint t_execStart;
    TimePoint t_execComplete;
    double handshakeLatencyUs;
    double execLatencyUs;
    double totalLatencyUs;
    bool success;
};

class MinimalSimulator {
public:
    void Initialize() {
        // No calibration needed with std::chrono
    }

    uint64_t RequestLease() {
        TimePoint t_request = GetTimestamp();
        
        // Simulate minimal work
        std::this_thread::sleep_for(std::chrono::microseconds(1));
        
        TimePoint t_grant = GetTimestamp();
        
        LeaseTelemetry tel;
        tel.leaseId = nextLeaseId_++;
        tel.t_requestSent = t_request;
        tel.t_grantReceived = t_grant;
        tel.handshakeLatencyUs = ToMicroseconds(t_request, t_grant);
        
        telemetry_.push_back(tel);
        return tel.leaseId;
    }

    bool ExecuteWithLease(uint64_t leaseId) {
        auto& tel = telemetry_[leaseId - 1];
        
        TimePoint t_execStart = GetTimestamp();
        
        // Simulate inference work
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        TimePoint t_execComplete = GetTimestamp();
        
        tel.t_execStart = t_execStart;
        tel.t_execComplete = t_execComplete;
        tel.execLatencyUs = ToMicroseconds(t_execStart, t_execComplete);
        tel.totalLatencyUs = ToMicroseconds(tel.t_requestSent, t_execComplete);
        tel.success = true;
        
        return true;
    }

    void PrintTelemetryReport() {
        std::cout << "\n=================================================================\n";
        std::cout << "  LEASE TELEMETRY REPORT\n";
        std::cout << "=================================================================\n";

        if (telemetry_.empty()) {
            std::cout << "  No telemetry data collected.\n";
            return;
        }

        double totalHandshake = 0.0;
        double totalExec = 0.0;
        double totalTotal = 0.0;
        std::vector<double> handshakeLatencies;

        for (const auto& t : telemetry_) {
            totalHandshake += t.handshakeLatencyUs;
            totalExec += t.execLatencyUs;
            totalTotal += t.totalLatencyUs;
            handshakeLatencies.push_back(t.handshakeLatencyUs);
        }

        double avgHandshake = totalHandshake / telemetry_.size();
        double avgExec = totalExec / telemetry_.size();
        double avgTotal = totalTotal / telemetry_.size();

        std::sort(handshakeLatencies.begin(), handshakeLatencies.end());
        double p95Handshake = handshakeLatencies[static_cast<size_t>(handshakeLatencies.size() * 0.95)];

        std::cout << "  Total Leases:        " << telemetry_.size() << "\n";
        std::cout << "\n";
        std::cout << "  Avg Handshake Latency: " << avgHandshake << " us\n";
        std::cout << "  P95 Handshake Latency: " << p95Handshake << " us\n";
        std::cout << "  Avg Execution Latency: " << avgExec << " us\n";
        std::cout << "  Avg Total Latency:     " << avgTotal << " us\n";
        std::cout << "=================================================================\n";

        if (avgHandshake > 500.0) {
            std::cout << "  WARNING: Handshake latency exceeds 500us budget!\n";
            std::cout << "  Consider optimizing ZeroMQ framing.\n";
        } else {
            std::cout << "  OK: Handshake latency within 500us budget.\n";
        }
    }

    void RunTests() {
        std::cout << "Running lease protocol tests...\n\n";
        
        // Run 10 lease operations
        for (int i = 0; i < 10; ++i) {
            uint64_t leaseId = RequestLease();
            ExecuteWithLease(leaseId);
        }
        
        std::cout << "Tests completed.\n";
    }

private:
    uint64_t nextLeaseId_ = 1;
    std::vector<LeaseTelemetry> telemetry_;
};

int main() {
    std::cout << "========================================\n";
    std::cout << "  SovereignRPC Simulator Test Suite\n";
    std::cout << "========================================\n\n";

    MinimalSimulator sim;
    sim.Initialize();
    sim.RunTests();
    sim.PrintTelemetryReport();

    return 0;
}
