// RawrXD-Script Trace Collector Integration Test
// Tests the MASM trace collector from C++

#include "trace_collector_masm.hpp"
#include <cstdio>
#include <cstring>

using namespace RawrXD::Script;

// Test helper to print fingerprint
void PrintFingerprint(const ExecutionFingerprint& fp, const char* label) {
    char buffer[33];
    fp.ToString(buffer, sizeof(buffer));
    printf("%s: %s\n", label, buffer);
}

// Test 1: Basic trace collection
bool Test_BasicTraceCollection() {
    printf("\n=== Test 1: Basic Trace Collection ===\n");
    
    // Reset and start recording
    MASMTraceCollector::Reset();
    MASMTraceCollector::Start();
    
    // Record some events
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);  // ADD r0, r1
    MASMTraceCollector::RecordRegister(0, 42);      // r0 = 42
    MASMTraceCollector::RecordOpcode(0x21, 1, 2);  // SUB r1, r2
    MASMTraceCollector::RecordRegister(1, 100);     // r1 = 100
    
    // Stop and get fingerprint
    MASMTraceCollector::Stop();
    
    auto fp = MASMTraceCollector::GetFingerprint();
    auto count = MASMTraceCollector::GetEventCount();
    
    printf("Events recorded: %u\n", count);
    PrintFingerprint(fp, "Execution fingerprint");
    
    // Verify we got events
    if (count != 4) {
        printf("FAIL: Expected 4 events, got %u\n", count);
        return false;
    }
    
    // Verify fingerprint is non-zero
    if (fp.low == 0 && fp.high == 0) {
        printf("FAIL: Fingerprint is zero\n");
        return false;
    }
    
    printf("PASS: Basic trace collection works\n");
    return true;
}

// Test 2: Determinism - same events = same fingerprint
bool Test_Determinism() {
    printf("\n=== Test 2: Determinism ===\n");
    
    // First run
    MASMTraceCollector::Reset();
    MASMTraceCollector::Start();
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);
    MASMTraceCollector::RecordOpcode(0x21, 1, 2);
    MASMTraceCollector::RecordOpcode(0x22, 2, 3);
    MASMTraceCollector::Stop();
    auto fp1 = MASMTraceCollector::GetFingerprint();
    
    // Second run (same events)
    MASMTraceCollector::Reset();
    MASMTraceCollector::Start();
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);
    MASMTraceCollector::RecordOpcode(0x21, 1, 2);
    MASMTraceCollector::RecordOpcode(0x22, 2, 3);
    MASMTraceCollector::Stop();
    auto fp2 = MASMTraceCollector::GetFingerprint();
    
    PrintFingerprint(fp1, "First run");
    PrintFingerprint(fp2, "Second run");
    
    if (fp1 != fp2) {
        printf("FAIL: Fingerprints don't match for identical execution\n");
        return false;
    }
    
    printf("PASS: Execution is deterministic\n");
    return true;
}

// Test 3: Differentiation - different events = different fingerprints
bool Test_Differentiation() {
    printf("\n=== Test 3: Differentiation ===\n");
    
    // First execution
    MASMTraceCollector::Reset();
    MASMTraceCollector::Start();
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);  // ADD
    MASMTraceCollector::RecordOpcode(0x21, 1, 2);  // SUB
    MASMTraceCollector::Stop();
    auto fp1 = MASMTraceCollector::GetFingerprint();
    
    // Second execution (different)
    MASMTraceCollector::Reset();
    MASMTraceCollector::Start();
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);  // ADD
    MASMTraceCollector::RecordOpcode(0x22, 1, 2);  // MUL (different!)
    MASMTraceCollector::Stop();
    auto fp2 = MASMTraceCollector::GetFingerprint();
    
    PrintFingerprint(fp1, "ADD then SUB");
    PrintFingerprint(fp2, "ADD then MUL");
    
    if (fp1 == fp2) {
        printf("FAIL: Fingerprints match for different execution\n");
        return false;
    }
    
    printf("PASS: Different executions produce different fingerprints\n");
    return true;
}

// Test 4: Recording state
bool Test_RecordingState() {
    printf("\n=== Test 4: Recording State ===\n");
    
    MASMTraceCollector::Reset();
    
    if (MASMTraceCollector::IsRecording()) {
        printf("FAIL: Should not be recording after reset\n");
        return false;
    }
    
    MASMTraceCollector::Start();
    if (!MASMTraceCollector::IsRecording()) {
        printf("FAIL: Should be recording after start\n");
        return false;
    }
    
    MASMTraceCollector::Stop();
    if (MASMTraceCollector::IsRecording()) {
        printf("FAIL: Should not be recording after stop\n");
        return false;
    }
    
    printf("PASS: Recording state management works\n");
    return true;
}

// Test 5: Event types
bool Test_EventTypes() {
    printf("\n=== Test 5: Event Types ===\n");
    
    MASMTraceCollector::Reset();
    MASMTraceCollector::Start();
    
    // Record different event types
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);                    // Type 0x01
    MASMTraceCollector::RecordRegister(0, 0xDEADBEEF);              // Type 0x02
    MASMTraceCollector::RecordMemoryAccess(0x1000, 8, false);       // Type 0x03 (read)
    MASMTraceCollector::RecordMemoryAccess(0x2000, 4, true);        // Type 0x03 (write)
    MASMTraceCollector::RecordBranch(0x100, 0x200, true);           // Type 0x04
    
    MASMTraceCollector::Stop();
    
    auto count = MASMTraceCollector::GetEventCount();
    printf("Events recorded: %u\n", count);
    
    if (count != 5) {
        printf("FAIL: Expected 5 events, got %u\n", count);
        return false;
    }
    
    printf("PASS: All event types recorded successfully\n");
    return true;
}

// Main test runner
int main() {
    printf("RawrXD-Script Trace Collector Integration Test\n");
    printf("=============================================\n");
    
    int passed = 0;
    int failed = 0;
    
    if (Test_BasicTraceCollection()) passed++; else failed++;
    if (Test_Determinism()) passed++; else failed++;
    if (Test_Differentiation()) passed++; else failed++;
    if (Test_RecordingState()) passed++; else failed++;
    if (Test_EventTypes()) passed++; else failed++;
    
    printf("\n=============================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    
    return failed > 0 ? 1 : 0;
}
