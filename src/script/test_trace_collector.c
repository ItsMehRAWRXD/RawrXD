// Test for RawrXD-Script Trace Collector
// Verifies fingerprint generation from execution traces

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "trace_collector.hpp"

// External ASM functions
extern int JsInterpreter_Run(uint8_t* bytecode, size_t bytecode_size, 
                             uint64_t* constants, uint64_t* result);

// Opcodes
#define OP_LOAD_CONST   0x01
#define OP_ADD          0x10
#define OP_RETURN       0x50

// NaN-boxed constants
#define JS_FALSE        0x7FF2000000000000ULL

using namespace RawrXD::Script;

static uint64_t encode_double(double val) {
    union { double d; uint64_t u; } conv;
    conv.d = val;
    return conv.u;
}

int main() {
    printf("RawrXD-Script Trace Collector Test\n");
    printf("====================================\n\n");
    
    // Initialize trace collector
    TraceCollector collector;
    collector.start();
    
    printf("Trace collector started.\n");
    printf("Buffer size: %zu events (%zu KB)\n\n", 
           (size_t)TRACE_BUFFER_SIZE, 
           (size_t)(TRACE_BUFFER_SIZE * sizeof(TraceEvent) / 1024));
    
    // Test 1: Generate fingerprint for simple arithmetic
    printf("Test 1: Simple Arithmetic (5 + 3)\n");
    printf("-----------------------------------\n");
    
    uint8_t bytecode[] = {
        OP_LOAD_CONST, 0, 0, 0,    // r0 = const[0] (5.0)
        OP_LOAD_CONST, 1, 1, 0,    // r1 = const[1] (3.0)
        OP_ADD, 2, 0, 1,           // r2 = r0 + r1
        OP_RETURN, 2               // return r2
    };
    uint64_t constants[] = { encode_double(5.0), encode_double(3.0) };
    uint64_t result;
    
    // Record events manually (simulating what MASM will do)
    collector.recordOpcode((uint64_t)bytecode, OP_LOAD_CONST);
    collector.recordRegisterWrite(0, constants[0]);
    
    collector.recordOpcode((uint64_t)(bytecode + 4), OP_LOAD_CONST);
    collector.recordRegisterWrite(1, constants[1]);
    
    collector.recordOpcode((uint64_t)(bytecode + 8), OP_ADD);
    collector.recordRegisterRead(0, constants[0]);
    collector.recordRegisterRead(1, constants[1]);
    collector.recordRegisterWrite(2, encode_double(8.0));
    
    collector.recordOpcode((uint64_t)(bytecode + 12), OP_RETURN);
    
    // Generate fingerprint
    TraceFingerprint fp = collector.generateFingerprint();
    
    printf("Fingerprint: %s\n", fp.toString().c_str());
    printf("Events recorded: %u\n", fp.event_count);
    printf("Instructions: %u\n\n", fp.instruction_count);
    
    // Test 2: Same computation should produce same fingerprint
    printf("Test 2: Determinism Check\n");
    printf("--------------------------\n");
    
    collector.reset();
    collector.start();
    
    // Record same events again
    collector.recordOpcode((uint64_t)bytecode, OP_LOAD_CONST);
    collector.recordRegisterWrite(0, constants[0]);
    collector.recordOpcode((uint64_t)(bytecode + 4), OP_LOAD_CONST);
    collector.recordRegisterWrite(1, constants[1]);
    collector.recordOpcode((uint64_t)(bytecode + 8), OP_ADD);
    collector.recordRegisterRead(0, constants[0]);
    collector.recordRegisterRead(1, constants[1]);
    collector.recordRegisterWrite(2, encode_double(8.0));
    collector.recordOpcode((uint64_t)(bytecode + 12), OP_RETURN);
    
    TraceFingerprint fp2 = collector.generateFingerprint();
    
    printf("Fingerprint 1: %s\n", fp.toString().c_str());
    printf("Fingerprint 2: %s\n", fp2.toString().c_str());
    
    if (fp == fp2) {
        printf("✅ PASS: Fingerprints are identical (deterministic)\n\n");
    } else {
        printf("❌ FAIL: Fingerprints differ (non-deterministic)\n\n");
    }
    
    // Test 3: Different computation produces different fingerprint
    printf("Test 3: Differentiation Check\n");
    printf("------------------------------\n");
    
    collector.reset();
    collector.start();
    
    // Different: 10 + 4 instead of 5 + 3
    collector.recordOpcode((uint64_t)bytecode, OP_LOAD_CONST);
    collector.recordRegisterWrite(0, encode_double(10.0));
    collector.recordOpcode((uint64_t)(bytecode + 4), OP_LOAD_CONST);
    collector.recordRegisterWrite(1, encode_double(4.0));
    collector.recordOpcode((uint64_t)(bytecode + 8), OP_ADD);
    collector.recordRegisterRead(0, encode_double(10.0));
    collector.recordRegisterRead(1, encode_double(4.0));
    collector.recordRegisterWrite(2, encode_double(14.0));
    collector.recordOpcode((uint64_t)(bytecode + 12), OP_RETURN);
    
    TraceFingerprint fp3 = collector.generateFingerprint();
    
    printf("Fingerprint 1 (5+3): %s\n", fp.toString().c_str());
    printf("Fingerprint 3 (10+4): %s\n", fp3.toString().c_str());
    
    if (fp != fp3) {
        printf("✅ PASS: Different executions have different fingerprints\n\n");
    } else {
        printf("❌ FAIL: Different executions have same fingerprint\n\n");
    }
    
    // Test 4: Trace summary
    printf("Test 4: Trace Summary\n");
    printf("---------------------\n");
    printf("%s\n", collector.getTraceSummary().c_str());
    
    // Test 5: Dump trace to file
    printf("Test 5: Trace Dump\n");
    printf("------------------\n");
    collector.dumpTraceToFile("trace_dump.txt");
    printf("Trace dumped to trace_dump.txt\n\n");
    
    printf("====================================\n");
    printf("Trace Collector Test Complete!\n");
    printf("Ready for MASM integration.\n");
    
    return 0;
}
