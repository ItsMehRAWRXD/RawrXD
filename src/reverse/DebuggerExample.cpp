/**
 * @file DebuggerExample.cpp
 * @brief Example usage of DebuggerIntegration with ComprehensivePatternGenerator
 * @defensive SAW/THF-compliant
 * 
 * This example demonstrates:
 * 1. Attaching to a running process or launching a new one
 * 2. Setting pattern-based breakpoints
 * 3. Scanning memory for patterns in real-time
 * 4. Discovering new patterns from live process memory
 * 5. Exporting findings to BigDaddyG model format
 */

#include "DebuggerIntegration.hpp"
#include "ComprehensivePatternGenerator.hpp"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

using namespace RawrXD::Reverse;

// Callback for pattern breakpoint hits
void onPatternHit(const LiveAnalysisResult& result) {
    std::cout << "\n[CALLBACK] Pattern detected!" << std::endl;
    std::cout << "  Address: 0x" << std::hex << result.address << std::dec << std::endl;
    std::cout << "  Pattern: " << result.pattern.name << std::endl;
    std::cout << "  Type: " << static_cast<int>(result.pattern.type) << std::endl;
    std::cout << "  Confidence: " << result.confidence << std::endl;
    std::cout << "  Thread ID: " << result.threadId << std::endl;
    std::cout << "  Context (first 32 bytes): ";
    
    for (size_t i = 0; i < std::min(size_t(32), result.context.size()); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << (int)result.context[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

// Callback for debug events
void onDebugEvent(const DebugEvent& event) {
    std::cout << "[EVENT] Type: " << static_cast<int>(event.type)
              << " | PID: " << event.processId
              << " | TID: " << event.threadId
              << " | Addr: 0x" << std::hex << event.address << std::dec;
    
    if (!event.description.empty()) {
        std::cout << " | " << event.description;
    }
    std::cout << std::endl;
}

void printUsage(const char* programName) {
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << programName << " attach <PID>           - Attach to running process" << std::endl;
    std::cout << "  " << programName << " launch <exe> [args]    - Launch and debug new process" << std::endl;
    std::cout << "  " << programName << " scan <PID>             - Quick memory scan demo" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    DebuggerIntegration debugger;
    
    // Set up event callback
    debugger.setEventCallback(onDebugEvent);

    // Initialize pattern generator with some known patterns
    std::vector<uint8_t> prologuePattern = {0x55, 0x89, 0xE5}; // push ebp; mov ebp, esp
    std::vector<uint8_t> callPattern = {0xE8}; // call rel32
    std::vector<uint8_t> retPattern = {0xC3}; // ret

    bool success = false;

    if (mode == "attach") {
        DWORD pid = std::stoul(argv[2]);
        std::cout << "[*] Attaching to process " << pid << "..." << std::endl;
        success = debugger.attachToProcess(pid);

    } else if (mode == "launch") {
        std::string exePath = argv[2];
        std::string args = (argc > 3) ? argv[3] : "";
        std::cout << "[*] Launching " << exePath << "..." << std::endl;
        success = debugger.launchAndAttach(exePath, args);

    } else if (mode == "scan") {
        DWORD pid = std::stoul(argv[2]);
        std::cout << "[*] Quick scan mode - attaching to " << pid << "..." << std::endl;
        
        if (!debugger.attachToProcess(pid)) {
            std::cerr << "[!] Failed to attach" << std::endl;
            return 1;
        }

        // Quick scan for function prologues
        std::cout << "[*] Scanning for function prologues..." << std::endl;
        
        Pattern prologuePat;
        prologuePat.name = "function_prologue";
        prologuePat.bytes = prologuePattern;
        prologuePat.confidence = 0.95;
        prologuePat.type = PatternType::ORIGINAL;

        // Scan all memory regions
        auto results = debugger.analyzeAllMemoryRegions({prologuePat});
        
        std::cout << "[*] Found " << results.size() << " potential function prologues" << std::endl;
        
        for (const auto& result : results) {
            std::cout << "  [+] 0x" << std::hex << result.address << std::dec
                      << " (confidence: " << result.confidence << ")" << std::endl;
        }

        debugger.detach();
        return 0;

    } else {
        printUsage(argv[0]);
        return 1;
    }

    if (!success) {
        std::cerr << "[!] Failed to initialize debugger" << std::endl;
        return 1;
    }

    std::cout << "[*] Debugger initialized. Setting up pattern breakpoints..." << std::endl;

    // Set up pattern breakpoints
    Pattern prologuePat;
    prologuePat.name = "function_prologue";
    prologuePat.bytes = prologuePattern;
    prologuePat.confidence = 0.95;
    prologuePat.type = PatternType::ORIGINAL;

    // Note: In a real scenario, you'd scan first to find addresses, then set breakpoints
    // For demo, we'll set a memory scan breakpoint
    debugger.setMemoryScanBreakpoint(prologuePattern, 1000, onPatternHit);

    // Also set up scan for call instructions
    debugger.setMemoryScanBreakpoint(callPattern, 500, 
        [](const LiveAnalysisResult& r) {
            std::cout << "[CALL DETECTED] at 0x" << std::hex << r.address << std::dec << std::endl;
        });

    std::cout << "[*] Running event loop. Press Ctrl+C to stop..." << std::endl;
    std::cout << "[*] The debugger will:" << std::endl;
    std::cout << "    - Monitor for function prologues (push ebp; mov ebp, esp)" << std::endl;
    std::cout << "    - Monitor for call instructions" << std::endl;
    std::cout << "    - Report all debug events" << std::endl;
    std::cout << "    - Scan memory periodically for patterns" << std::endl;

    // Run event loop for 30 seconds or until process exits
    auto startTime = std::chrono::steady_clock::now();
    
    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (elapsed > std::chrono::seconds(30)) {
            std::cout << "[*] Timeout reached, stopping..." << std::endl;
            break;
        }

        // Process debug events with 100ms timeout
        if (!debugger.waitForEvent(100)) {
            // No event - continue
            continue;
        }

        // Event was processed - check if we should continue
        // (waitForEvent handles the callback)
    }

    // Demonstrate pattern discovery
    std::cout << "\n[*] Running pattern discovery on executable memory regions..." << std::endl;
    
    // Get memory regions and scan for patterns
    auto regions = debugger.getMemoryRegions();
    ComprehensivePatternGenerator generator;
    
    int regionsScanned = 0;
    for (const auto& region : regions) {
        if (region.isExecutable && regionsScanned < 5) { // Limit to first 5 executable regions
            std::cout << "  Scanning region at 0x" << std::hex << region.baseAddress 
                      << " (" << std::dec << region.size << " bytes)..." << std::endl;
            
            auto discovered = debugger.discoverPatternsInMemory(region.baseAddress, 
                                                                  std::min(region.size, size_t(65536)),
                                                                  4);
            
            std::cout << "    Found " << discovered.size() << " patterns" << std::endl;
            regionsScanned++;
        }
    }

    // Export discovered patterns to BigDaddyG model format
    std::cout << "\n[*] Exporting patterns to BigDaddyG model format..." << std::endl;
    
    // Create a sample pattern set for export
    std::vector<Pattern> patternsToExport = {
        {"prologue_std", {0x55, 0x8B, 0xEC}, 0.95, PatternType::ORIGINAL},
        {"prologue_frame", {0x55, 0x89, 0xE5}, 0.95, PatternType::ORIGINAL},
        {"call_rel32", {0xE8}, 0.90, PatternType::ORIGINAL},
        {"jmp_rel32", {0xE9}, 0.90, PatternType::ORIGINAL},
        {"ret_near", {0xC3}, 0.99, PatternType::ORIGINAL},
        {"ret_far", {0xCB}, 0.99, PatternType::ORIGINAL},
        {"int3", {0xCC}, 0.99, PatternType::ORIGINAL},
        {"nop", {0x90}, 0.99, PatternType::ORIGINAL}
    };

    // Export to JSON
    std::string jsonOutput = generator.exportToBigDaddyGModel(patternsToExport);
    std::cout << "Exported model (first 500 chars):\n" 
              << jsonOutput.substr(0, 500) << "..." << std::endl;

    // Cleanup
    std::cout << "\n[*] Detaching from process..." << std::endl;
    debugger.detach();

    std::cout << "[*] Done!" << std::endl;
    return 0;
}
