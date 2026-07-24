/**
 * @file DebuggerIntegration.cpp
 * @brief Implementation of debugger integration for live pattern analysis
 * @defensive SAW/THF-compliant
 */

#include "DebuggerIntegration.hpp"
#include <iostream>
#include <algorithm>
#include <cstring>

// Windows Debug API headers
#include <windows.h>
#include <debugapi.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")

namespace RawrXD {
namespace Reverse {

DebuggerIntegration::DebuggerIntegration() 
    : processHandle_(nullptr)
    , processId_(0)
    , isAttached_(false)
    , isPaused_(false)
    , patternGenerator_(std::make_unique<ComprehensivePatternGenerator>())
    , nextBreakpointId_(1)
    , eventCallback_(nullptr)
{
}

DebuggerIntegration::~DebuggerIntegration() {
    if (isAttached_) {
        detach();
    }
}

bool DebuggerIntegration::attachToProcess(DWORD processId) {
    if (isAttached_) {
        std::cerr << "[Debugger] Already attached to process " << processId_ << std::endl;
        return false;
    }

    // Request debug privileges
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(hToken);
    }

    // Attach to process
    if (!DebugActiveProcess(processId)) {
        std::cerr << "[Debugger] Failed to attach to process " << processId 
                  << ", Error: " << GetLastError() << std::endl;
        return false;
    }

    processId_ = processId;
    processHandle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    
    if (!processHandle_) {
        std::cerr << "[Debugger] Failed to open process handle" << std::endl;
        DebugActiveProcessStop(processId);
        return false;
    }

    isAttached_ = true;
    std::cout << "[Debugger] Successfully attached to process " << processId << std::endl;

    // Enumerate memory regions
    enumerateMemoryRegions();

    return true;
}

bool DebuggerIntegration::launchAndAttach(const std::string& executablePath, 
                                            const std::string& arguments) {
    if (isAttached_) {
        std::cerr << "[Debugger] Already attached to process" << std::endl;
        return false;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    std::string cmdLine = executablePath;
    if (!arguments.empty()) {
        cmdLine += " " + arguments;
    }

    // Create process suspended for debugging
    if (!CreateProcessA(
            NULL,
            const_cast<char*>(cmdLine.c_str()),
            NULL,
            NULL,
            FALSE,
            DEBUG_PROCESS | CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi)) {
        std::cerr << "[Debugger] Failed to launch process, Error: " << GetLastError() << std::endl;
        return false;
    }

    processId_ = pi.dwProcessId;
    processHandle_ = pi.hProcess;
    isAttached_ = true;

    // Resume main thread
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    std::cout << "[Debugger] Launched and attached to " << executablePath 
              << " (PID: " << processId_ << ")" << std::endl;

    enumerateMemoryRegions();

    return true;
}

bool DebuggerIntegration::detach() {
    if (!isAttached_) {
        return false;
    }

    // Remove all breakpoints
    removeAllBreakpoints();

    // Stop debugging
    DebugActiveProcessStop(processId_);

    if (processHandle_) {
        CloseHandle(processHandle_);
        processHandle_ = nullptr;
    }

    isAttached_ = false;
    isPaused_ = false;
    processId_ = 0;
    memoryRegions_.clear();

    std::cout << "[Debugger] Detached from process" << std::endl;

    return true;
}

bool DebuggerIntegration::setPatternBreakpoint(const Pattern& pattern, 
                                                uint64_t address,
                                                PatternBreakpointCallback callback) {
    if (!isAttached_ || !processHandle_) {
        std::cerr << "[Debugger] Not attached to process" << std::endl;
        return false;
    }

    uint32_t bpId = nextBreakpointId_++;

    // Store breakpoint info
    BreakpointInfo bpInfo;
    bpInfo.id = bpId;
    bpInfo.address = address;
    bpInfo.pattern = pattern;
    bpInfo.callback = callback;
    bpInfo.isActive = true;

    // Read original byte
    SIZE_T bytesRead;
    if (!ReadProcessMemory(processHandle_, (LPCVOID)address, &bpInfo.originalByte, 1, &bytesRead)) {
        std::cerr << "[Debugger] Failed to read memory at 0x" << std::hex << address << std::endl;
        return false;
    }

    // Write INT3 (0xCC) breakpoint
    uint8_t int3 = 0xCC;
    SIZE_T bytesWritten;
    DWORD oldProtect;
    
    // Make memory writable
    VirtualProtectEx(processHandle_, (LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    if (!WriteProcessMemory(processHandle_, (LPVOID)address, &int3, 1, &bytesWritten)) {
        std::cerr << "[Debugger] Failed to write breakpoint at 0x" << std::hex << address << std::endl;
        VirtualProtectEx(processHandle_, (LPVOID)address, 1, oldProtect, &oldProtect);
        return false;
    }

    // Restore protection
    VirtualProtectEx(processHandle_, (LPVOID)address, 1, oldProtect, &oldProtect);
    FlushInstructionCache(processHandle_, (LPCVOID)address, 1);

    breakpoints_[bpId] = bpInfo;

    std::cout << "[Debugger] Set pattern breakpoint " << bpId 
              << " at 0x" << std::hex << address << std::dec << std::endl;

    return true;
}

bool DebuggerIntegration::setMemoryScanBreakpoint(const std::vector<uint8_t>& patternBytes,
                                                  uint32_t scanIntervalMs,
                                                  PatternBreakpointCallback callback) {
    if (!isAttached_) {
        return false;
    }

    // Create a memory scan breakpoint that triggers when pattern is found
    MemoryScanBreakpoint scanBp;
    scanBp.id = nextBreakpointId_++;
    scanBp.patternBytes = patternBytes;
    scanBp.scanIntervalMs = scanIntervalMs;
    scanBp.callback = callback;
    scanBp.lastScanTime = 0;
    scanBp.isActive = true;

    memoryScanBreakpoints_[scanBp.id] = scanBp;

    std::cout << "[Debugger] Set memory scan breakpoint " << scanBp.id 
              << " for pattern of " << patternBytes.size() << " bytes" << std::endl;

    return true;
}

bool DebuggerIntegration::removeBreakpoint(uint32_t breakpointId) {
    auto it = breakpoints_.find(breakpointId);
    if (it == breakpoints_.end()) {
        return false;
    }

    // Restore original byte
    SIZE_T bytesWritten;
    DWORD oldProtect;
    
    VirtualProtectEx(processHandle_, (LPVOID)it->second.address, 1, 
                       PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(processHandle_, (LPVOID)it->second.address, 
                       &it->second.originalByte, 1, &bytesWritten);
    VirtualProtectEx(processHandle_, (LPVOID)it->second.address, 1, 
                       oldProtect, &oldProtect);
    FlushInstructionCache(processHandle_, (LPCVOID)it->second.address, 1);

    breakpoints_.erase(it);

    std::cout << "[Debugger] Removed breakpoint " << breakpointId << std::endl;

    return true;
}

void DebuggerIntegration::removeAllBreakpoints() {
    // Remove all execution breakpoints
    for (auto& [id, bp] : breakpoints_) {
        SIZE_T bytesWritten;
        DWORD oldProtect;
        
        VirtualProtectEx(processHandle_, (LPVOID)bp.address, 1, 
                           PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(processHandle_, (LPVOID)bp.address, 
                           &bp.originalByte, 1, &bytesWritten);
        VirtualProtectEx(processHandle_, (LPVOID)bp.address, 1, 
                           oldProtect, &oldProtect);
    }
    
    breakpoints_.clear();
    memoryScanBreakpoints_.clear();

    std::cout << "[Debugger] Removed all breakpoints" << std::endl;
}

bool DebuggerIntegration::continueExecution() {
    if (!isAttached_ || !isPaused_) {
        return false;
    }

    isPaused_ = false;
    return ContinueDebugEvent(processId_, threadId_, DBG_CONTINUE);
}

bool DebuggerIntegration::stepInstruction() {
    if (!isAttached_ || !isPaused_) {
        return false;
    }

    // Set single-step flag in EFLAGS
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId_);
    if (!hThread) {
        return false;
    }

    if (!GetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return false;
    }

#ifdef _WIN64
    ctx.EFlags |= 0x100;  // Trap flag for x64
#else
    ctx.Eflags |= 0x100;  // Trap flag for x86
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return false;
    }

    CloseHandle(hThread);

    return continueExecution();
}

std::vector<LiveAnalysisResult> DebuggerIntegration::scanForPatterns(
    const std::vector<Pattern>& patterns,
    uint64_t startAddress,
    size_t size) {
    
    std::vector<LiveAnalysisResult> results;

    if (!isAttached_ || !processHandle_) {
        return results;
    }

    // Read memory region
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead;
    
    if (!ReadProcessMemory(processHandle_, (LPCVOID)startAddress, 
                           buffer.data(), size, &bytesRead)) {
        return results;
    }

    // Scan for each pattern
    for (const auto& pattern : patterns) {
        if (pattern.bytes.empty()) continue;

        // Use SIMD-accelerated scan if available
        auto matches = simdScan(buffer.data(), bytesRead, pattern.bytes.data(), 
                                pattern.bytes.size());

        for (size_t offset : matches) {
            LiveAnalysisResult result;
            result.address = startAddress + offset;
            result.pattern = pattern;
            result.confidence = pattern.confidence;
            result.timestamp = GetTickCount64();
            result.threadId = 0;  // Will be populated during live analysis
            result.context = readMemoryContext(result.address, 64);
            
            results.push_back(result);
        }
    }

    return results;
}

std::vector<LiveAnalysisResult> DebuggerIntegration::discoverPatternsInMemory(
    uint64_t startAddress,
    size_t size,
    size_t minPatternLength) {
    
    std::vector<LiveAnalysisResult> results;

    if (!isAttached_ || !processHandle_) {
        return results;
    }

    // Read memory
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead;
    
    if (!ReadProcessMemory(processHandle_, (LPCVOID)startAddress, 
                           buffer.data(), size, &bytesRead)) {
        return results;
    }

    // Use pattern generator to discover patterns
    auto discovered = patternGenerator_->discoverPatterns(buffer.data(), bytesRead, minPatternLength);

    for (const auto& pattern : discovered) {
        LiveAnalysisResult result;
        result.address = startAddress;  // Base address
        result.pattern = pattern;
        result.confidence = pattern.confidence;
        result.timestamp = GetTickCount64();
        result.threadId = 0;
        result.context = std::vector<uint8_t>(buffer.begin(), 
                                               buffer.begin() + std::min(size_t(64), bytesRead));
        
        results.push_back(result);
    }

    return results;
}

std::vector<LiveAnalysisResult> DebuggerIntegration::analyzeAllMemoryRegions(
    const std::vector<Pattern>& patterns) {
    
    std::vector<LiveAnalysisResult> allResults;

    for (const auto& region : memoryRegions_) {
        if (!region.isReadable) continue;

        auto results = scanForPatterns(patterns, region.baseAddress, region.size);
        allResults.insert(allResults.end(), results.begin(), results.end());
    }

    return allResults;
}

bool DebuggerIntegration::waitForEvent(uint32_t timeoutMs) {
    if (!isAttached_) {
        return false;
    }

    DEBUG_EVENT debugEvent;
    DWORD waitResult = WaitForDebugEvent(&debugEvent, timeoutMs);

    if (waitResult == 0) {
        // Timeout - check memory scan breakpoints
        checkMemoryScanBreakpoints();
        return false;
    }

    // Process debug event
    processDebugEvent(debugEvent);

    return true;
}

void DebuggerIntegration::runEventLoop(uint32_t timeoutMs) {
    if (!isAttached_) {
        return;
    }

    std::cout << "[Debugger] Starting event loop..." << std::endl;

    while (isAttached_) {
        if (!waitForEvent(timeoutMs)) {
            // Timeout - continue
            continue;
        }

        // Event was processed
        if (!isPaused_) {
            continueExecution();
        }
    }
}

void DebuggerIntegration::setEventCallback(DebugEventCallback callback) {
    eventCallback_ = callback;
}

std::vector<uint8_t> DebuggerIntegration::readMemory(uint64_t address, size_t size) {
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead;

    if (!ReadProcessMemory(processHandle_, (LPCVOID)address, 
                           buffer.data(), size, &bytesRead)) {
        return {};
    }

    buffer.resize(bytesRead);
    return buffer;
}

bool DebuggerIntegration::writeMemory(uint64_t address, 
                                      const std::vector<uint8_t>& data) {
    SIZE_T bytesWritten;
    DWORD oldProtect;

    // Make memory writable
    if (!VirtualProtectEx(processHandle_, (LPVOID)address, data.size(), 
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    bool success = WriteProcessMemory(processHandle_, (LPVOID)address, 
                                     data.data(), data.size(), &bytesWritten);

    // Restore protection
    VirtualProtectEx(processHandle_, (LPVOID)address, data.size(), 
                     oldProtect, &oldProtect);
    FlushInstructionCache(processHandle_, (LPCVOID)address, data.size());

    return success && (bytesWritten == data.size());
}

std::vector<uint8_t> DebuggerIntegration::readMemoryContext(uint64_t address, size_t size) {
    return readMemory(address, size);
}

void DebuggerIntegration::enumerateMemoryRegions() {
    memoryRegions_.clear();

    if (!processHandle_) {
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t address = 0;

    while (VirtualQueryEx(processHandle_, (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegion region;
            region.baseAddress = (uint64_t)mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.isExecutable = (mbi.Protect & PAGE_EXECUTE) || 
                                   (mbi.Protect & PAGE_EXECUTE_READ) ||
                                   (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                                   (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
            region.isReadable = (mbi.Protect & PAGE_READONLY) || 
                               (mbi.Protect & PAGE_READWRITE) ||
                               (mbi.Protect & PAGE_EXECUTE_READ) ||
                               (mbi.Protect & PAGE_EXECUTE_READWRITE);
            region.isWritable = (mbi.Protect & PAGE_READWRITE) ||
                               (mbi.Protect & PAGE_EXECUTE_READWRITE);

            // Get module info if available
            getModuleInfoForAddress(region.baseAddress, region.moduleName);

            memoryRegions_.push_back(region);
        }

        address = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
    }

    std::cout << "[Debugger] Enumerated " << memoryRegions_.size() 
              << " memory regions" << std::endl;
}

void DebuggerIntegration::getModuleInfoForAddress(uint64_t address, std::string& moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(processHandle_, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(processHandle_, hMods[i], &modInfo, sizeof(modInfo))) {
                uint64_t modBase = (uint64_t)modInfo.lpBaseOfDll;
                uint64_t modEnd = modBase + modInfo.SizeOfImage;

                if (address >= modBase && address < modEnd) {
                    char modName[MAX_PATH];
                    if (GetModuleFileNameExA(processHandle_, hMods[i], modName, sizeof(modName))) {
                        moduleName = modName;
                    }
                    break;
                }
            }
        }
    }
}

void DebuggerIntegration::processDebugEvent(const DEBUG_EVENT& event) {
    threadId_ = event.dwThreadId;

    DebugEvent debugEvent;
    debugEvent.type = static_cast<DebugEventType>(event.dwDebugEventCode);
    debugEvent.processId = event.dwProcessId;
    debugEvent.threadId = event.dwThreadId;

    switch (event.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            const EXCEPTION_RECORD& exc = event.u.Exception.ExceptionRecord;
            debugEvent.address = (uint64_t)exc.ExceptionAddress;

            if (exc.ExceptionCode == EXCEPTION_BREAKPOINT) {
                handleBreakpoint(debugEvent);
            } else if (exc.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                handleSingleStep(debugEvent);
            } else {
                debugEvent.description = "Exception: 0x" + std::to_string(exc.ExceptionCode);
                std::cout << "[Debugger] Exception at 0x" << std::hex 
                          << debugEvent.address << std::dec << std::endl;
            }
            break;
        }

        case CREATE_THREAD_DEBUG_EVENT:
            debugEvent.description = "Thread created";
            debugEvent.address = (uint64_t)event.u.CreateThread.lpStartAddress;
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            debugEvent.description = "Process created";
            debugEvent.address = (uint64_t)event.u.CreateProcessInfo.lpStartAddress;
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            debugEvent.description = "Thread exited with code " + 
                                  std::to_string(event.u.ExitThread.dwExitCode);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            debugEvent.description = "Process exited with code " + 
                                  std::to_string(event.u.ExitProcess.dwExitCode);
            isAttached_ = false;
            break;

        case LOAD_DLL_DEBUG_EVENT:
            debugEvent.description = "DLL loaded";
            // Re-enumerate memory regions when DLL is loaded
            enumerateMemoryRegions();
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            debugEvent.description = "DLL unloaded";
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            debugEvent.description = "Debug output";
            break;

        default:
            debugEvent.description = "Unknown event: " + std::to_string(event.dwDebugEventCode);
            break;
    }

    // Call user callback if set
    if (eventCallback_) {
        eventCallback_(debugEvent);
    }

    // Pause execution for analysis
    if (debugEvent.type == DebugEventType::EXCEPTION) {
        isPaused_ = true;
    }
}

void DebuggerIntegration::handleBreakpoint(DebugEvent& event) {
    event.description = "Breakpoint hit";

    // Find which breakpoint was hit
    for (auto& [id, bp] : breakpoints_) {
        if (bp.address == event.address && bp.isActive) {
            // Restore original byte
            SIZE_T bytesWritten;
            WriteProcessMemory(processHandle_, (LPVOID)bp.address, 
                               &bp.originalByte, 1, &bytesWritten);
            FlushInstructionCache(processHandle_, (LPCVOID)bp.address, 1);

            // Get thread context for analysis
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_FULL;
            
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.threadId);
            if (hThread && GetThreadContext(hThread, &ctx)) {
                // Analyze pattern at breakpoint
                auto context = readMemoryContext(event.address - 32, 64);
                
                LiveAnalysisResult result;
                result.address = event.address;
                result.pattern = bp.pattern;
                result.confidence = bp.pattern.confidence;
                result.timestamp = GetTickCount64();
                result.threadId = event.threadId;
                result.context = context;

                // Call pattern callback
                if (bp.callback) {
                    bp.callback(result);
                }

                CloseHandle(hThread);
            }

            // Set single-step to re-enable breakpoint after execution
            // (simplified - in production would use trap flag)
            break;
        }
    }
}

void DebuggerIntegration::handleSingleStep(DebugEvent& event) {
    event.description = "Single step";
    
    // Re-enable breakpoints after single step
    for (auto& [id, bp] : breakpoints_) {
        if (bp.isActive) {
            uint8_t int3 = 0xCC;
            SIZE_T bytesWritten;
            DWORD oldProtect;
            
            VirtualProtectEx(processHandle_, (LPVOID)bp.address, 1, 
                           PAGE_EXECUTE_READWRITE, &oldProtect);
            WriteProcessMemory(processHandle_, (LPVOID)bp.address, &int3, 1, &bytesWritten);
            VirtualProtectEx(processHandle_, (LPVOID)bp.address, 1, oldProtect, &oldProtect);
            FlushInstructionCache(processHandle_, (LPCVOID)bp.address, 1);
        }
    }
}

void DebuggerIntegration::checkMemoryScanBreakpoints() {
    uint64_t currentTime = GetTickCount64();

    for (auto& [id, scanBp] : memoryScanBreakpoints_) {
        if (!scanBp.isActive) continue;
        if (currentTime - scanBp.lastScanTime < scanBp.scanIntervalMs) continue;

        scanBp.lastScanTime = currentTime;

        // Scan all memory regions
        for (const auto& region : memoryRegions_) {
            if (!region.isReadable) continue;

            auto results = scanForPatterns(
                {{"scan_pattern", scanBp.patternBytes, 1.0, PatternType::ORIGINAL}},
                region.baseAddress,
                region.size
            );

            for (const auto& result : results) {
                if (scanBp.callback) {
                    scanBp.callback(result);
                }
            }
        }
    }
}

std::vector<size_t> DebuggerIntegration::simdScan(const uint8_t* data, size_t dataSize,
                                                   const uint8_t* pattern, size_t patternSize) {
    std::vector<size_t> matches;

    if (patternSize == 0 || dataSize < patternSize) {
        return matches;
    }

    // Use AVX2 for 32-byte parallel comparison
    if (patternSize <= 32) {
        // Pad pattern to 32 bytes
        alignas(32) uint8_t paddedPattern[32] = {0};
        memcpy(paddedPattern, pattern, patternSize);
        
        __m256i patternVec = _mm256_load_si256((__m256i*)paddedPattern);
        
        for (size_t i = 0; i <= dataSize - patternSize; i++) {
            __m256i dataVec = _mm256_loadu_si256((__m256i*)(data + i));
            __m256i cmp = _mm256_cmpeq_epi8(dataVec, patternVec);
            int mask = _mm256_movemask_epi8(cmp);
            
            // Check if first patternSize bytes match
            int patternMask = (1 << patternSize) - 1;
            if ((mask & patternMask) == patternMask) {
                matches.push_back(i);
            }
        }
    } else {
        // Fallback to scalar scan for larger patterns
        for (size_t i = 0; i <= dataSize - patternSize; i++) {
            if (memcmp(data + i, pattern, patternSize) == 0) {
                matches.push_back(i);
            }
        }
    }

    return matches;
}

} // namespace Reverse
} // namespace RawrXD
