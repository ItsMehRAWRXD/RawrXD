// ============================================================================
// DebuggerPatternIntegration.cpp - Debugger Integration Implementation
// ============================================================================

#include "DebuggerPatternIntegration.hpp"
#include "ComprehensivePatternGenerator.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

namespace RawrXD::Reverse {

// ============================================================================
// Implementation Class
// ============================================================================

class DebuggerPatternIntegration::Impl {
public:
    DebuggerState state_ = DebuggerState::DISCONNECTED;
    DebuggerConfig config_;
    IntegrationStats stats_;
    
    std::function<void(const PatternMatchInMemory&)> on_pattern_found_;
    std::function<void(const BreakpointPattern&)> on_breakpoint_hit_;
    std::function<void(uint64_t, size_t, MemoryAccessType)> on_memory_access_;
    
    std::vector<BreakpointPattern> breakpoints_;
    std::vector<MemoryRegionInfo> memory_regions_;
    
#ifdef _WIN32
    HANDLE process_handle_ = nullptr;
    uint32_t target_pid_ = 0;
#endif
    
    Impl() = default;
    ~Impl() {
        disconnect();
    }
    
    bool connectToProcess(uint32_t pid) {
#ifdef _WIN32
        if (process_handle_ != nullptr) {
            CloseHandle(process_handle_);
        }
        
        process_handle_ = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            FALSE, pid);
        
        if (process_handle_ == nullptr) {
            state_ = DebuggerState::ERROR;
            return false;
        }
        
        target_pid_ = pid;
        state_ = DebuggerState::ATTACHED;
        
        // Enumerate memory regions
        memory_regions_ = enumerateMemoryRegionsInternal();
        
        return true;
#else
        state_ = DebuggerState::ERROR;
        return false;
#endif
    }
    
    bool disconnect() {
#ifdef _WIN32
        if (process_handle_ != nullptr) {
            CloseHandle(process_handle_);
            process_handle_ = nullptr;
        }
        target_pid_ = 0;
#endif
        state_ = DebuggerState::DISCONNECTED;
        breakpoints_.clear();
        memory_regions_.clear();
        return true;
    }
    
    std::vector<MemoryRegionInfo> enumerateMemoryRegionsInternal() {
        std::vector<MemoryRegionInfo> regions;
        
#ifdef _WIN32
        if (process_handle_ == nullptr) return regions;
        
        MEMORY_BASIC_INFORMATION mbi;
        uint8_t* addr = nullptr;
        
        while (VirtualQueryEx(process_handle_, addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                MemoryRegionInfo region{};
                region.base_address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.is_readable = (mbi.Protect & PAGE_READONLY) || 
                                    (mbi.Protect & PAGE_READWRITE) ||
                                    (mbi.Protect & PAGE_EXECUTE_READ) ||
                                    (mbi.Protect & PAGE_EXECUTE_READWRITE);
                region.is_writable = (mbi.Protect & PAGE_READWRITE) ||
                                    (mbi.Protect & PAGE_WRITECOPY) ||
                                    (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                                    (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
                region.is_executable = (mbi.Protect & PAGE_EXECUTE) ||
                                        (mbi.Protect & PAGE_EXECUTE_READ) ||
                                        (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                                        (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
                
                // Get module name if available
                char module_name[MAX_PATH];
                if (GetModuleFileNameExA(process_handle_, nullptr, module_name, MAX_PATH)) {
                    region.name = module_name;
                } else {
                    region.name = "unnamed_region";
                }
                
                regions.push_back(region);
            }
            
            addr = reinterpret_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
        }
#endif
        
        return regions;
    }
    
    std::vector<uint8_t> readMemory(uint64_t address, size_t size) {
        std::vector<uint8_t> buffer(size);
        
#ifdef _WIN32
        if (process_handle_ == nullptr) return {};
        
        SIZE_T bytes_read;
        if (!ReadProcessMemory(process_handle_, reinterpret_cast<LPCVOID>(address), 
                               buffer.data(), size, &bytes_read)) {
            return {};
        }
        
        buffer.resize(bytes_read);
#endif
        
        return buffer;
    }
    
    std::vector<PatternMatchInMemory> scanMemoryRegionInternal(
        uint64_t base_address,
        size_t size,
        const std::vector<ComprehensivePattern>& patterns) {
        
        std::vector<PatternMatchInMemory> matches;
        
        auto data = readMemory(base_address, size);
        if (data.empty()) return matches;
        
        for (const auto& pattern : patterns) {
            if (pattern.bytes.empty()) continue;
            
            // Simple byte-by-byte search
            for (size_t i = 0; i + pattern.bytes.size() <= data.size(); ++i) {
                bool match = true;
                for (size_t j = 0; j < pattern.bytes.size(); ++j) {
                    if (data[i + j] != pattern.bytes[j]) {
                        match = false;
                        break;
                    }
                }
                
                if (match) {
                    PatternMatchInMemory pmm{};
                    pmm.pattern_id = pattern.id;
                    pmm.address = base_address + i;
                    pmm.length = pattern.bytes.size();
                    pmm.type = pattern.type;
                    pmm.confidence = pattern.confidence;
                    pmm.matched_bytes = pattern.bytes;
                    pmm.region_name = "scanned_region";
                    pmm.is_hotspot = false;
                    
                    matches.push_back(pmm);
                    
                    if (on_pattern_found_) {
                        on_pattern_found_(pmm);
                    }
                }
            }
        }
        
        return matches;
    }
};

// ============================================================================
// Public Implementation
// ============================================================================

DebuggerPatternIntegration::DebuggerPatternIntegration() 
    : pImpl(std::make_unique<Impl>()) {}

DebuggerPatternIntegration::~DebuggerPatternIntegration() = default;

bool DebuggerPatternIntegration::connectToDebugger(const std::string& debugger_path) {
    // Placeholder for external debugger connection
    pImpl->state_ = DebuggerState::CONNECTED;
    return true;
}

bool DebuggerPatternIntegration::connectToProcess(uint32_t pid) {
    return pImpl->connectToProcess(pid);
}

bool DebuggerPatternIntegration::connectToProcess(const std::string& process_name) {
#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    uint32_t pid = 0;
    if (Process32First(snapshot, &pe)) {
        do {
            if (process_name == pe.szExeFile) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    
    if (pid == 0) return false;
    return connectToProcess(pid);
#else
    return false;
#endif
}

bool DebuggerPatternIntegration::disconnect() {
    return pImpl->disconnect();
}

bool DebuggerPatternIntegration::isConnected() const {
    return pImpl->state_ == DebuggerState::CONNECTED ||
           pImpl->state_ == DebuggerState::ATTACHED;
}

DebuggerState DebuggerPatternIntegration::getState() const {
    return pImpl->state_;
}

std::vector<PatternMatchInMemory> DebuggerPatternIntegration::scanMemoryRegion(
    uint64_t base_address,
    size_t size,
    const std::vector<ComprehensivePattern>& patterns) {
    
    auto start = std::chrono::high_resolution_clock::now();
    auto matches = pImpl->scanMemoryRegionInternal(base_address, size, patterns);
    auto end = std::chrono::high_resolution_clock::now();
    
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    pImpl->stats_.total_scans++;
    pImpl->stats_.total_matches_found += matches.size();
    pImpl->stats_.total_scan_time_ms += duration;
    
    return matches;
}

std::vector<PatternMatchInMemory> DebuggerPatternIntegration::scanAllMemoryRegions(
    const std::vector<ComprehensivePattern>& patterns) {
    
    std::vector<PatternMatchInMemory> all_matches;
    
    auto regions = enumerateMemoryRegions();
    for (const auto& region : regions) {
        auto matches = scanMemoryRegion(region.base_address, region.size, patterns);
        for (auto& match : matches) {
            match.region_name = region.name;
            all_matches.push_back(match);
        }
    }
    
    pImpl->stats_.memory_regions_scanned = regions.size();
    return all_matches;
}

std::vector<PatternMatchInMemory> DebuggerPatternIntegration::scanExecutableRegions(
    const std::vector<ComprehensivePattern>& patterns) {
    
    std::vector<PatternMatchInMemory> all_matches;
    
    auto regions = enumerateMemoryRegions();
    for (const auto& region : regions) {
        if (region.is_executable) {
            auto matches = scanMemoryRegion(region.base_address, region.size, patterns);
            for (auto& match : matches) {
                match.region_name = region.name;
                all_matches.push_back(match);
            }
        }
    }
    
    return all_matches;
}

LivePatternAnalysis DebuggerPatternIntegration::performLiveAnalysis(
    const std::vector<ComprehensivePattern>& patterns,
    size_t duration_ms) {
    
    LivePatternAnalysis analysis{};
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Scan all regions
    analysis.active_matches = scanAllMemoryRegions(patterns);
    analysis.scanned_regions = enumerateMemoryRegions();
    
    auto end = std::chrono::high_resolution_clock::now();
    analysis.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    analysis.total_bytes_scanned = 0;
    for (const auto& region : analysis.scanned_regions) {
        analysis.total_bytes_scanned += region.size;
    }
    analysis.patterns_found = analysis.active_matches.size();
    analysis.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    return analysis;
}

bool DebuggerPatternIntegration::setPatternBreakpoint(
    uint64_t address,
    const std::string& pattern_id,
    const std::string& condition) {
    
    BreakpointPattern bp{};
    bp.address = address;
    bp.pattern_id = pattern_id;
    bp.condition = condition;
    bp.enabled = true;
    bp.hit_count = 0;
    
    pImpl->breakpoints_.push_back(bp);
    return true;
}

bool DebuggerPatternIntegration::removePatternBreakpoint(uint64_t address) {
    auto it = std::remove_if(pImpl->breakpoints_.begin(), pImpl->breakpoints_.end(),
        [address](const BreakpointPattern& bp) { return bp.address == address; });
    
    if (it != pImpl->breakpoints_.end()) {
        pImpl->breakpoints_.erase(it, pImpl->breakpoints_.end());
        return true;
    }
    return false;
}

void DebuggerPatternIntegration::clearAllBreakpoints() {
    pImpl->breakpoints_.clear();
}

std::vector<BreakpointPattern> DebuggerPatternIntegration::getActiveBreakpoints() const {
    return pImpl->breakpoints_;
}

std::vector<PatternMatchInMemory> DebuggerPatternIntegration::detectHotspots(size_t threshold) {
    // Placeholder - would track memory access patterns
    std::vector<PatternMatchInMemory> hotspots;
    return hotspots;
}

std::vector<MemoryRegionInfo> DebuggerPatternIntegration::enumerateMemoryRegions() {
    return pImpl->enumerateMemoryRegionsInternal();
}

MemoryRegionInfo DebuggerPatternIntegration::getMemoryRegionInfo(uint64_t address) const {
    for (const auto& region : pImpl->memory_regions_) {
        if (address >= region.base_address && 
            address < region.base_address + region.size) {
            return region;
        }
    }
    return MemoryRegionInfo{};
}

bool DebuggerPatternIntegration::injectPatternAtAddress(
    uint64_t address,
    const std::vector<uint8_t>& pattern_bytes) {
    
#ifdef _WIN32
    if (pImpl->process_handle_ == nullptr) return false;
    
    SIZE_T written;
    return WriteProcessMemory(
        pImpl->process_handle_,
        reinterpret_cast<LPVOID>(address),
        pattern_bytes.data(),
        pattern_bytes.size(),
        &written) != 0;
#else
    return false;
#endif
}

std::string DebuggerPatternIntegration::exportScanResults(
    const std::vector<PatternMatchInMemory>& matches) {
    
    std::ostringstream oss;
    oss << "Pattern Scan Results\n";
    oss << "====================\n\n";
    oss << "Total matches: " << matches.size() << "\n\n";
    
    for (const auto& match : matches) {
        oss << "Pattern: " << match.pattern_id << "\n";
        oss << "  Address: 0x" << std::hex << match.address << std::dec << "\n";
        oss << "  Length: " << match.length << "\n";
        oss << "  Type: " << formatPatternType(match.type) << "\n";
        oss << "  Confidence: " << std::fixed << std::setprecision(2) << match.confidence << "\n";
        oss << "  Region: " << match.region_name << "\n";
        oss << "  Bytes: " << formatBytes(match.matched_bytes) << "\n\n";
    }
    
    return oss.str();
}

bool DebuggerPatternIntegration::exportToDebuggerFormat(
    const std::vector<PatternMatchInMemory>& matches,
    const std::string& output_path) {
    
    std::ofstream file(output_path);
    if (!file.is_open()) return false;
    
    file << exportScanResults(matches);
    file.close();
    
    return true;
}

void DebuggerPatternIntegration::setOnPatternFound(
    std::function<void(const PatternMatchInMemory&)> callback) {
    pImpl->on_pattern_found_ = callback;
}

void DebuggerPatternIntegration::setOnBreakpointHit(
    std::function<void(const BreakpointPattern&)> callback) {
    pImpl->on_breakpoint_hit_ = callback;
}

void DebuggerPatternIntegration::setOnMemoryAccess(
    std::function<void(uint64_t, size_t, MemoryAccessType)> callback) {
    pImpl->on_memory_access_ = callback;
}

void DebuggerPatternIntegration::setConfig(const DebuggerConfig& config) {
    pImpl->config_ = config;
}

DebuggerConfig DebuggerPatternIntegration::getConfig() const {
    return pImpl->config_;
}

DebuggerPatternIntegration::IntegrationStats DebuggerPatternIntegration::getStats() const {
    return pImpl->stats_;
}

void DebuggerPatternIntegration::resetStats() {
    pImpl->stats_ = {};
}

// ============================================================================
// Pattern Debugger Commands
// ============================================================================

std::string PatternDebuggerCommands::cmdPatternScan(
    const std::vector<std::string>& args,
    DebuggerPatternIntegration* integration) {
    
    if (args.size() < 2) {
        return "Usage: pattern_scan <address> <size>\n";
    }
    
    uint64_t address = std::stoull(args[0], nullptr, 0);
    size_t size = std::stoull(args[1]);
    
    // Create some test patterns
    std::vector<ComprehensivePattern> patterns;
    // Would load patterns from somewhere
    
    auto matches = integration->scanMemoryRegion(address, size, patterns);
    
    std::ostringstream oss;
    oss << "Found " << matches.size() << " patterns\n";
    for (const auto& match : matches) {
        oss << "  0x" << std::hex << match.address << std::dec 
            << ": " << match.pattern_id << "\n";
    }
    
    return oss.str();
}

std::string PatternDebuggerCommands::cmdPatternFind(
    const std::vector<std::string>& args,
    DebuggerPatternIntegration* integration) {
    return "pattern_find: Not yet implemented\n";
}

std::string PatternDebuggerCommands::cmdPatternBreakpoint(
    const std::vector<std::string>& args,
    DebuggerPatternIntegration* integration) {
    return "pattern_breakpoint: Not yet implemented\n";
}

std::string PatternDebuggerCommands::cmdPatternHotspots(
    const std::vector<std::string>& args,
    DebuggerPatternIntegration* integration) {
    return "pattern_hotspots: Not yet implemented\n";
}

std::string PatternDebuggerCommands::cmdPatternExport(
    const std::vector<std::string>& args,
    DebuggerPatternIntegration* integration) {
    return "pattern_export: Not yet implemented\n";
}

std::string PatternDebuggerCommands::cmdPatternInfo(
    const std::vector<std::string>& args,
    const std::vector<ComprehensivePattern>& patterns) {
    
    std::ostringstream oss;
    oss << "Pattern Database Info\n";
    oss << "=====================\n";
    oss << "Total patterns: " << patterns.size() << "\n\n";
    
    for (const auto& p : patterns) {
        oss << "ID: " << p.id << "\n";
        oss << "  Name: " << p.name << "\n";
        oss << "  Type: " << formatPatternType(p.type) << "\n";
        oss << "  Confidence: " << p.confidence << "\n";
        oss << "  Size: " << p.bytes.size() << " bytes\n\n";
    }
    
    return oss.str();
}

std::string PatternDebuggerCommands::cmdPatternCompare(
    const std::vector<std::string>& args,
    const ComprehensivePattern& a,
    const ComprehensivePattern& b) {
    
    ComprehensivePatternGenerator gen;
    auto comp = gen.comparePatterns(a, b);
    
    std::ostringstream oss;
    oss << "Pattern Comparison\n";
    oss << "==================\n";
    oss << "Hamming distance: " << comp.hamming_distance << "\n";
    oss << "Similarity: " << std::fixed << std::setprecision(4) << comp.similarity << "\n";
    oss << "Cosine similarity: " << comp.cosine_similarity << "\n";
    oss << "Correlation: " << comp.correlation_coefficient << "\n";
    
    return oss.str();
}

std::string PatternDebuggerCommands::getHelpText() {
    return R"(
Pattern Debugger Commands
=========================

pattern_scan <address> <size>     - Scan memory region for patterns
pattern_find <pattern_id>         - Find specific pattern in memory
pattern_breakpoint <address> <id> - Set breakpoint on pattern
pattern_hotspots [threshold]        - Detect frequently accessed patterns
pattern_export <path>               - Export scan results
pattern_info                        - Show pattern database info
pattern_compare <id1> <id2>         - Compare two patterns

Type 'help <command>' for detailed usage.
)";
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string formatAddress(uint64_t address) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(16) << address;
    return oss.str();
}

std::string formatBytes(const std::vector<uint8_t>& bytes, size_t max_len) {
    std::ostringstream oss;
    size_t len = std::min(bytes.size(), max_len);
    
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) 
            << static_cast<int>(bytes[i]);
        if (i < len - 1) oss << " ";
    }
    
    if (bytes.size() > max_len) {
        oss << " ...";
    }
    
    return oss.str();
}

std::string formatPatternType(PatternType type) {
    switch (type) {
        case PatternType::ORIGINAL: return "ORIGINAL";
        case PatternType::INVERSE: return "INVERSE";
        case PatternType::COMPLEMENT: return "COMPLEMENT";
        case PatternType::REVERSED: return "REVERSED";
        case PatternType::XOR_VARIANT: return "XOR_VARIANT";
        case PatternType::ANTI_PATTERN: return "ANTI_PATTERN";
        case PatternType::DISCOVERED: return "DISCOVERED";
        case PatternType::CONTEXT_INVERSE: return "CONTEXT_INVERSE";
        case PatternType::SLIDING_WINDOW: return "SLIDING_WINDOW";
        case PatternType::FREQUENCY_BASED: return "FREQUENCY_BASED";
        case PatternType::TRANSITION_BASED: return "TRANSITION_BASED";
        case PatternType::ENTROPY_BASED: return "ENTROPY_BASED";
        case PatternType::HYBRID: return "HYBRID";
        default: return "UNKNOWN";
    }
}

} // namespace RawrXD::Reverse
