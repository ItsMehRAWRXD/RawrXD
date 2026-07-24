//=============================================================================
// Flame Graph Generator Implementation
//=============================================================================

#include "flame_graph.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>

namespace RawrXD {
namespace Profiling {

//=============================================================================
// FlameGraphProfiler Implementation
//=============================================================================

FlameGraphProfiler::FlameGraphProfiler()
    : is_running_(false)
    , sample_interval_ms_(10)
    , max_samples_(100000)
    , total_duration_ns_(0)
    , stop_sampling_(false)
{
}

FlameGraphProfiler::~FlameGraphProfiler() {
    Stop();
}

void FlameGraphProfiler::SetSampleInterval(uint32_t interval_ms) {
    sample_interval_ms_ = interval_ms;
}

void FlameGraphProfiler::SetMaxSamples(size_t max_samples) {
    max_samples_ = max_samples;
}

void FlameGraphProfiler::Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (is_running_) return;
    
    is_running_ = true;
    start_time_ = std::chrono::high_resolution_clock::now();
    stop_sampling_ = false;
    
    // Start background sampling thread
    sampling_thread_ = std::thread(&FlameGraphProfiler::SamplingThread, this);
}

void FlameGraphProfiler::Stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_running_) return;
        
        is_running_ = false;
        stop_sampling_ = true;
    }
    
    if (sampling_thread_.joinable()) {
        sampling_thread_.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    total_duration_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end_time - start_time_).count();
}

void FlameGraphProfiler::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    samples_.clear();
    while (!call_stack_.empty()) {
        call_stack_.pop();
    }
    total_duration_ns_ = 0;
}

void FlameGraphProfiler::EnterFrame(const char* name, const char* file, uint32_t line) {
    if (!is_running_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    Frame frame;
    frame.name = name;
    frame.file = file;
    frame.line = line;
    frame.enter_time = std::chrono::high_resolution_clock::now();
    
    call_stack_.push(frame);
}

void FlameGraphProfiler::ExitFrame() {
    if (!is_running_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (call_stack_.empty()) return;
    
    auto exit_time = std::chrono::high_resolution_clock::now();
    auto& frame = call_stack_.top();
    
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
        exit_time - frame.enter_time).count();
    
    // Create sample from current stack
    Sample sample;
    sample.count = 1;
    sample.duration_ns = duration;
    
    // Copy stack
    std::stack<Frame> temp_stack = call_stack_;
    while (!temp_stack.empty()) {
        const auto& f = temp_stack.top();
        sample.stack.push_back({f.name, f.file, f.line});
        temp_stack.pop();
    }
    
    // Reverse to get root->leaf order
    std::reverse(sample.stack.begin(), sample.stack.end());
    
    samples_.push_back(sample);
    
    // Limit samples
    if (samples_.size() > max_samples_) {
        samples_.erase(samples_.begin());
    }
    
    call_stack_.pop();
}

void FlameGraphProfiler::TakeSample() {
    if (!is_running_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Capture current stack
    Sample sample;
    sample.count = 1;
    sample.duration_ns = 0;
    
    std::stack<Frame> temp_stack = call_stack_;
    while (!temp_stack.empty()) {
        const auto& f = temp_stack.top();
        sample.stack.push_back({f.name, f.file, f.line});
        temp_stack.pop();
    }
    
    std::reverse(sample.stack.begin(), sample.stack.end());
    
    if (!sample.stack.empty()) {
        samples_.push_back(sample);
    }
}

void FlameGraphProfiler::SamplingThread() {
    while (!stop_sampling_) {
        TakeSample();
        std::this_thread::sleep_for(std::chrono::milliseconds(sample_interval_ms_));
    }
}

void FlameGraphProfiler::GenerateFoldedStacks(const char* filename) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(filename);
    if (!file.is_open()) return;
    
    // Aggregate samples
    std::unordered_map<std::string, uint64_t> folded;
    
    for (const auto& sample : samples_) {
        std::string stack_str;
        for (size_t i = 0; i < sample.stack.size(); ++i) {
            if (i > 0) stack_str += ";";
            stack_str += sample.stack[i].name;
        }
        folded[stack_str] += sample.count;
    }
    
    // Write folded format
    for (const auto& [stack, count] : folded) {
        file << stack << " " << count << "\n";
    }
}

void FlameGraphProfiler::GenerateSpeedscopeJSON(const char* filename) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(filename);
    if (!file.is_open()) return;
    
    file << "{\n";
    file << "  \"version\": \"0.0.1\",\n";
    file << "  \"activeProfileIndex\": 0,\n";
    file << "  \"profiles\": [\n";
    file << "    {\n";
    file << "      \"type\": \"sampled\",\n";
    file << "      \"name\": \"RawrXD Profile\",\n";
    file << "      \"unit\": \"none\",\n";
    
    // Collect unique frames
    std::vector<StackFrame> unique_frames;
    std::unordered_map<std::string, size_t> frame_indices;
    
    for (const auto& sample : samples_) {
        for (const auto& frame : sample.stack) {
            std::string key = std::string(frame.name) + ":" + std::string(frame.file);
            if (frame_indices.find(key) == frame_indices.end()) {
                frame_indices[key] = unique_frames.size();
                unique_frames.push_back(frame);
            }
        }
    }
    
    // Write frames
    file << "      \"frames\": [\n";
    for (size_t i = 0; i < unique_frames.size(); ++i) {
        const auto& f = unique_frames[i];
        file << "        {\"name\": \"" << f.name << "\"";
        if (f.file) {
            file << ", \"file\": \"" << f.file << "\"";
        }
        file << "}";
        if (i < unique_frames.size() - 1) file << ",";
        file << "\n";
    }
    file << "      ],\n";
    
    // Write samples
    file << "      \"samples\": [\n";
    for (size_t i = 0; i < samples_.size(); ++i) {
        const auto& sample = samples_[i];
        file << "        [";
        for (size_t j = 0; j < sample.stack.size(); ++j) {
            const auto& frame = sample.stack[j];
            std::string key = std::string(frame.name) + ":" + std::string(frame.file);
            file << frame_indices[key];
            if (j < sample.stack.size() - 1) file << ", ";
        }
        file << "]";
        if (i < samples_.size() - 1) file << ",";
        file << "\n";
    }
    file << "      ]\n";
    file << "    }\n";
    file << "  ]\n";
    file << "}\n";
}

void FlameGraphProfiler::GenerateChromeTrace(const char* filename) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(filename);
    if (!file.is_open()) return;
    
    file << "[\n";
    
    // Write samples as complete events
    for (size_t i = 0; i < samples_.size(); ++i) {
        const auto& sample = samples_[i];
        if (sample.stack.empty()) continue;
        
        // Use duration from sample
        uint64_t ts = i * 1000; // Fake timestamp
        uint64_t dur = sample.duration_ns / 1000; // Convert to microseconds
        
        file << "  {\"name\": \"" << sample.stack.back().name << "\",";
        file << " \"ph\": \"X\",";
        file << " \"ts\": " << ts << ",";
        file << " \"dur\": " << dur << ",";
        file << " \"pid\": 1, \"tid\": 1}";
        
        if (i < samples_.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "]\n";
}

size_t FlameGraphProfiler::GetSampleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return samples_.size();
}

uint64_t FlameGraphProfiler::GetTotalDurationNs() const {
    return total_duration_ns_;
}

//=============================================================================
// ScopedFlameProfile Implementation
//=============================================================================

ScopedFlameProfile::ScopedFlameProfile(FlameGraphProfiler& profiler, 
                                        const char* name, 
                                        const char* file, 
                                        uint32_t line)
    : profiler_(profiler)
{
    profiler_.EnterFrame(name, file, line);
}

ScopedFlameProfile::~ScopedFlameProfile() {
    profiler_.ExitFrame();
}

//=============================================================================
// Global Profiler
//=============================================================================

FlameGraphProfiler& GetGlobalFlameProfiler() {
    static FlameGraphProfiler instance;
    return instance;
}

//=============================================================================
// Stack Trace Capture
//=============================================================================

#ifdef _WIN32

std::vector<StackFrame> CaptureStackTrace(size_t skip_frames, size_t max_depth) {
    std::vector<StackFrame> frames;
    
    // Windows stack walking using DbgHelp
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();
    
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);
    
    STACKFRAME64 stack_frame;
    memset(&stack_frame, 0, sizeof(STACKFRAME64));
    
#ifdef _M_X64
    stack_frame.AddrPC.Offset = context.Rip;
    stack_frame.AddrPC.Mode = AddrModeFlat;
    stack_frame.AddrFrame.Offset = context.Rbp;
    stack_frame.AddrFrame.Mode = AddrModeFlat;
    stack_frame.AddrStack.Offset = context.Rsp;
    stack_frame.AddrStack.Mode = AddrModeFlat;
#else
    stack_frame.AddrPC.Offset = context.Eip;
    stack_frame.AddrPC.Mode = AddrModeFlat;
    stack_frame.AddrFrame.Offset = context.Ebp;
    stack_frame.AddrFrame.Mode = AddrModeFlat;
    stack_frame.AddrStack.Offset = context.Esp;
    stack_frame.AddrStack.Mode = AddrModeFlat;
#endif
    
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
    symbol->MaxNameLen = 255;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    
    for (size_t i = 0; i < skip_frames + max_depth; ++i) {
        if (!StackWalk64(
#ifdef _M_X64
            IMAGE_FILE_MACHINE_AMD64,
#else
            IMAGE_FILE_MACHINE_I386,
#endif
            process, thread, &stack_frame, &context, NULL, 
            SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }
        
        if (i >= skip_frames) {
            StackFrame frame;
            frame.name = "unknown";
            frame.file = nullptr;
            frame.line = 0;
            
            if (SymFromAddr(process, stack_frame.AddrPC.Offset, 0, symbol)) {
                static char demangled[256];
                strncpy(demangled, symbol->Name, 255);
                demangled[255] = '\0';
                frame.name = _strdup(demangled);
            }
            
            frames.push_back(frame);
        }
    }
    
    free(symbol);
    return frames;
}

#else // Linux

std::vector<StackFrame> CaptureStackTrace(size_t skip_frames, size_t max_depth) {
    std::vector<StackFrame> frames;
    
    void* buffer[max_depth + skip_frames];
    int nptrs = backtrace(buffer, max_depth + skip_frames);
    char** strings = backtrace_symbols(buffer, nptrs);
    
    if (strings == nullptr) {
        return frames;
    }
    
    for (int i = skip_frames; i < nptrs; ++i) {
        StackFrame frame;
        frame.name = strings[i];
        frame.file = nullptr;
        frame.line = 0;
        
        // Try to demangle
        std::string demangled = DemangleSymbol(strings[i]);
        if (!demangled.empty()) {
            frame.name = _strdup(demangled.c_str());
        }
        
        frames.push_back(frame);
    }
    
    free(strings);
    return frames;
}

#endif

std::string DemangleSymbol(const char* mangled) {
#ifdef __linux__
    int status = 0;
    char* demangled = abi::__cxa_demangle(mangled, nullptr, nullptr, &status);
    if (status == 0 && demangled) {
        std::string result(demangled);
        free(demangled);
        return result;
    }
#endif
    return std::string(mangled);
}

} // namespace Profiling
} // namespace RawrXD
