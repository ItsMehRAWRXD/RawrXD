// RawrXD-Script Trace Collector Implementation
// Generates deterministic fingerprints from execution traces

#include "trace_collector.hpp"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <cmath>

namespace RawrXD {
namespace Script {

// Global trace buffer (shared with MASM)
TraceBuffer g_trace_buffer;

// Thread-local collector instance
thread_local TraceCollector* g_collector = nullptr;

// Known bug patterns (populated as discovered)
const TracePattern kKnownPatterns[] = {
    // Placeholder patterns - will be populated from actual bugs
    {"IC_MISS_PATTERN", "Inline cache miss detected", 0x0, 1},
    {"ARITH_OVERFLOW", "Arithmetic overflow in operation", 0x0, 2},
    {"NULL_DEREF", "Null pointer dereference", 0x0, 3},
    {"STACK_IMBALANCE", "Stack pointer imbalance detected", 0x0, 2},
    {"REG_CORRUPTION", "Register value corruption", 0x0, 3},
};

const size_t kKnownPatternCount = sizeof(kKnownPatterns) / sizeof(kKnownPatterns[0]);

// C API Implementation
extern "C" {

void TraceCollector_Enable() {
    g_trace_buffer.active = 1;
}

void TraceCollector_Disable() {
    g_trace_buffer.active = 0;
}

void TraceCollector_Reset() {
    g_trace_buffer.reset();
    if (g_collector) {
        g_collector->reset();
    }
}

void TraceCollector_RecordOpcode(uint64_t pc, uint8_t opcode) {
    if (!g_trace_buffer.active) return;
    
    uint64_t idx = g_trace_buffer.head++;
    idx &= TRACE_MASK;
    
    TraceEvent& evt = g_trace_buffer.events[idx];
    evt.data = (pc << 8) | opcode;
    evt.timestamp = static_cast<uint32_t>(g_trace_buffer.instruction_counter++);
    evt.type = static_cast<uint16_t>(TraceEventType::OpcodeDispatch);
    evt.reserved = 0;
}

void TraceCollector_RecordRegister(uint8_t reg_idx, uint64_t value, uint8_t is_write) {
    if (!g_trace_buffer.active) return;
    
    uint64_t idx = g_trace_buffer.head++;
    idx &= TRACE_MASK;
    
    TraceEvent& evt = g_trace_buffer.events[idx];
    // Pack register index and operation into data
    evt.data = (static_cast<uint64_t>(reg_idx) << 56) | (value & 0x00FFFFFFFFFFFFFFULL);
    evt.timestamp = static_cast<uint32_t>(g_trace_buffer.instruction_counter++);
    evt.type = is_write ? 
        static_cast<uint16_t>(TraceEventType::RegisterWrite) :
        static_cast<uint16_t>(TraceEventType::RegisterRead);
    evt.reserved = 0;
}

uint64_t TraceCollector_GetFingerprintA() {
    if (!g_collector) return 0;
    return g_collector->generateFingerprint().hash_a;
}

uint64_t TraceCollector_GetFingerprintB() {
    if (!g_collector) return 0;
    return g_collector->generateFingerprint().hash_b;
}

uint32_t TraceCollector_GetEventCount() {
    return static_cast<uint32_t>(g_trace_buffer.head);
}

} // extern "C"

// TraceBuffer methods
void TraceBuffer::push_event(uint64_t data, uint16_t type) {
    if (!active) return;
    
    uint64_t idx = head++;
    idx &= TRACE_MASK;
    
    TraceEvent& evt = events[idx];
    evt.data = data;
    evt.timestamp = static_cast<uint32_t>(instruction_counter++);
    evt.type = type;
    evt.reserved = 0;
}

// TraceCollector Implementation
TraceCollector::TraceCollector() : buffer_(g_trace_buffer), events_processed_(0) {
    g_collector = this;
}

TraceCollector::~TraceCollector() {
    if (g_collector == this) {
        g_collector = nullptr;
    }
}

void TraceCollector::start() {
    buffer_.reset();
    hasher_a_ = HashState();
    hasher_b_ = HashState();
    events_processed_ = 0;
    
    // Initialize secondary hasher with different seed
    hasher_b_.value = 0x84222225cbf29ce4ULL; // Reversed FNV offset
}

void TraceCollector::stop() {
    buffer_.active = 0;
}

void TraceCollector::reset() {
    start();
}

void TraceCollector::recordOpcode(uint64_t pc, uint8_t opcode) {
    TraceCollector_RecordOpcode(pc, opcode);
    
    // Update hashers immediately for rolling fingerprint
    uint64_t event_data = (pc << 8) | opcode;
    hasher_a_.update(event_data);
    hasher_b_.update(event_data ^ 0x9E3779B97F4A7C15ULL); // Golden ratio mix
}

void TraceCollector::recordRegisterRead(uint8_t reg, uint64_t value) {
    TraceCollector_RecordRegister(reg, value, 0);
    
    uint64_t event_data = (static_cast<uint64_t>(reg) << 56) | (value & 0x00FFFFFFFFFFFFFFULL);
    hasher_a_.update(event_data);
    hasher_b_.update(event_data ^ 0x9E3779B97F4A7C15ULL);
}

void TraceCollector::recordRegisterWrite(uint8_t reg, uint64_t value) {
    TraceCollector_RecordRegister(reg, value, 1);
    
    uint64_t event_data = (static_cast<uint64_t>(reg | 0x80) << 56) | (value & 0x00FFFFFFFFFFFFFFULL);
    hasher_a_.update(event_data);
    hasher_b_.update(event_data ^ 0x9E3779B97F4A7C15ULL);
}

void TraceCollector::recordBranch(uint64_t src_pc, uint64_t dst_pc, bool taken) {
    if (!buffer_.active) return;
    
    uint64_t idx = buffer_.head++;
    idx &= TRACE_MASK;
    
    TraceEvent& evt = buffer_.events[idx];
    evt.data = (src_pc << 32) | (dst_pc & 0xFFFFFFFFULL);
    evt.timestamp = static_cast<uint32_t>(buffer_.instruction_counter++);
    evt.type = taken ? 
        static_cast<uint16_t>(TraceEventType::BranchTaken) :
        static_cast<uint16_t>(TraceEventType::BranchNotTaken);
    evt.reserved = 0;
    
    // Update hashers
    hasher_a_.update(evt.data);
    hasher_b_.update(evt.data ^ 0x9E3779B97F4A7C15ULL);
}

void TraceCollector::recordCallNative(uint32_t func_idx) {
    if (!buffer_.active) return;
    
    uint64_t idx = buffer_.head++;
    idx &= TRACE_MASK;
    
    TraceEvent& evt = buffer_.events[idx];
    evt.data = func_idx;
    evt.timestamp = static_cast<uint32_t>(buffer_.instruction_counter++);
    evt.type = static_cast<uint16_t>(TraceEventType::CallNative);
    evt.reserved = 0;
    
    hasher_a_.update(func_idx);
    hasher_b_.update(func_idx ^ 0x9E3779B97F4A7C15ULL);
}

void TraceCollector::recordReturn(uint64_t value) {
    if (!buffer_.active) return;
    
    uint64_t idx = buffer_.head++;
    idx &= TRACE_MASK;
    
    TraceEvent& evt = buffer_.events[idx];
    evt.data = hashValue(value);
    evt.timestamp = static_cast<uint32_t>(buffer_.instruction_counter++);
    evt.type = static_cast<uint16_t>(TraceEventType::Return);
    evt.reserved = 0;
    
    hasher_a_.update(evt.data);
    hasher_b_.update(evt.data ^ 0x9E3779B97F4A7C15ULL);
}

TraceFingerprint TraceCollector::generateFingerprint() {
    // Process any remaining events in buffer
    while (events_processed_ < buffer_.head) {
        uint64_t idx = events_processed_++;
        idx &= TRACE_MASK;
        processEvent(buffer_.events[idx]);
    }
    
    TraceFingerprint fp;
    fp.hash_a = hasher_a_.finalize();
    fp.hash_b = hasher_b_.finalize();
    fp.event_count = static_cast<uint32_t>(buffer_.head);
    fp.instruction_count = static_cast<uint32_t>(buffer_.instruction_counter);
    
    return fp;
}

size_t TraceCollector::getEventCount() const {
    return static_cast<size_t>(buffer_.head);
}

std::string TraceCollector::getTraceSummary() const {
    std::ostringstream oss;
    
    size_t count = getEventCount();
    if (count == 0) {
        oss << "No trace events recorded.";
        return oss.str();
    }
    
    oss << "Trace Summary:\n";
    oss << "  Total events: " << count << "\n";
    oss << "  Instructions: " << buffer_.instruction_counter << "\n";
    oss << "  Buffer usage: " << (count * 100 / TRACE_BUFFER_SIZE) << "%\n";
    
    // Count event types
    size_t opcode_events = 0;
    size_t reg_events = 0;
    size_t branch_events = 0;
    
    for (size_t i = 0; i < count && i < TRACE_BUFFER_SIZE; i++) {
        const TraceEvent& evt = buffer_.events[i];
        switch (static_cast<TraceEventType>(evt.type)) {
            case TraceEventType::OpcodeDispatch:
                opcode_events++;
                break;
            case TraceEventType::RegisterRead:
            case TraceEventType::RegisterWrite:
                reg_events++;
                break;
            case TraceEventType::BranchTaken:
            case TraceEventType::BranchNotTaken:
                branch_events++;
                break;
            default:
                break;
        }
    }
    
    oss << "  Opcode events: " << opcode_events << "\n";
    oss << "  Register events: " << reg_events << "\n";
    oss << "  Branch events: " << branch_events << "\n";
    
    return oss.str();
}

void TraceCollector::dumpTraceToFile(const char* filename) const {
    FILE* fp = fopen(filename, "w");
    if (!fp) return;
    
    fprintf(fp, "RawrXD-Script Execution Trace\n");
    fprintf(fp, "=============================\n\n");
    
    size_t count = getEventCount();
    for (size_t i = 0; i < count && i < TRACE_BUFFER_SIZE; i++) {
        const TraceEvent& evt = buffer_.events[i];
        
        fprintf(fp, "[%06zu] T=%08X ", i, evt.timestamp);
        
        switch (static_cast<TraceEventType>(evt.type)) {
            case TraceEventType::OpcodeDispatch:
                fprintf(fp, "OP  PC=0x%016llX OP=%02llX\n", 
                       (unsigned long long)(evt.data >> 8),
                       (unsigned long long)(evt.data & 0xFF));
                break;
            case TraceEventType::RegisterRead:
                fprintf(fp, "REG_READ  R%d VAL=0x%016llX\n",
                       (int)(evt.data >> 56),
                       (unsigned long long)(evt.data & 0x00FFFFFFFFFFFFFFULL));
                break;
            case TraceEventType::RegisterWrite:
                fprintf(fp, "REG_WRITE R%d VAL=0x%016llX\n",
                       (int)(evt.data >> 56),
                       (unsigned long long)(evt.data & 0x00FFFFFFFFFFFFFFULL));
                break;
            case TraceEventType::BranchTaken:
                fprintf(fp, "BRANCH_TAKEN 0x%08llX -> 0x%08llX\n",
                       (unsigned long long)(evt.data >> 32),
                       (unsigned long long)(evt.data & 0xFFFFFFFFULL));
                break;
            case TraceEventType::BranchNotTaken:
                fprintf(fp, "BRANCH_NOT_TAKEN 0x%08llX\n",
                       (unsigned long long)(evt.data >> 32));
                break;
            default:
                fprintf(fp, "EVENT_%d DATA=0x%016llX\n",
                       evt.type, (unsigned long long)evt.data);
                break;
        }
    }
    
    fclose(fp);
}

float TraceCollector::computeSimilarity(const TraceFingerprint& a, const TraceFingerprint& b) {
    // Simple Jaccard-like similarity on hash components
    uint64_t xor_a = a.hash_a ^ b.hash_a;
    uint64_t xor_b = a.hash_b ^ b.hash_b;
    
    // Count matching bits (MSVC version)
    int match_bits_a = 64;
    int match_bits_b = 64;
    
    // Simple bit count
    for (int i = 0; i < 64; i++) {
        if ((xor_a >> i) & 1) match_bits_a--;
        if ((xor_b >> i) & 1) match_bits_b--;
    }
    
    float sim_a = static_cast<float>(match_bits_a) / 64.0f;
    float sim_b = static_cast<float>(match_bits_b) / 64.0f;
    
    return (sim_a + sim_b) / 2.0f;
}

std::string TraceFingerprint::toString() const {
    char buf[64];
    snprintf(buf, sizeof(buf), "%016llX-%016llX", 
             (unsigned long long)hash_a, (unsigned long long)hash_b);
    return std::string(buf);
}

void TraceCollector::processEvent(const TraceEvent& event) {
    // Already hashed during recording, but can do additional analysis here
    (void)event;
}

uint64_t TraceCollector::hashValue(uint64_t val) const {
    // Simple mixing function for values
    val ^= val >> 33;
    val *= 0xff51afd7ed558ccdULL;
    val ^= val >> 33;
    val *= 0xc4ceb9fe1a85ec53ULL;
    val ^= val >> 33;
    return val;
}

} // namespace Script
} // namespace RawrXD
