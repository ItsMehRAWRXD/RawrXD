#include "FeedbackCollector.h"

#include <fstream>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

namespace RawrXD::Telemetry {

// JSON serialization
std::string FeedbackEntry::to_json() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"signal\":" << static_cast<int>(signal) << ",";
    oss << "\"context_hash\":\"" << context_hash << "\",";
    oss << "\"suggestion_text\":\"" << suggestion_text << "\",";
    oss << "\"trie_score\":" << trie_score << ",";
    oss << "\"semantic_score\":" << semantic_score << ",";
    oss << "\"final_score\":" << final_score << ",";
    oss << "\"timestamp_ms\":" << timestamp_ms << ",";
    oss << "\"edit_distance\":" << edit_distance;
    oss << "}";
    return oss.str();
}

FeedbackEntry FeedbackEntry::from_json(const std::string& json) {
    FeedbackEntry entry;
    // Simple parsing - in production use a proper JSON library
    // This is a minimal implementation for Phase 18A
    size_t pos = json.find("\"signal\":");
    if (pos != std::string::npos) {
        entry.signal = static_cast<InteractionSignal>(
            std::stoi(json.substr(pos + 9))
        );
    }
    // ... additional parsing would go here
    return entry;
}

// Singleton implementation
FeedbackCollector& FeedbackCollector::instance() {
    static FeedbackCollector instance;
    return instance;
}

FeedbackCollector::FeedbackCollector() 
    : m_worker(&FeedbackCollector::worker_loop, this) {
    // Ensure data directory exists
    std::string wal_path = get_wal_path();
    size_t last_slash = wal_path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        std::string dir = wal_path.substr(0, last_slash);
#ifdef _WIN32
        CreateDirectoryA(dir.c_str(), nullptr);
#else
        mkdir(dir.c_str(), 0755);
#endif
    }
}

FeedbackCollector::~FeedbackCollector() {
    shutdown();
}

void FeedbackCollector::SetHandler(FeedbackHandler handler) {
    std::lock_guard<std::mutex> lock(m_handler_mutex);
    m_handler = std::move(handler);
}

void FeedbackCollector::record(
    InteractionSignal signal,
    const std::string& context_hash,
    const std::string& suggestion_text,
    float trie_score,
    float semantic_score,
    float final_score,
    int edit_distance
) {
    FeedbackEntry entry;
    entry.signal = signal;
    entry.context_hash = context_hash;
    entry.suggestion_text = suggestion_text;
    entry.trie_score = trie_score;
    entry.semantic_score = semantic_score;
    entry.final_score = final_score;
    entry.edit_distance = edit_distance;
    
    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    entry.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();
    
    // Lock-free enqueue (minimal critical section)
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_queue.push(std::move(entry));
    }
    
    // Notify worker thread
    m_cv.notify_one();
    m_total_recorded.fetch_add(1);
}

size_t FeedbackCollector::flush_to_wal() {
    std::vector<FeedbackEntry> batch;
    
    // Drain queue
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        while (!m_queue.empty()) {
            batch.push_back(std::move(m_queue.front()));
            m_queue.pop();
        }
    }
    
    // Phase 18B: Invoke real-time handler before WAL flush
    {
        std::lock_guard<std::mutex> lock(m_handler_mutex);
        if (m_handler) {
            for (const auto& entry : batch) {
                m_handler(entry);
            }
        }
    }
    
    if (batch.empty()) {
        return 0;
    }
    
    // Append to WAL file
    std::string wal_path = get_wal_path();
    std::ofstream wal_file(wal_path, std::ios::app);
    if (!wal_file.is_open()) {
        // Log error but don't crash
        return 0;
    }
    
    for (const auto& entry : batch) {
        wal_file << entry.to_json() << "\n";
    }
    
    wal_file.flush();
    m_total_flushed.fetch_add(batch.size());
    
    return batch.size();
}

size_t FeedbackCollector::pending_count() const {
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    return m_queue.size();
}

void FeedbackCollector::shutdown() {
    if (!m_running.exchange(false)) {
        return; // Already shutting down
    }
    
    // Wake worker thread
    m_cv.notify_all();
    
    // Wait for worker to finish
    if (m_worker.joinable()) {
        m_worker.join();
    }
    
    // Final flush
    flush_to_wal();
}

void FeedbackCollector::worker_loop() {
    while (m_running.load()) {
        std::unique_lock<std::mutex> lock(m_queue_mutex);
        
        // Wait for entries or timeout
        auto timeout = std::chrono::steady_clock::now() + FLUSH_INTERVAL_MS;
        m_cv.wait_until(lock, timeout, [this] {
            return !m_queue.empty() || !m_running.load();
        });
        
        // Check if we should flush
        bool should_flush = m_queue.size() >= BATCH_SIZE || 
                           std::chrono::steady_clock::now() >= timeout;
        
        if (should_flush && !m_queue.empty()) {
            lock.unlock();
            flush_to_wal();
        }
    }
    
    // Final flush on shutdown
    flush_to_wal();
}

std::string FeedbackCollector::get_wal_path() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path))) {
        return std::string(path) + "\\RawrXD\\feedback.wal";
    }
    return "C:\\RawrXD\\feedback.wal";
#else
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (home) {
        return std::string(home) + "/.local/share/rawrxd/feedback.wal";
    }
    return "/tmp/rawrxd_feedback.wal";
#endif
}

} // namespace RawrXD::Telemetry
