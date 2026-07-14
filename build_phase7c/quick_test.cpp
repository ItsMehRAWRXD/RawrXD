#include <iostream>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>

struct SimpleEvent {
    uint64_t timestamp;
    uint64_t id;
};

struct SimpleTrace {
    uint64_t id;
    std::vector<SimpleEvent> events;
    void AddEvent(const SimpleEvent& e) { events.push_back(e); }
};

class SimpleLogger {
public:
    bool Init() { return true; }
    void Log(const SimpleEvent& e) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = traces_.find(e.id);
        if (it == traces_.end()) {
            auto trace = std::make_shared<SimpleTrace>();
            trace->id = e.id;
            traces_[e.id] = trace;
            it = traces_.find(e.id);
        }
        it->second->AddEvent(e);
    }
    std::shared_ptr<SimpleTrace> GetTrace(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = traces_.find(id);
        if (it != traces_.end()) return it->second;
        return nullptr;
    }
private:
    std::mutex mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<SimpleTrace>> traces_;
};

int main() {
    std::cout << "Starting test..." << std::endl;
    
    SimpleLogger logger;
    if (!logger.Init()) {
        std::cout << "FAILED" << std::endl;
        return 1;
    }
    std::cout << "Logger initialized" << std::endl;
    
    for (int i = 0; i < 100; i++) {
        SimpleEvent e;
        e.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        e.id = 12345;
        logger.Log(e);
    }
    std::cout << "Events logged" << std::endl;
    
    auto trace = logger.GetTrace(12345);
    if (!trace) {
        std::cout << "FAILED: No trace" << std::endl;
        return 1;
    }
    std::cout << "Trace retrieved: " << trace->events.size() << " events" << std::endl;
    
    std::cout << "PASSED" << std::endl;
    return 0;
}
