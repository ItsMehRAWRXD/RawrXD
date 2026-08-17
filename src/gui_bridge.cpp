#include "runtime_core.h"
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <future>

namespace {
    // Thread-safe queue for GUI requests
    struct GUIRequest {
        std::string text;
        std::promise<std::string>* promise;
    };
    
    std::queue<GUIRequest> g_requestQueue;
    std::mutex g_queueMutex;
    std::condition_variable g_queueCV;
    std::atomic<bool> g_running{false};
    std::thread g_workerThread;
    
    // Response cache for synchronous calls
    std::string g_lastResponse;
    std::mutex g_responseMutex;
    
    void WorkerLoop() {
        while (g_running.load()) {
            std::unique_lock<std::mutex> lock(g_queueMutex);
            g_queueCV.wait(lock, [] { return !g_requestQueue.empty() || !g_running.load(); });
            
            if (!g_running.load()) break;
            
            GUIRequest req = std::move(g_requestQueue.front());
            g_requestQueue.pop();
            lock.unlock();
            
            // Process the request
            std::string result = process_prompt(req.text.c_str() ? req.text.c_str() : "");
            
            // Store response
            {
                std::lock_guard<std::mutex> respLock(g_responseMutex);
                g_lastResponse = result;
            }
            
            // Fulfill promise if async
            if (req.promise) {
                req.promise->set_value(result);
            }
        }
    }
}

extern "C" __declspec(dllexport)
const char* gui_submit(const char* text) {
    static thread_local std::string out;
    out = process_prompt(text ? text : "");
    return out.c_str();
}

extern "C" __declspec(dllexport)
bool gui_initialize() {
    if (g_running.exchange(true)) {
        return false;  // Already initialized
    }
    
    g_workerThread = std::thread(WorkerLoop);
    return true;
}

extern "C" __declspec(dllexport)
void gui_shutdown() {
    g_running.store(false);
    g_queueCV.notify_all();
    
    if (g_workerThread.joinable()) {
        g_workerThread.join();
    }
    
    // Clear any pending requests
    std::lock_guard<std::mutex> lock(g_queueMutex);
    while (!g_requestQueue.empty()) {
        if (g_requestQueue.front().promise) {
            g_requestQueue.front().promise->set_value("");
        }
        g_requestQueue.pop();
    }
}

extern "C" __declspec(dllexport)
const char* gui_get_last_response() {
    std::lock_guard<std::mutex> lock(g_responseMutex);
    return g_lastResponse.c_str();
}

extern "C" __declspec(dllexport)
bool gui_is_ready() {
    return g_running.load();
}
