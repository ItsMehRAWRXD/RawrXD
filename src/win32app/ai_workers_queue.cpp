#include <chrono>
#include <deque>
#include <fstream>
#include <functional>
#include <mutex>

namespace {
std::deque<std::function<void()>> g_invokeQueue;
std::mutex g_invokeQueueMutex;
}

void AIWorkersInvokeLater(std::function<void()> f) {
    if (!f) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_invokeQueueMutex);
    g_invokeQueue.push_back(std::move(f));
}

void AIWorkersProcessInvokeQueue() {
    std::deque<std::function<void()>> pending;
    {
        std::lock_guard<std::mutex> lock(g_invokeQueueMutex);
        pending.swap(g_invokeQueue);
    }
    if (!pending.empty()) {
        // #region agent log
        std::ofstream f("f:\\~dev\\debug-536900.log", std::ios::app);
        if (f) {
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            f << "{\"sessionId\":\"536900\",\"timestamp\":" << ms
              << ",\"location\":\"AIWorkersProcessInvokeQueue\",\"message\":\"run\","
              << "\"data\":{\"count\":" << pending.size()
              << "},\"hypothesisId\":\"H12\",\"runId\":\"pre-fix\"}\n";
        }
        // #endregion
    }
    for (auto& task : pending) {
        task();
    }
}
