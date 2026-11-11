// Async Logger - Thread-safe asynchronous logging
#pragma once
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <fstream>
#include <iostream>
#include <chrono>

class AsyncLogger {
public:
    static AsyncLogger& Instance() {
        static AsyncLogger instance;
        return instance;
    }

    void Initialize(const std::string& logFile = "") {
        m_logFile = logFile;
        m_running = true;
        m_worker = std::thread([this]() { ProcessQueue(); });
    }

    void Shutdown() {
        m_running = false;
        m_cv.notify_all();
        if (m_worker.joinable()) {
            m_worker.join();
        }
    }

    void Log(const std::string& message, int level = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char timestamp[64];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
        m_queue.push(std::string("[") + timestamp + "] " + message);
        m_cv.notify_one();
    }

private:
    AsyncLogger() = default;
    ~AsyncLogger() { Shutdown(); }

    void ProcessQueue() {
        std::ofstream file;
        if (!m_logFile.empty()) {
            file.open(m_logFile, std::ios::app);
        }
        while (m_running) {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this]() { return !m_queue.empty() || !m_running; });
            while (!m_queue.empty()) {
                std::string msg = std::move(m_queue.front());
                m_queue.pop();
                lock.unlock();
                if (file.is_open()) {
                    file << msg << std::endl;
                }
                std::cout << msg << std::endl;
                lock.lock();
            }
        }
    }

    std::queue<std::string> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::thread m_worker;
    std::atomic<bool> m_running{false};
    std::string m_logFile;
};
