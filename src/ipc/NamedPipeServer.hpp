// ============================================================================
// NamedPipeServer.hpp — Named Pipe IPC Server
// For RawrXD IDE <-> Deep2 Runtime communication
// ============================================================================

#ifndef NAMED_PIPE_SERVER_HPP
#define NAMED_PIPE_SERVER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {

// ============================================================================
// Pipe Callback
// ============================================================================
using PipeMessageCallback = std::function<void(const char* message, size_t size)>;

// ============================================================================
// NamedPipeServer — Windows named pipe for IPC
// ============================================================================
class NamedPipeServer {
public:
    NamedPipeServer();
    ~NamedPipeServer();

    bool Start(const char* pipeName);
    void Stop();
    bool IsRunning() const { return m_running; }

    bool SendMessage(const char* message, size_t size);
    void SetOnMessage(PipeMessageCallback cb) { m_onMessage = std::move(cb); }

private:
    void WorkerThread();

    std::string m_pipeName;
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    PipeMessageCallback m_onMessage;

#ifdef _WIN32
    HANDLE m_pipe = INVALID_HANDLE_VALUE;
#endif
};

} // namespace rawr

#endif // NAMED_PIPE_SERVER_HPP
