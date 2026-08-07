// ============================================================================
// NamedPipeServer.cpp — Named Pipe IPC Server Implementation
// ============================================================================

#include "NamedPipeServer.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <cstring>

namespace rawr {

NamedPipeServer::NamedPipeServer() = default;
NamedPipeServer::~NamedPipeServer() { Stop(); }

bool NamedPipeServer::Start(const char* pipeName) {
#ifdef _WIN32
    m_pipeName = pipeName ? pipeName : R"(\\.\pipe\RawrXD)";

    m_pipe = CreateNamedPipeA(
        m_pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096, 4096,
        0, nullptr
    );

    if (m_pipe == INVALID_HANDLE_VALUE) {
        RawrRuntime::Get().Log(LogLevel::Error, "Failed to create named pipe");
        return false;
    }

    m_running = true;
    m_thread = std::thread(&NamedPipeServer::WorkerThread, this);

    RawrRuntime::Get().Log(LogLevel::Info, "Named pipe server started");
    return true;
#else
    RawrRuntime::Get().Log(LogLevel::Warn, "Named pipes not supported on this platform");
    return false;
#endif
}

void NamedPipeServer::Stop() {
    m_running = false;

#ifdef _WIN32
    if (m_pipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(m_pipe);
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
#endif

    if (m_thread.joinable()) {
        m_thread.join();
    }
}

bool NamedPipeServer::SendMessage(const char* message, size_t size) {
#ifdef _WIN32
    if (m_pipe == INVALID_HANDLE_VALUE) return false;

    DWORD written;
    return WriteFile(m_pipe, message, (DWORD)size, &written, nullptr) != 0;
#else
    return false;
#endif
}

void NamedPipeServer::WorkerThread() {
#ifdef _WIN32
    char buffer[4096];

    while (m_running) {
        BOOL connected = ConnectNamedPipe(m_pipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            if (!m_running) break;
            continue;
        }

        DWORD bytesRead;
        BOOL success = ReadFile(m_pipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);

        if (success && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            if (m_onMessage) {
                m_onMessage(buffer, bytesRead);
            }
        }

        DisconnectNamedPipe(m_pipe);
    }
#endif
}

} // namespace rawr
