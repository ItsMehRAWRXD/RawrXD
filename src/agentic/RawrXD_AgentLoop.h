#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
<<<<<<< HEAD
#include <queue>
#include <windows.h>

#include "ToolRegistry.h"
#include "../win32app/Win32IDE_AgenticBridge.h"
=======
#include <windows.h>

#include "RawrXD_ToolRegistry.h"
#include "win32app/Win32IDE_AgenticBridge.h"
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

namespace RawrXD {
namespace Agentic {

enum class PerceptionType {
    CodeChange,
    FileChange,
    UserRequest,
    ExternalSignal
};

struct PerceptionEvent {
    PerceptionType type;
    std::string data;
    uint64_t timestamp;
};

class AgentLoop {
public:
    AgentLoop();
    ~AgentLoop();

    void SetBridge(AgenticBridge* bridge);
    void Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }

    void TriggerPerception(PerceptionType type, const std::string& data);

private:
    void Loop();
    void ProcessEvent(const PerceptionEvent& evt);

    std::atomic<bool> m_running;
    std::thread m_thread;

    std::queue<PerceptionEvent> m_queue;
    std::mutex m_queueMutex;

    AgenticBridge* m_bridge;
<<<<<<< HEAD
    RawrXD::Agent::AgentToolRegistry* m_toolRegistry;
=======
    RawrXD::Agent::ToolRegistry* m_toolRegistry;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

} // namespace Agentic
} // namespace RawrXD
<<<<<<< HEAD
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
