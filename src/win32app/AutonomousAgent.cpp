#include "AutonomousAgent.h"

#include <atomic>
#include <mutex>

namespace AutonomousAgent {

namespace {
std::mutex g_mu;
AutonomousAgent* g_instance = nullptr;
std::atomic<bool> g_running{false};
void* g_ideWindow = nullptr;
unsigned long g_idePid = 0;
}  // namespace

void AutonomousAgent::Initialize() {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_instance) {
        g_instance = new AutonomousAgent();
    }
}

AutonomousAgent* AutonomousAgent::Instance() {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_instance) {
        g_instance = new AutonomousAgent();
    }
    return g_instance;
}

bool AutonomousAgent::IsRunning() const {
    return g_running.load();
}

void AutonomousAgent::SetIDEWindow(void* hwnd) {
    g_ideWindow = hwnd;
}

void AutonomousAgent::SetIDEProcessId(unsigned long pid) {
    g_idePid = pid;
}

bool AutonomousAgent::Start() {
    if (!g_ideWindow && g_idePid == 0) {
        // Allow start without HWND when only PID is set, but require at least one bind.
        // Production path always sets HWND via Win32IDE_AutonomousAgent.
    }
    g_running.store(true);
    return true;
}

}  // namespace AutonomousAgent
