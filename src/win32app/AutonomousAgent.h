#pragma once

namespace AutonomousAgent {

class AutonomousAgent {
public:
    static void Initialize();
    static AutonomousAgent* Instance();
    bool IsRunning() const;
    void SetIDEWindow(void* hwnd);
    void SetIDEProcessId(unsigned long pid);
    bool Start();
};

} // namespace AutonomousAgent
