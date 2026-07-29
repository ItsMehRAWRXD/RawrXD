<<<<<<< HEAD
// SCAFFOLD_348: Zero day agentic engine void*

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#pragma once

#include <string>
#include <memory>
#include <vector>

namespace RawrXD { 
    class ToolRegistry;
    class PlanOrchestrator; 
    class UniversalModelRouter;
<<<<<<< HEAD
}
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

class ZeroDayAgenticEngine {
public:
    explicit ZeroDayAgenticEngine(RawrXD::UniversalModelRouter* router = nullptr,
                                  RawrXD::ToolRegistry* tools = nullptr,
                                  RawrXD::PlanOrchestrator* planner = nullptr,
<<<<<<< HEAD
                                  void* parent = nullptr);  // Win32: HWND when provided
=======
                                  void* parent = nullptr);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    ~ZeroDayAgenticEngine();

    void startMission(const std::string& userGoal);
    void abortMission();
<<<<<<< HEAD
=======
    void shutdown();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

private:
    struct Impl;
    std::unique_ptr<Impl> d;
    
    // Internal helpers
    void agentStream(const std::string& msg);
    void agentError(const std::string& msg);
    void agentComplete(const std::string& msg);
};
<<<<<<< HEAD
=======

} // namespace RawrXD
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
