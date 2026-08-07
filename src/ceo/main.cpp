// ============================================================================
// CEO Agent CLI Entry Point
// Command: rawrxd ceo "finish the compiler backend"
// ============================================================================
#include "CEOAgent.hpp"
#include <iostream>
#include <string>
#include <vector>

using namespace RawrXD::CEO;

void PrintUsage(const char* program) {
    std::cout << "RawrXD CEO Agent - Autonomous Software Engineer\n"
              << "Usage: " << program << " <command> [options]\n\n"
              << "Commands:\n"
              << "  start <goal>       Start a new autonomous project\n"
              << "  continue            Continue from previous session\n"
              << "  status              Show current project status\n"
              << "  pause               Pause current operation\n"
              << "  resume              Resume paused operation\n"
              << "  cancel              Cancel current operation\n"
              << "  report              Generate completion report\n"
              << "\nExamples:\n"
              << "  " << program << " start \"implement Vulkan backend\"\n"
              << "  " << program << " continue\n"
              << "  " << program << " status\n";
}

void PrintProgress(const std::string& stage, const std::string& message, float percent) {
    int barWidth = 50;
    int pos = static_cast<int>(barWidth * percent);
    
    std::cout << "\r[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << int(percent * 100.0) << "% " << stage << ": " << message;
    std::cout.flush();
    
    if (percent >= 1.0f) {
        std::cout << std::endl;
    }
}

void PrintTask(const Task& task) {
    const char* statusStr = "Unknown";
    switch (task.status) {
        case Task::Status::Pending: statusStr = "PENDING"; break;
        case Task::Status::Queued: statusStr = "QUEUED"; break;
        case Task::Status::InProgress: statusStr = "WORKING"; break;
        case Task::Status::Blocked: statusStr = "BLOCKED"; break;
        case Task::Status::Failed: statusStr = "FAILED"; break;
        case Task::Status::Success: statusStr = "SUCCESS"; break;
        case Task::Status::Skipped: statusStr = "SKIPPED"; break;
    }
    
    std::cout << "[" << statusStr << "] " << task.description << std::endl;
}

void PrintCompletion(const Goal& goal, bool success) {
    std::cout << "\n========================================\n";
    std::cout << "Goal: " << goal.description << "\n";
    std::cout << "Status: " << (success ? "✓ COMPLETED" : "✗ FAILED") << "\n";
    std::cout << "========================================\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    // Initialize CEO Agent
    CEOAgent ceo;
    CEOConfig config;
    config.projectRoot = ".";
    config.autoPlan = true;
    config.autoExecute = true;
    config.autoRepair = true;
    
    if (!ceo.Initialize(config)) {
        std::cerr << "Failed to initialize CEO Agent\n";
        return 1;
    }
    
    // Set up callbacks
    ceo.SetProgressCallback(PrintProgress);
    ceo.SetTaskCallback(PrintTask);
    ceo.SetCompletionCallback(PrintCompletion);
    
    // Execute command
    if (command == "start") {
        if (argc < 3) {
            std::cerr << "Error: start requires a goal description\n";
            PrintUsage(argv[0]);
            return 1;
        }
        
        // Concatenate all remaining arguments as the goal
        std::string goal;
        for (int i = 2; i < argc; ++i) {
            if (i > 2) goal += " ";
            goal += argv[i];
        }
        
        std::cout << "Starting CEO Agent with goal:\n  \"" << goal << "\"\n\n";
        
        auto result = ceo.ExecuteGoal(goal);
        
        // Wait for completion (blocking mode)
        while (ceo.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        return result.completed ? 0 : 1;
        
    } else if (command == "continue") {
        std::cout << "Continuing previous session...\n\n";
        
        auto result = ceo.ContinueProject();
        
        while (ceo.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        return result.completed ? 0 : 1;
        
    } else if (command == "status") {
        const auto& state = ceo.GetProjectState();
        auto goal = ceo.GetCurrentGoal();
        auto tasks = ceo.GetTaskQueue();
        
        std::cout << "Current Goal: " << (goal.description.empty() ? "None" : goal.description) << "\n";
        std::cout << "Status: " << (ceo.IsRunning() ? "Running" : "Idle") << "\n";
        std::cout << "Tasks: " << tasks.size() << " pending\n";
        std::cout << "Completed: " << state.GetCompletedTaskCount() << "\n";
        std::cout << "Failed: " << state.GetFailedTaskCount() << "\n";
        
        return 0;
        
    } else if (command == "pause") {
        ceo.Pause();
        std::cout << "Operation paused.\n";
        return 0;
        
    } else if (command == "resume") {
        ceo.Resume();
        std::cout << "Operation resumed.\n";
        return 0;
        
    } else if (command == "cancel") {
        ceo.Cancel();
        std::cout << "Operation cancelled.\n";
        return 0;
        
    } else if (command == "report") {
        auto report = ceo.GenerateReport();
        std::cout << report.dump(2) << std::endl;
        return 0;
        
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        PrintUsage(argv[0]);
        return 1;
    }
    
    return 0;
}
