#pragma once
#include <string>
#include <filesystem>

// Struct to represent an agent task
struct AgentTask {
    std::string model;
    std::string instruction;
    std::filesystem::path workspace;
};

// Parse CLI arguments into an AgentTask
AgentTask ParseAgentTask(int argc, char* argv[]);