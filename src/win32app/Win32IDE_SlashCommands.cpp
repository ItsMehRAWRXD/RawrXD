// Win32IDE_SlashCommands.cpp - Full Implementation
// Wires slash command initialization to existing Win32IDE infrastructure
// Replaces stub with functional command registry

#include "Win32IDE.h"
#include "../agentic/slash_command_parser.hpp"
#include <windows.h>
#include <string>
#include <vector>
#include <map>

namespace RawrXD {
namespace Agentic {

// ============================================================================
// Slash Command Registry
// ============================================================================

struct SlashCommandEntry
{
    std::string command;
    std::string description;
    std::string category;
    bool requiresArgs;
    bool needsApproval;
};

static std::vector<SlashCommandEntry> g_slashCommands;
static bool g_slashCommandsInitialized = false;

static void InitializeSlashCommandRegistry()
{
    if (g_slashCommandsInitialized) return;
    
    g_slashCommands = {
        {"fix",       "Apply AI-powered code fixes",           "Editing",  true,  true},
        {"edit",      "Multi-file edit with approval",       "Editing",  true,  true},
        {"explain",   "Explain selected code",               "Analysis", true,  false},
        {"test",      "Generate unit tests",                 "Testing",  true,  true},
        {"doc",       "Generate documentation",              "Docs",     true,  false},
        {"refactor",  "Refactor with AI assistance",         "Editing",  true,  true},
        {"review",    "Review code for issues",              "Analysis", true,  false},
        {"commit",    "Generate commit message",             "Git",      false, false},
        {"search",    "Semantic code search",                "Search",   true,  false},
        {"model",     "Switch AI model",                     "Config",   true,  false},
        {"clear",     "Clear chat history",                  "Chat",     false, false},
        {"help",      "Show available commands",               "Help",     false, false}
    };
    
    g_slashCommandsInitialized = true;
}

// ============================================================================
// Public API
// ============================================================================

std::vector<std::string> GetAvailableSlashCommands()
{
    InitializeSlashCommandRegistry();
    std::vector<std::string> result;
    result.reserve(g_slashCommands.size());
    for (const auto& cmd : g_slashCommands)
    {
        result.push_back(cmd.command);
    }
    return result;
}

std::string GetSlashCommandDescription(const std::string& command)
{
    InitializeSlashCommandRegistry();
    for (const auto& cmd : g_slashCommands)
    {
        if (cmd.command == command)
            return cmd.description;
    }
    return "Unknown command";
}

std::string GetSlashCommandCategory(const std::string& command)
{
    InitializeSlashCommandRegistry();
    for (const auto& cmd : g_slashCommands)
    {
        if (cmd.command == command)
            return cmd.category;
    }
    return "Unknown";
}

bool SlashCommandNeedsApproval(const std::string& command)
{
    InitializeSlashCommandRegistry();
    for (const auto& cmd : g_slashCommands)
    {
        if (cmd.command == command)
            return cmd.needsApproval;
    }
    return false;
}

bool IsValidSlashCommand(const std::string& command)
{
    InitializeSlashCommandRegistry();
    for (const auto& cmd : g_slashCommands)
    {
        if (cmd.command == command)
            return true;
    }
    return false;
}

std::string BuildSlashCommandHelpText()
{
    InitializeSlashCommandRegistry();
    std::string help = "Available slash commands:\n";
    help += "═══════════════════════════════\n";
    
    std::map<std::string, std::vector<SlashCommandEntry>> byCategory;
    for (const auto& cmd : g_slashCommands)
    {
        byCategory[cmd.category].push_back(cmd);
    }
    
    for (const auto& [category, commands] : byCategory)
    {
        help += "\n[" + category + "]\n";
        for (const auto& cmd : commands)
        {
            help += "  /" + cmd.command;
            if (cmd.requiresArgs) help += " <args>";
            help += " - " + cmd.description;
            if (cmd.needsApproval) help += " [requires approval]";
            help += "\n";
        }
    }
    
    return help;
}

} // namespace Agentic
} // namespace RawrXD

// ============================================================================
// C API for Win32IDE Integration
// ============================================================================

extern "C" void Win32IDE_InitSlashCommands()
{
    RawrXD::Agentic::InitializeSlashCommandRegistry();
    OutputDebugStringA("[SlashCommands] Registry initialized\n");
}

extern "C" const char* Win32IDE_GetSlashCommandDescription(const char* cmd)
{
    if (!cmd) return "";
    static thread_local std::string desc;
    desc = RawrXD::Agentic::GetSlashCommandDescription(cmd);
    return desc.c_str();
}

extern "C" bool Win32IDE_IsValidSlashCommand(const char* cmd)
{
    if (!cmd) return false;
    return RawrXD::Agentic::IsValidSlashCommand(cmd);
}
