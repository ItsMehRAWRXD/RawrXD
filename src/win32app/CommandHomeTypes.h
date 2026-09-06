#pragma once
// COMMAND_HOME_001 — Command-home shell types (Phase 1)
#include <cstdint>
#include <string>

namespace RawrXD::CommandHome {

enum class ShellMode : uint8_t {
    CommandHome = 0,
    WorkMode = 1,
};

enum class ExecutionMode : uint8_t {
    Plan = 0,
    Agent = 1,
};

struct CapabilityFlags {
    bool read = true;
    bool edit = true;
    bool execute = false;
    bool commit = false;
    bool push = false;
    bool destructive = false;
};

struct SessionBind {
    std::string machineId = "ThisPC";
    std::string workspaceRoot;
    std::string repoRoot;
    std::string branch = "unknown";
    std::string modelId = "Deep2 Local";
    CapabilityFlags capabilities{};
    bool bound = false;
};

enum class AgentActivityState : uint8_t {
    Idle = 0,
    Working,
    WaitingApproval,
    Stopped,
    Error,
};

struct AgentActivity {
    AgentActivityState state = AgentActivityState::Idle;
    std::string actor = "RawrXD Agent";
    std::string operation;
    std::string detail;
    int progressPct = 0;
};

// Control IDs (14000 block — Command-home shell)
constexpr int IDC_COMMAND_WORKSPACE = 14000;
constexpr int IDC_COMMAND_CONTEXT_BAR = 14001;
constexpr int IDC_COMMAND_RAIL = 14002;
constexpr int IDC_COMMAND_NEW_TASK = 14003;
constexpr int IDC_COMMAND_ENTER_IDE = 14004;
constexpr int IDC_COMMAND_RETURN = 14005;
constexpr int IDC_COMMAND_TRANSCRIPT = 14006;
constexpr int IDC_COMMAND_ACTIVITY_STRIP = 14007;
constexpr int IDC_COMMAND_STOP_AGENT = 14008;
constexpr int IDC_COMMAND_COMPOSER = 14009;
constexpr int IDC_COMMAND_SEND = 14010;
constexpr int IDC_COMMAND_ATTACH = 14011;
constexpr int IDC_COMMAND_MODE = 14012;
constexpr int IDC_COMMAND_MODEL = 14013;
constexpr int IDC_COMMAND_FOOTER = 14014;
constexpr int IDC_COMMAND_APPROVALS = 14015;

constexpr int kCommandRailWidth = 260;
constexpr int kCommandContextBarH = 40;
constexpr int kCommandActivityStripH = 44;
constexpr int kCommandComposerH = 120;
constexpr int kCommandFooterH = 28;

} // namespace RawrXD::CommandHome
