// rawr_ecosystem_protocol.hpp — MCP/ACP-shaped host surface for external agents
// RawrXD hosts tools/skills/extensions; third parties supply integrations.
#pragma once
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace rawr {

enum class EcoSurface : int { Mcp = 1, Acp = 2, Extension = 3, Skill = 4 };

struct EcoCapability {
    EcoSurface surface = EcoSurface::Mcp;
    std::string id;
    std::string path;
};

struct EcoProtocolWitness {
    int mcpCompat = 1;      // existing mcp_integration / MCPServer
    int acpCompat = 1;      // this facade (session/prompt shaped)
    int extensionHost = 1;  // VSIX / QuickJS / marketplace
    int skillRegistry = 0;
    int capsListed = 0;
};

inline std::string EcoSkillsRoot(const std::string& workspace) {
    if (const char* e = std::getenv("RAWR_SKILLS_ROOT"))
        if (e[0]) return std::string(e);
    return (std::filesystem::path(workspace) / ".rawrxd" / "skills").string();
}

// Discover reusable skill packages: <root>/<name>/SKILL.md (Cursor-compatible).
inline std::vector<EcoCapability> ListSkillCapabilities(const std::string& workspace) {
    namespace fs = std::filesystem;
    std::vector<EcoCapability> out;
    const fs::path root = EcoSkillsRoot(workspace);
    std::error_code ec;
    if (!fs::exists(root, ec)) return out;
    for (fs::directory_iterator it(root, ec); !ec && it != fs::directory_iterator();
         it.increment(ec)) {
        if (!it->is_directory()) continue;
        const fs::path skill = it->path() / "SKILL.md";
        if (!fs::exists(skill, ec)) continue;
        EcoCapability c;
        c.surface = EcoSurface::Skill;
        c.id = it->path().filename().string();
        c.path = skill.string();
        out.push_back(std::move(c));
    }
    return out;
}

// ACP-like initialize: advertise host surfaces without binding one vendor SDK.
inline std::string AcpInitializeBanner(const std::string& workspace,
                                       EcoProtocolWitness& wit) {
    auto skills = ListSkillCapabilities(workspace);
    wit.skillRegistry = skills.empty() ? 0 : 1;
    wit.capsListed = (int)skills.size();
    std::string s = "protocol=rawr.ecosystem/1\n";
    s += "mcp=1\nacp=1\nextensions=1\nskills=";
    s += std::to_string(wit.capsListed);
    s += "\nskills_root=";
    s += EcoSkillsRoot(workspace);
    s += "\npolicy=external_agents_bring_tools\n";
    return s;
}

inline bool EcosystemProtocolWanted() {
    const char* e = std::getenv("RAWR_ECOSYSTEM_PROTOCOL");
    return e && e[0] == '1';
}

} // namespace rawr
