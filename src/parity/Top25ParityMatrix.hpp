#pragma once
// Explicit evidence-first parity model: never equate a feature name with PASS.
#include <array>
#include <cstdint>
#include <string_view>
namespace rawrxd::parity {
enum class Status : uint8_t { Unknown, Missing, Implemented, Tested, Certified };
struct Competitor { std::string_view name; };
inline constexpr std::array<Competitor,25> kTargets = {{
 {"Cursor"},{"Windsurf"},{"VS Code + GitHub Copilot"},{"Zed"},{"JetBrains AI / Junie"},
 {"Cline"},{"Roo Code"},{"Continue"},{"Aider"},{"Claude Code"},
 {"OpenAI Codex"},{"Google Antigravity"},{"Gemini Code Assist"},{"Amazon Q Developer"},
 {"Tabnine"},{"Sourcegraph Cody"},{"Replit Agent"},{"Devin"},{"Void"},
 {"PearAI"},{"Trae"},{"Kiro"},{"Firebase Studio"},{"GitLab Duo"},{"Tabby"}
}};
inline constexpr std::array<std::string_view,20> kCapabilities = {{
 "editor","multi-cursor","find-replace","project-search","syntax-highlighting",
 "lsp","debugger","terminal","git","extensions","inline-completion",
 "chat","agent-tools","multi-file-edit","build-test-verify","rollback",
 "local-models","model-switching","context-management","offline-operation"
}};
// Certification requires a retained, reviewable test receipt, not just a flag.
struct Cell { Status status=Status::Unknown; std::string_view evidence_ref{}; };
using Matrix = std::array<std::array<Cell,kCapabilities.size()>,kTargets.size()>;
inline constexpr size_t CertifiedCount(const Matrix& m) {
    size_t n=0;
    for(const auto& row:m) for(const auto& c:row)
        if(c.status==Status::Certified && !c.evidence_ref.empty()) ++n;
    return n;
}
inline constexpr size_t TotalCells() { return kTargets.size()*kCapabilities.size(); }
} // namespace rawrxd::parity
