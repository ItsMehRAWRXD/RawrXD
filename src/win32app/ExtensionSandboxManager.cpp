// ExtensionSandboxManager.cpp — real path/command policy (no always-allow)
#include "ExtensionSandboxManager.h"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <windows.h>

namespace ExtensionSandbox {
namespace fs = std::filesystem;

namespace {
std::string ToLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
std::string JsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\\' || c == '"') { o.push_back('\\'); o.push_back(c); }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else o.push_back(c);
    }
    return o;
}
} // namespace

ExtensionSandboxManager& ExtensionSandboxManager::Instance() {
    static ExtensionSandboxManager inst;
    return inst;
}

bool ExtensionSandboxManager::PolicyReady() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return !m_roots.empty();
}

void ExtensionSandboxManager::ClearPolicy() {
    std::lock_guard<std::mutex> lock(m_mu);
    m_roots.clear();
    m_denyPrefixes.clear();
}

void ExtensionSandboxManager::AddWorkspaceRoot(const std::string& root) {
    if (root.empty()) return;
    std::error_code ec;
    fs::path p = fs::weakly_canonical(fs::absolute(fs::u8path(root)), ec);
    std::string n = Normalize(ec ? root : std::string(
        reinterpret_cast<const char*>(p.u8string().data()), p.u8string().size()));
    std::lock_guard<std::mutex> lock(m_mu);
    if (std::find(m_roots.begin(), m_roots.end(), n) == m_roots.end())
        m_roots.push_back(n);
}

void ExtensionSandboxManager::AddDeniedPathPrefix(const std::string& prefix) {
    if (prefix.empty()) return;
    std::string n = Normalize(prefix);
    std::lock_guard<std::mutex> lock(m_mu);
    m_denyPrefixes.push_back(n);
}

void ExtensionSandboxManager::SetAuditLogPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_auditPath = path;
}

void ExtensionSandboxManager::SetInteractive(bool interactive) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_interactive = interactive;
}

void ExtensionSandboxManager::SetAutoApproveConfirm(bool allow) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_autoApproveConfirm = allow;
}

std::string ExtensionSandboxManager::Normalize(const std::string& p) const {
    std::string s = p;
    for (char& c : s) if (c == '/') c = '\\';
    // Collapse "\\.\\" noise lightly; full canonical done by callers when possible.
    while (!s.empty() && (s.back() == '\\' || s.back() == '/')) s.pop_back();
    return ToLower(s);
}

bool ExtensionSandboxManager::PathUnderRoot(const std::string& absPath) const {
    for (const auto& root : m_roots) {
        if (absPath == root) return true;
        if (absPath.size() > root.size() &&
            absPath.compare(0, root.size(), root) == 0 &&
            absPath[root.size()] == '\\')
            return true;
    }
    return false;
}

bool ExtensionSandboxManager::PathDenied(const std::string& absPath) const {
    for (const auto& d : m_denyPrefixes) {
        if (absPath == d) return true;
        if (absPath.size() >= d.size() &&
            absPath.compare(0, d.size(), d) == 0)
            return true;
    }
    // Hard deny: Windows sensitive trees even if somehow rooted.
    static const char* kHard[] = {
        "c:\\windows\\system32", "c:\\windows\\syswow64",
        "c:\\program files", "c:\\program files (x86)"
    };
    for (const char* h : kHard) {
        std::string H = h;
        if (absPath == H || (absPath.size() > H.size() &&
            absPath.compare(0, H.size(), H) == 0 && absPath[H.size()] == '\\'))
            return true;
    }
    return false;
}

bool ExtensionSandboxManager::IsPathAllowed(const std::string& path) const {
    if (path.empty()) return false;
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_roots.empty()) return false; // fail closed: policy missing
    // Reject traversal tokens before resolve.
    if (path.find("..") != std::string::npos) return false;
    std::error_code ec;
    fs::path cand = fs::u8path(path);
    fs::path abs = fs::weakly_canonical(fs::absolute(cand), ec);
    std::string n = Normalize(ec ? path : std::string(
        reinterpret_cast<const char*>(abs.u8string().data()), abs.u8string().size()));
    if (PathDenied(n)) return false;
    return PathUnderRoot(n);
}

bool ExtensionSandboxManager::CommandMatchesDanger(const std::string& lower) const {
    static const char* kDanger[] = {
        "format ", "format\t", "format.com",
        "del /s", "rd /s", "rmdir /s", "rm -rf", "rm -fr",
        "reg delete", "reg.exe delete",
        "shutdown", "bcdedit", "diskpart",
        "mimikatz", "invoke-mimikatz",
        "remove-item -recurse", "ri -recurse",
        "start-process.*-verb runas",
        "iex(", "invoke-expression",
        "downloadstring", "downloadfile",
        "curl .*|.*iex", "wget .*|.*iex",
        "cmd /c del", "cmd.exe /c del",
        "cipher /w", "fsutil",
        "net user", "net localgroup",
        "schtasks /create", "bitsadmin",
        "powershell -enc", "powershell -e ",
        "pwsh -enc", "-encodedcommand"
    };
    for (const char* pat : kDanger) {
        std::string p = pat;
        // Simple substring match (patterns are literals except we skip regex ones).
        if (p.find(".*") != std::string::npos) continue;
        if (lower.find(p) != std::string::npos) return true;
    }
    // Encoded / pipe-to-iex heuristics
    if (lower.find("encodedcommand") != std::string::npos) return true;
    if (lower.find("invoke-expression") != std::string::npos) return true;
    if (lower.find("iex(") != std::string::npos) return true;
    if (lower.find("downloadstring") != std::string::npos) return true;
    return false;
}

bool ExtensionSandboxManager::IsCommandAllowed(const std::string& command) const {
    if (command.empty()) return false;
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_roots.empty()) return false; // fail closed: policy missing
    std::string lower = ToLower(command);
    if (CommandMatchesDanger(lower)) return false;
    // Reject absolute escapes outside workspace via cmd path args like C:\Windows\...
    if (lower.find("c:\\windows") != std::string::npos) return false;
    if (lower.find("%systemroot%") != std::string::npos) return false;
    if (lower.find("\\\\") != std::string::npos) return false; // UNC
    return true;
}

void ExtensionSandboxManager::AppendAudit(const std::string& decision,
                                          const std::string& tool,
                                          const std::string& detail,
                                          const std::string& reason) {
    std::string path;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        path = m_auditPath;
    }
    if (path.empty()) {
        if (const char* env = std::getenv("RAWRXD_SECURITY_AUDIT_LOG"))
            path = env;
        else
            path = "F:\\rawrxd\\evidence\\AGENT_SECURITY_WIRE_001\\security_audit.jsonl";
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::ofstream out(path, std::ios::app);
    if (!out) return;
    out << "{\"ts_ms\":" << ms
        << ",\"decision\":\"" << JsonEscape(decision)
        << "\",\"tool\":\"" << JsonEscape(tool)
        << "\",\"detail\":\"" << JsonEscape(detail)
        << "\",\"reason\":\"" << JsonEscape(reason)
        << "\",\"certified\":0,\"promote\":0}\n";
}

bool ExtensionSandboxManager::RequestApproval(const std::string& action) {
    return RequestRiskApproval(RiskTier::Confirm, "approval", action);
}

bool ExtensionSandboxManager::RequestRiskApproval(RiskTier tier,
                                                  const std::string& tool,
                                                  const std::string& detail) {
    if (tier == RiskTier::Block) {
        AppendAudit("DENY", tool, detail, "risk_tier=Block");
        return false;
    }
    if (tier == RiskTier::Auto) {
        AppendAudit("ALLOW", tool, detail, "risk_tier=Auto");
        return true;
    }
    bool interactive = true;
    bool autoConfirm = false;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        interactive = m_interactive;
        autoConfirm = m_autoApproveConfirm;
    }
    if (!interactive) {
        if (autoConfirm) {
            AppendAudit("ALLOW", tool, detail, "headless_auto_confirm");
            return true;
        }
        AppendAudit("DENY", tool, detail, "headless_fail_closed");
        return false;
    }
    std::string msg = "Approve agent tool?\n\nTool: " + tool + "\n" + detail;
    const int result = MessageBoxA(NULL, msg.c_str(), "AI Consent Prompt",
                                   MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
    const bool ok = (result == IDYES);
    AppendAudit(ok ? "ALLOW" : "DENY", tool, detail,
                ok ? "user_consent_yes" : "user_consent_no");
    return ok;
}

bool ExtensionSandboxManager::CheckPathAndCommand(const std::string& toolName,
                                                  const std::string& pathArg,
                                                  const std::string& commandArg,
                                                  std::string& denyReason) {
    if (!PolicyReady()) {
        denyReason = "security policy missing (no workspace roots)";
        AppendAudit("DENY", toolName, pathArg + "|" + commandArg, denyReason);
        return false;
    }
    if (!pathArg.empty() && !IsPathAllowed(pathArg)) {
        denyReason = "path not allowed by sandbox";
        AppendAudit("DENY", toolName, pathArg, denyReason);
        return false;
    }
    if (!commandArg.empty() && !IsCommandAllowed(commandArg)) {
        denyReason = "command denied by sandbox";
        AppendAudit("DENY", toolName, commandArg, denyReason);
        return false;
    }
    return true;
}

bool ExtensionSandboxManager::GateToolDispatch(const std::string& toolName,
                                               RiskTier tier,
                                               const std::string& pathArg,
                                               const std::string& commandArg,
                                               std::string& denyReason) {
    if (!CheckPathAndCommand(toolName, pathArg, commandArg, denyReason))
        return false;
    RiskTier effective = tier;
    if (!commandArg.empty() && effective == RiskTier::Auto)
        effective = RiskTier::Confirm;
    if (effective == RiskTier::Auto) return true;
    if (!RequestRiskApproval(effective, toolName,
                             !commandArg.empty() ? commandArg : pathArg)) {
        denyReason = "approval denied";
        return false;
    }
    return true;
}

} // namespace ExtensionSandbox
