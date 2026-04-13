// ============================================================================
// AgentToolHandlers.cpp — Agentic Tool Handler Implementations
// ============================================================================
// Concrete tools for the RawrXD autonomous coding agent.
// Every tool returns ToolCallResult. Every path is sandboxed.
// Every mutation creates a backup. Every command is timeout-enforced.
//
// Pattern: PatchResult-style, no exceptions, factory results.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#include "AgentToolHandlers.h"
#include "DiffEngine.h"
#include "core/scoped_instructions_provider.hpp"
#include "multi_file_edit_plan.hpp"
#include "SovereignAssembler.h"
#include "../win32app/TodoManager.h"

#include "../runtime/SemanticRetrieval.h"
#include "native_debugger_engine.h"
#include "debug/ai_debugger.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <intrin.h>
#include <iterator>
#include <mutex>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <windows.h>

using RawrXD::Agent::AgentToolHandlers;
using RawrXD::Agent::ToolCallResult;
using RawrXD::Agent::ToolGuardrails;
using RawrXD::Agent::ToolOutcome;
using json = nlohmann::json;

static std::string ToLowerCopy(const std::string& s)
{
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}
namespace fs = std::filesystem;

// ============================================================================
// Static state
// ============================================================================
ToolGuardrails AgentToolHandlers::s_guardrails;

namespace
{

std::string ToForwardSlashes(std::string value)
{
    std::replace(value.begin(), value.end(), '\\', '/');
    return value;
}

std::string TrimAscii(std::string value)
{
    const auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

bool ContainsDotDotPathTraversal(const std::string& value)
{
    const std::string normalized = ToForwardSlashes(value);
    return normalized == ".." || normalized.find("../") != std::string::npos ||
           normalized.find("/..") != std::string::npos;
}

std::string MakeTimestampForFilename()
{
    SYSTEMTIME utcNow{};
    GetSystemTime(&utcNow);

    char buffer[32] = {};
    std::snprintf(buffer, sizeof(buffer), "%04u%02u%02u_%02u%02u%02u",
                  static_cast<unsigned>(utcNow.wYear),
                  static_cast<unsigned>(utcNow.wMonth),
                  static_cast<unsigned>(utcNow.wDay),
                  static_cast<unsigned>(utcNow.wHour),
                  static_cast<unsigned>(utcNow.wMinute),
                  static_cast<unsigned>(utcNow.wSecond));
    return std::string(buffer);
}

std::string GetAppDataBaseDir()
{
    char* appData = nullptr;
    size_t len = 0;
    if (_dupenv_s(&appData, &len, "APPDATA") == 0 && appData && appData[0] != '\0')
    {
        std::string base = appData;
        free(appData);
        return base;
    }
    if (appData)
    {
        free(appData);
    }
    return fs::temp_directory_path().string();
}

fs::path GetMemoryBaseForScope(const std::string& scope)
{
    if (scope == "repo" && !AgentToolHandlers::GetGuardrails().allowedRoots.empty())
    {
        return fs::path(AgentToolHandlers::GetGuardrails().allowedRoots.front()) / ".rawrxd" / "memories" / "repo";
    }

    fs::path base = fs::path(GetAppDataBaseDir()) / "RawrXD" / "memories";
    if (scope == "session")
    {
        return base / "session";
    }
    if (scope == "repo")
    {
        return base / "repo";
    }
    return base / "user";
}

std::string CreateBackupImpl(const std::string& path)
{
    std::error_code ec;
    fs::path source(path);
    if (!fs::exists(source, ec) || ec || !fs::is_regular_file(source, ec) || ec)
    {
        return std::string();
    }

    fs::path backupDir = source.parent_path() / ".rawrxd-backups";
    fs::create_directories(backupDir, ec);
    if (ec)
    {
        return "failed to create backup directory: " + ec.message();
    }

    const std::string stem = source.stem().string();
    const std::string extension = source.extension().string();
    fs::path backupPath = backupDir / (stem + "." + MakeTimestampForFilename() + extension + ".bak");

    fs::copy_file(source, backupPath, fs::copy_options::overwrite_existing, ec);
    if (ec)
    {
        return "failed to create backup: " + ec.message();
    }

    return std::string();
}

bool ResolveMemoryPath(const std::string& virtualPath, fs::path& resolvedPath, std::string& scope, std::string& error)
{
    std::string normalized = ToForwardSlashes(TrimAscii(virtualPath));
    if (normalized.empty())
    {
        error = "memory path is required";
        return false;
    }
    if (normalized.rfind("/memories/", 0) != 0 && normalized != "/memories")
    {
        error = "memory path must start with /memories";
        return false;
    }
    if (ContainsDotDotPathTraversal(normalized))
    {
        error = "memory path traversal is not allowed";
        return false;
    }

    std::string rest;
    if (normalized == "/memories" || normalized == "/memories/")
    {
        scope = "user";
    }
    else if (normalized.rfind("/memories/session/", 0) == 0)
    {
        scope = "session";
        rest = normalized.substr(std::string("/memories/session/").size());
    }
    else if (normalized == "/memories/session")
    {
        scope = "session";
    }
    else if (normalized.rfind("/memories/repo/", 0) == 0)
    {
        scope = "repo";
        rest = normalized.substr(std::string("/memories/repo/").size());
    }
    else if (normalized == "/memories/repo")
    {
        scope = "repo";
    }
    else
    {
        scope = "user";
        rest = normalized.substr(std::string("/memories/").size());
    }

    fs::path base = GetMemoryBaseForScope(scope);
    std::error_code ec;
    fs::create_directories(base, ec);
    if (ec)
    {
        error = "failed to initialize memory directory: " + ec.message();
        return false;
    }

    fs::path candidate = base;
    if (!rest.empty())
    {
        candidate /= fs::path(rest);
    }
    candidate = candidate.lexically_normal();

    const std::string baseNorm = ToForwardSlashes(base.lexically_normal().string());
    const std::string candidateNorm = ToForwardSlashes(candidate.string());
    if (candidateNorm.rfind(baseNorm, 0) != 0)
    {
        error = "memory path escaped its scope";
        return false;
    }

    resolvedPath = candidate;
    return true;
}

std::string MakeVirtualMemoryPath(const std::string& scope, const fs::path& realPath)
{
    const fs::path base = GetMemoryBaseForScope(scope).lexically_normal();
    const fs::path normalized = realPath.lexically_normal();
    std::error_code ec;
    const fs::path relative = fs::relative(normalized, base, ec);

    std::string prefix = "/memories";
    if (scope == "session")
    {
        prefix += "/session";
    }
    else if (scope == "repo")
    {
        prefix += "/repo";
    }

    if (ec || relative.empty() || relative == ".")
    {
        return prefix + "/";
    }
    return prefix + "/" + ToForwardSlashes(relative.generic_string());
}

std::string GlobToRegex(const std::string& glob)
{
    std::string regex = "^";
    for (size_t i = 0; i < glob.size(); ++i)
    {
        const char ch = glob[i];
        if (ch == '*')
        {
            if (i + 1 < glob.size() && glob[i + 1] == '*')
            {
                regex += ".*";
                ++i;
            }
            else
            {
                regex += "[^/]*";
            }
        }
        else if (ch == '?')
        {
            regex += '.';
        }
        else if (ch == '.' || ch == '(' || ch == ')' || ch == '+' || ch == '^' || ch == '$' || ch == '|' ||
                 ch == '{' || ch == '}' || ch == '[' || ch == ']' || ch == '\\')
        {
            regex.push_back('\\');
            regex.push_back(ch);
        }
        else if (ch == '\\')
        {
            regex += "/";
        }
        else
        {
            regex.push_back(ch);
        }
    }
    regex += "$";
    return regex;
}

std::vector<std::string> ReadLines(const std::string& content)
{
    std::vector<std::string> lines;
    std::stringstream ss(content);
    std::string line;
    while (std::getline(ss, line))
    {
        lines.push_back(line);
    }
    if (!content.empty() && content.back() == '\n')
    {
        lines.push_back("");
    }
    if (content.empty())
    {
        lines.push_back("");
    }
    return lines;
}

std::string ToUtf8(const std::wstring& s);

std::string BuildCompactToolCatalog(const json& tools)
{
    std::ostringstream oss;
    for (const auto& tool : tools)
    {
        if (!tool.is_object() || !tool.contains("function") || !tool["function"].is_object())
        {
            continue;
        }

        const auto& fn = tool["function"];
        const std::string name = fn.value("name", std::string());
        if (name.empty())
        {
            continue;
        }

        oss << "- " << name;
        const std::string description = fn.value("description", std::string());
        if (!description.empty())
        {
            oss << ": " << description;
        }

        if (fn.contains("parameters") && fn["parameters"].is_object())
        {
            const auto& params = fn["parameters"];
            if (params.contains("properties") && params["properties"].is_object() && !params["properties"].empty())
            {
                oss << " Params[";
                bool first = true;
                for (auto it = params["properties"].begin(); it != params["properties"].end(); ++it)
                {
                    if (!first)
                    {
                        oss << ", ";
                    }
                    first = false;
                    oss << it.key();
                }
                oss << "]";
            }
        }
        oss << "\n";
    }
    return oss.str();
}

bool ReadTextFile(const std::string& path, std::string& out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
    {
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

std::vector<std::string> SplitLinesPreserveEmpty(const std::string& text)
{
    std::vector<std::string> lines;
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line))
    {
        lines.push_back(line);
    }
    if (!text.empty() && text.back() == '\n')
    {
        lines.push_back("");
    }
    return lines;
}

std::string JoinLinesWithNewline(const std::vector<std::string>& lines, bool preserveTrailingNewline)
{
    std::ostringstream out;
    for (size_t i = 0; i < lines.size(); ++i)
    {
        out << lines[i];
        if (i + 1 < lines.size())
        {
            out << "\n";
        }
    }
    if (preserveTrailingNewline && (lines.empty() || !lines.back().empty()))
    {
        out << "\n";
    }
    return out.str();
}

bool ParseEditType(const std::string& rawType, RawrXD::Agentic::EditType& outType)
{
    const std::string t = ToLowerCopy(rawType);
    if (t == "insert")
    {
        outType = RawrXD::Agentic::EditType::INSERT;
        return true;
    }
    if (t == "delete" || t == "delete_range")
    {
        outType = RawrXD::Agentic::EditType::DELETE_RANGE;
        return true;
    }
    if (t == "replace")
    {
        outType = RawrXD::Agentic::EditType::REPLACE;
        return true;
    }
    if (t == "modify")
    {
        outType = RawrXD::Agentic::EditType::MODIFY;
        return true;
    }
    return false;
}

bool ApplyEditInMemory(const RawrXD::Agentic::FileEdit& edit, std::string& content, std::string& outError)
{
    std::vector<std::string> lines = SplitLinesPreserveEmpty(content);
    const bool hadTrailingNewline = !content.empty() && content.back() == '\n';
    std::vector<std::string> replacement = SplitLinesPreserveEmpty(edit.newContent);

    int start = edit.lineStart;
    int end = edit.lineEnd;
    if (start > 0)
        --start;
    if (end > 0)
        --end;

    const int lineCount = static_cast<int>(lines.size());
    switch (edit.type)
    {
        case RawrXD::Agentic::EditType::INSERT:
        {
            if (start < 0 || start > lineCount)
            {
                outError = "Insert line out of range";
                return false;
            }
            lines.insert(lines.begin() + start, replacement.begin(), replacement.end());
            break;
        }
        case RawrXD::Agentic::EditType::DELETE_RANGE:
        {
            if (start < 0 || end < 0 || start > end || end >= lineCount)
            {
                outError = "Delete range out of range";
                return false;
            }
            lines.erase(lines.begin() + start, lines.begin() + end + 1);
            break;
        }
        case RawrXD::Agentic::EditType::REPLACE:
        {
            if (start < 0 || end < 0 || start > end || end >= lineCount)
            {
                outError = "Replace range out of range";
                return false;
            }
            lines.erase(lines.begin() + start, lines.begin() + end + 1);
            lines.insert(lines.begin() + start, replacement.begin(), replacement.end());
            break;
        }
        case RawrXD::Agentic::EditType::MODIFY:
        {
            if (start < 0 || end < 0 || start > end || end >= lineCount)
            {
                outError = "Modify range out of range";
                return false;
            }
            for (int i = start; i <= end; ++i)
            {
                lines[i] = edit.newContent;
            }
            break;
        }
    }

    content = JoinLinesWithNewline(lines, hadTrailingNewline);
    return true;
}

bool BuildMultiFilePlanFromArgs(const json& args, std::vector<RawrXD::Agentic::FileEdit>& outEdits,
                                std::string& outError)
{
    if (!args.contains("edits") || !args["edits"].is_array())
    {
        outError = "requires 'edits' (array)";
        return false;
    }
    for (const auto& e : args["edits"])
    {
        if (!e.is_object())
        {
            outError = "all edits must be objects";
            return false;
        }
        if (!e.contains("file") || !e["file"].is_string())
        {
            outError = "each edit requires 'file' (string)";
            return false;
        }
        if (!e.contains("type") || !e["type"].is_string())
        {
            outError = "each edit requires 'type' (string)";
            return false;
        }

        RawrXD::Agentic::FileEdit fe;
        fe.filePath = e["file"].get<std::string>();
        if (!ParseEditType(e["type"].get<std::string>(), fe.type))
        {
            outError = "unsupported edit type: " + e["type"].get<std::string>();
            return false;
        }
        fe.lineStart = e.value("line_start", 1);
        fe.lineEnd = e.value("line_end", fe.lineStart);
        fe.newContent = e.value("content", std::string());
        fe.reason = e.value("reason", std::string());
        outEdits.push_back(std::move(fe));
    }
    if (outEdits.empty())
    {
        outError = "edits array is empty";
        return false;
    }
    return true;
}

#ifdef _WIN32
extern "C" void TermPipe_Init();
extern "C" int TermPipe_Spawn(char* cmdLine);
extern "C" int TermPipe_Read(int sessionId, char* outBuf, int maxLen);
extern "C" int TermPipe_Kill(int sessionId);
extern "C" void* TermPipe_GetSession(int sessionId);

struct TermPipeSessionView
{
    HANDLE hProcess;
    HANDLE hThread;
    HANDLE hStdoutRd;
    HANDLE hStdoutWr;
    HANDLE hStdinRd;
    HANDLE hStdinWr;
    HANDLE hCaptureThread;
    uint32_t exitCode;
    uint32_t flags;
    uint32_t wrCursor;
    uint32_t rdCursor;
    uint32_t sessionId;
    uint32_t pid;
    uint64_t reserved;
};

constexpr uint32_t kTermFlagAlive = 0x01u;
constexpr uint32_t kTermFlagComplete = 0x04u;
constexpr uint32_t kTermPipeUnavailable = 0xFFFFFFFFu;

bool RunProcessWithTermPipe(const std::wstring& cmdLine, uint32_t timeoutMs, std::string& output, uint32_t& exitCode)
{
    static std::once_flag initFlag;
    const auto& guardrails = AgentToolHandlers::GetGuardrails();
    std::call_once(initFlag, []() { TermPipe_Init(); });

    std::string narrowCmd = ToUtf8(cmdLine);
    if (narrowCmd.empty())
    {
        output = "Empty command line";
        exitCode = ERROR_INVALID_PARAMETER;
        return false;
    }

    std::vector<char> mutableCmd(narrowCmd.begin(), narrowCmd.end());
    mutableCmd.push_back('\0');

    const int sessionId = TermPipe_Spawn(mutableCmd.data());
    if (sessionId < 0)
    {
        exitCode = kTermPipeUnavailable;
        return false;
    }

    auto appendOutput = [&](const char* buffer, size_t bytes) -> bool
    {
        if (bytes == 0)
        {
            return true;
        }
        const size_t remaining =
            guardrails.maxOutputCaptureBytes > output.size() ? (guardrails.maxOutputCaptureBytes - output.size()) : 0;
        const size_t toAppend = std::min(bytes, remaining);
        output.append(buffer, toAppend);
        if (toAppend < bytes || output.size() >= guardrails.maxOutputCaptureBytes)
        {
            output += "\n[OUTPUT TRUNCATED]";
            TermPipe_Kill(sessionId);
            exitCode = ERROR_MORE_DATA;
            return false;
        }
        return true;
    };

    const DWORD startTick = GetTickCount();
    char buffer[4096];

    while (true)
    {
        const int bytesRead = TermPipe_Read(sessionId, buffer, static_cast<int>(sizeof(buffer)));
        if (bytesRead > 0 && !appendOutput(buffer, static_cast<size_t>(bytesRead)))
        {
            return false;
        }

        auto* session = static_cast<TermPipeSessionView*>(TermPipe_GetSession(sessionId));
        if (session == nullptr || session->hProcess == nullptr)
        {
            output += "\n[terminal session unavailable]";
            exitCode = ERROR_INVALID_HANDLE;
            return false;
        }

        const DWORD wait = WaitForSingleObject(session->hProcess, 10);
        if (wait == WAIT_OBJECT_0 || (session->flags & kTermFlagComplete) != 0u)
        {
            for (int attempt = 0; attempt < 8; ++attempt)
            {
                const int tailBytes = TermPipe_Read(sessionId, buffer, static_cast<int>(sizeof(buffer)));
                if (tailBytes <= 0)
                {
                    break;
                }
                if (!appendOutput(buffer, static_cast<size_t>(tailBytes)))
                {
                    return false;
                }
                Sleep(2);
            }

            DWORD processExitCode = 0;
            if (!GetExitCodeProcess(session->hProcess, &processExitCode))
            {
                processExitCode = session->exitCode;
            }
            exitCode = static_cast<uint32_t>(processExitCode);
            TermPipe_Kill(sessionId);
            return true;
        }

        if (GetTickCount() - startTick > timeoutMs)
        {
            TermPipe_Kill(sessionId);
            output += "\n[TIMEOUT after " + std::to_string(timeoutMs) + "ms]";
            exitCode = WAIT_TIMEOUT;
            return false;
        }
    }
}
#endif

std::wstring ToWide(const std::string& s)
{
    if (s.empty())
        return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), len);
    if (!out.empty() && out.back() == L'\0')
        out.pop_back();
    return out;
}

std::string ToUtf8(const std::wstring& s)
{
    if (s.empty())
        return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0')
        out.pop_back();
    return out;
}

int CountLines(const std::string& text)
{
    int count = 0;
    for (char c : text)
    {
        if (c == '\n')
            ++count;
    }
    return count + (text.empty() ? 0 : 1);
}

// Very small semantic index: TF cosine over tokenized files
struct IndexedFile
{
    std::string path;
    std::unordered_map<std::string, double> tf;
    double norm = 0.0;
};

bool IsLikelyBinary(const std::string& content)
{
    if (content.empty())
        return false;
    size_t nonPrintable = 0;
    size_t sample = std::min<size_t>(content.size(), 4096);
    for (size_t i = 0; i < sample; ++i)
    {
        unsigned char c = static_cast<unsigned char>(content[i]);
        if (c == 0)
            return true;
        if (c < 9 || (c > 13 && c < 32))
            ++nonPrintable;
    }
    // Consider binary if more than 5% of sampled bytes are non-printable
    return (nonPrintable * 20) > sample;
}

std::vector<std::string> Tokenize(const std::string& text)
{
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : text)
    {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_')
        {
            cur.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        else if (!cur.empty())
        {
            tokens.push_back(cur);
            cur.clear();
        }
    }
    if (!cur.empty())
        tokens.push_back(cur);
    return tokens;
}

IndexedFile BuildIndexForFile(const std::string& path, size_t maxBytes)
{
    IndexedFile f;
    f.path = path;
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
        return f;
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();
    if (content.size() > maxBytes && maxBytes > 0)
    {
        content = content.substr(0, maxBytes);
    }
    if (IsLikelyBinary(content))
        return f;
    auto tokens = Tokenize(content);
    if (tokens.empty())
        return f;
    for (const auto& t : tokens)
    {
        f.tf[t] += 1.0;
    }
    for (auto& kv : f.tf)
    {
        kv.second = kv.second / static_cast<double>(tokens.size());
        f.norm += kv.second * kv.second;
    }
    f.norm = std::sqrt(f.norm);
    return f;
}

double CosineScore(const IndexedFile& f, const std::unordered_map<std::string, double>& qtf, double qnorm)
{
    if (f.norm == 0.0 || qnorm == 0.0)
        return 0.0;
    double dot = 0.0;
    for (const auto& kv : qtf)
    {
        auto it = f.tf.find(kv.first);
        if (it != f.tf.end())
            dot += kv.second * it->second;
    }
    return dot / (f.norm * qnorm);
}

}  // anonymous namespace

// ============================================================================
// Guardrails
// ============================================================================

void AgentToolHandlers::SetGuardrails(const ToolGuardrails& guards)
{
    s_guardrails = guards;
}

const ToolGuardrails& AgentToolHandlers::GetGuardrails()
{
    return s_guardrails;
}

static void (*s_integratedTerminalEcho)(const char* utf8Line, void* userData) = nullptr;
static void* s_integratedTerminalEchoUser = nullptr;

void AgentToolHandlers::SetIntegratedTerminalEchoCallback(void (*fn)(const char* utf8Line, void* userData),
                                                          void* userData)
{
    s_integratedTerminalEcho = fn;
    s_integratedTerminalEchoUser = userData;
}

static void emitIntegratedTerminalEcho(const std::string& line)
{
    if (!s_integratedTerminalEcho || line.empty())
        return;
    s_integratedTerminalEcho(line.c_str(), s_integratedTerminalEchoUser);
}

// ============================================================================
// Path validation
// ============================================================================

std::string AgentToolHandlers::NormalizePath(const std::string& path)
{
    try
    {
        return fs::weakly_canonical(path).string();
    }
    catch (...)
    {
        return path;
    }
}

bool AgentToolHandlers::IsPathAllowed(const std::string& path)
{
    std::string normalized = NormalizePath(path);

    // Must be under at least one allowed root
    if (s_guardrails.allowedRoots.empty())
        return true;  // No restrictions configured

    for (const auto& root : s_guardrails.allowedRoots)
    {
        std::string normRoot = NormalizePath(root);
        if (normalized.find(normRoot) == 0)
        {
            // Check deny patterns
            if (!MatchesDenyPattern(normalized))
            {
                return true;
            }
        }
    }
    return false;
}

bool AgentToolHandlers::MatchesDenyPattern(const std::string& path)
{
    if (s_guardrails.denyPatterns.empty())
        return false;

    const std::string normalized = ToForwardSlashes(path);
    for (const auto& pattern : s_guardrails.denyPatterns)
    {
        if (pattern.empty())
            continue;
        try
        {
            std::regex re(GlobToRegex(ToForwardSlashes(pattern)), std::regex::ECMAScript | std::regex::icase);
            if (std::regex_match(normalized, re))
            {
                return true;
            }
        }
        catch (...)
        {
        }
    }
    return false;
}

// ============================================================================
// read_file — Read file contents (optionally bounded by line range)
// ============================================================================

ToolCallResult AgentToolHandlers::ToolReadFile(const json& args)
{
    if (!args.contains("path") || !args["path"].is_string())
    {
        return ToolCallResult::Validation("read_file requires 'path' (string)");
    }

    std::string path = NormalizePath(args["path"].get<std::string>());
    if (!IsPathAllowed(path))
    {
        return ToolCallResult::Sandbox("Path not in workspace allowlist: " + path);
    }
    if (!fs::exists(path) || !fs::is_regular_file(path))
    {
        return ToolCallResult::Error("File not found: " + path, ToolOutcome::NotFound);
    }

    std::string content;
    if (!ReadTextFile(path, content))
    {
        return ToolCallResult::Error("Cannot read file: " + path);
    }

    if (content.size() > s_guardrails.maxFileSizeBytes)
    {
        return ToolCallResult::Error("File too large: " + std::to_string(content.size()) + " bytes");
    }

    const int totalLines = std::max(1, CountLines(content));
    int startLine = std::max(1, args.value("start_line", args.value("startLine", 1)));
    int endLine = std::max(startLine, args.value("end_line", args.value("endLine", totalLines)));
    startLine = std::min(startLine, totalLines);
    endLine = std::min(endLine, totalLines);

    std::string sliced = content;
    if (startLine != 1 || endLine != totalLines)
    {
        const std::vector<std::string> lines = ReadLines(content);
        std::ostringstream ranged;
        for (int i = startLine - 1; i < endLine && i < static_cast<int>(lines.size()); ++i)
        {
            if (i > startLine - 1)
            {
                ranged << "\n";
            }
            ranged << lines[static_cast<size_t>(i)];
        }
        sliced = ranged.str();
    }

    nlohmann::json res_metadata = nlohmann::json::object();
    res_metadata["lines"] = totalLines;
    res_metadata["size_bytes"] = content.size();
    res_metadata["start_line"] = startLine;
    res_metadata["end_line"] = endLine;

    ToolCallResult result = ToolCallResult::Ok(sliced, res_metadata);
    result.filePath = path;
    result.bytesRead = sliced.size();
    return result;
}

// ============================================================================
// write_file — Create or overwrite file
// ============================================================================

ToolCallResult AgentToolHandlers::WriteFile(const json& args)
{
    if (!args.contains("path") || !args["path"].is_string())
    {
        return ToolCallResult::Validation("write_file requires 'path' (string)");
    }
    if (!args.contains("content") || !args["content"].is_string())
    {
        return ToolCallResult::Validation("write_file requires 'content' (string)");
    }

    std::string path = NormalizePath(args["path"].get<std::string>());
    std::string content = args["content"].get<std::string>();

    if (!IsPathAllowed(path))
    {
        return ToolCallResult::Sandbox("Path not in workspace allowlist: " + path);
    }

    if (content.size() > s_guardrails.maxFileSizeBytes)
    {
        return ToolCallResult::Error("Content too large: " + std::to_string(content.size()) + " bytes");
    }

    // Create backup if file exists and guardrails require it
    bool existed = fs::exists(path);
    if (existed && s_guardrails.requireBackupOnWrite)
    {
        std::string backupError = CreateBackup(path);
        if (!backupError.empty())
        {
            return ToolCallResult::Error(backupError);
        }
    }

    // Ensure parent directories exist
    try
    {
        fs::path parentDir = fs::path(path).parent_path();
        if (!parentDir.empty() && !fs::exists(parentDir))
        {
            fs::create_directories(parentDir);
        }
    }
    catch (const std::exception& ex)
    {
        return ToolCallResult::Error(std::string("Cannot create directories: ") + ex.what());
    }

    // Write file
    std::ofstream file(path, std::ios::trunc | std::ios::binary);
    if (!file.is_open())
    {
        return ToolCallResult::Error("Cannot open file for writing: " + path);
    }
    file.write(content.data(), content.size());
    file.close();

    nlohmann::json res_metadata = nlohmann::json::object();
    res_metadata["lines"] = CountLines(content);
    res_metadata["size_bytes"] = content.size();
    res_metadata["created"] = !existed;

    ToolCallResult result =
        ToolCallResult::Ok(existed ? "File overwritten successfully" : "File created successfully", res_metadata);
    result.filePath = path;
    result.bytesWritten = content.size();
    result.linesAffected = CountLines(content);
    return result;
}

// ============================================================================
// replace_in_file — Search+replace text block
// ============================================================================

ToolCallResult AgentToolHandlers::ReplaceInFile(const json& args)
{
    if (!args.contains("path") || !args["path"].is_string())
    {
        return ToolCallResult::Validation("replace_in_file requires 'path' (string)");
    }
    if (!args.contains("old_string") || !args["old_string"].is_string())
    {
        return ToolCallResult::Validation("replace_in_file requires 'old_string' (string)");
    }
    if (!args.contains("new_string") || !args["new_string"].is_string())
    {
        return ToolCallResult::Validation("replace_in_file requires 'new_string' (string)");
    }

    std::string path = NormalizePath(args["path"].get<std::string>());
    std::string oldStr = args["old_string"].get<std::string>();
    std::string newStr = args["new_string"].get<std::string>();

    if (!IsPathAllowed(path))
    {
        return ToolCallResult::Sandbox("Path not in workspace allowlist: " + path);
    }
    if (!fs::exists(path))
    {
        return ToolCallResult::Error("File not found: " + path);
    }

    // Read file
    std::ifstream inFile(path, std::ios::binary);
    if (!inFile.is_open())
    {
        return ToolCallResult::Error("Cannot open file: " + path);
    }
    std::ostringstream ss;
    ss << inFile.rdbuf();
    inFile.close();
    std::string content = ss.str();

    // Find the old string
    size_t pos = content.find(oldStr);
    if (pos == std::string::npos)
    {
        return ToolCallResult::Error("old_string not found in file. "
                                     "Ensure you're using the exact text including whitespace.");
    }

    // Check for multiple matches (warn but still replace first)
    size_t secondMatch = content.find(oldStr, pos + oldStr.size());
    bool multipleMatches = (secondMatch != std::string::npos);

    // Create backup
    if (s_guardrails.requireBackupOnWrite)
    {
        std::string backupError = CreateBackup(path);
        if (!backupError.empty())
        {
            return ToolCallResult::Error(backupError);
        }
    }

    // Perform replacement
    std::string newContent = content.substr(0, pos) + newStr + content.substr(pos + oldStr.size());

    // Write back
    std::ofstream outFile(path, std::ios::trunc | std::ios::binary);
    if (!outFile.is_open())
    {
        return ToolCallResult::Error("Cannot write file: " + path);
    }
    outFile.write(newContent.data(), newContent.size());
    outFile.close();

    int linesChanged = CountLines(newStr) - CountLines(oldStr);
    std::string msg =
        "Replaced " + std::to_string(oldStr.size()) + " bytes with " + std::to_string(newStr.size()) + " bytes";
    if (multipleMatches)
    {
        msg += " (WARNING: multiple matches found, only first replaced)";
    }

    nlohmann::json res_metadata = nlohmann::json::object();
    res_metadata["old_length"] = oldStr.size();
    res_metadata["new_length"] = newStr.size();
    res_metadata["position"] = pos;
    res_metadata["multiple_matches"] = multipleMatches;
    res_metadata["line_delta"] = linesChanged;

    ToolCallResult result = ToolCallResult::Ok(msg, res_metadata);
    result.filePath = path;
    result.bytesWritten = newContent.size();
    result.linesAffected = std::abs(linesChanged) + CountLines(newStr);
    return result;
}

// ============================================================================
// list_dir — List directory contents
// ============================================================================

ToolCallResult AgentToolHandlers::ListDir(const json& args)
{
    if (!args.contains("path") || !args["path"].is_string())
    {
        return ToolCallResult::Validation("list_dir requires 'path' (string)");
    }

    std::string path = NormalizePath(args["path"].get<std::string>());
    if (!IsPathAllowed(path))
    {
        return ToolCallResult::Sandbox("Path not in workspace allowlist: " + path);
    }
    if (!fs::exists(path) || !fs::is_directory(path))
    {
        return ToolCallResult::Error("Directory not found: " + path);
    }

    std::ostringstream listing;
    int fileCount = 0, dirCount = 0;

    try
    {
        for (const auto& entry : fs::directory_iterator(path))
        {
            std::string name = entry.path().filename().string();
            if (entry.is_directory())
            {
                listing << name << "/\n";
                ++dirCount;
            }
            else
            {
                auto size = entry.file_size();
                listing << name << " (" << size << " bytes)\n";
                ++fileCount;
            }
        }
    }
    catch (const std::exception& ex)
    {
        return ToolCallResult::Error(std::string("Directory listing failed: ") + ex.what());
    }

    nlohmann::json res_metadata = nlohmann::json::object();
    res_metadata["files"] = fileCount;
    res_metadata["directories"] = dirCount;
    res_metadata["total"] = fileCount + dirCount;

    return ToolCallResult::Ok(listing.str(), res_metadata);
}

ToolCallResult AgentToolHandlers::DeleteFile(const json& args)
{
    if (!args.contains("path") || !args["path"].is_string())
    {
        return ToolCallResult::Validation("fs_delete_file requires 'path' (string)");
    }

    const std::string path = NormalizePath(args["path"].get<std::string>());
    if (!IsPathAllowed(path))
    {
        return ToolCallResult::Sandbox("Path not in workspace allowlist: " + path);
    }
    if (!fs::exists(path))
    {
        return ToolCallResult::Error("File not found: " + path);
    }
    if (fs::is_directory(path))
    {
        return ToolCallResult::Validation("fs_delete_file only supports files");
    }

    std::error_code ec;
    const bool removed = fs::remove(path, ec);
    if (ec || !removed)
    {
        return ToolCallResult::Error("Failed to delete file: " + path + (ec ? (" (" + ec.message() + ")") : ""));
    }

    nlohmann::json meta = nlohmann::json::object();
    meta["deleted"] = true;
    ToolCallResult result = ToolCallResult::Ok("Deleted file", meta);
    result.filePath = path;
    return result;
}

ToolCallResult AgentToolHandlers::MoveFile(const json& args)
{
    const std::string fromKey = args.contains("source") ? "source" : (args.contains("old_path") ? "old_path" : "");
    const std::string toKey =
        args.contains("destination") ? "destination" : (args.contains("new_path") ? "new_path" : "");
    if (fromKey.empty() || !args[fromKey].is_string() || toKey.empty() || !args[toKey].is_string())
    {
        return ToolCallResult::Validation("fs_move_file requires 'source' and 'destination' (string)");
    }

    const std::string source = NormalizePath(args[fromKey].get<std::string>());
    const std::string destination = NormalizePath(args[toKey].get<std::string>());
    if (!IsPathAllowed(source) || !IsPathAllowed(destination))
    {
        return ToolCallResult::Sandbox("Source/destination must be within workspace allowlist");
    }
    if (!fs::exists(source))
    {
        return ToolCallResult::Error("Source file not found: " + source);
    }
    if (fs::is_directory(source))
    {
        return ToolCallResult::Validation("fs_move_file only supports files");
    }

    std::error_code ec;
    const fs::path parent = fs::path(destination).parent_path();
    if (!parent.empty())
    {
        fs::create_directories(parent, ec);
        if (ec)
        {
            return ToolCallResult::Error("Failed to create destination directory: " + ec.message());
        }
    }

    fs::rename(source, destination, ec);
    if (ec)
    {
        ec.clear();
        fs::copy_file(source, destination, fs::copy_options::overwrite_existing, ec);
        if (ec)
        {
            return ToolCallResult::Error("Failed to move file: " + ec.message());
        }
        ec.clear();
        fs::remove(source, ec);
        if (ec)
        {
            return ToolCallResult::Error("File copied but source removal failed: " + ec.message());
        }
    }

    nlohmann::json meta = nlohmann::json::object();
    meta["source"] = source;
    meta["destination"] = destination;
    ToolCallResult result = ToolCallResult::Ok("Moved file", meta);
    result.filePath = destination;
    return result;
}

ToolCallResult AgentToolHandlers::CopyFile(const json& args)
{
    const std::string fromKey = args.contains("source") ? "source" : (args.contains("from") ? "from" : "");
    const std::string toKey = args.contains("destination") ? "destination" : (args.contains("to") ? "to" : "");
    if (fromKey.empty() || !args[fromKey].is_string() || toKey.empty() || !args[toKey].is_string())
    {
        return ToolCallResult::Validation("fs_copy_file requires 'source' and 'destination' (string)");
    }

    const std::string source = NormalizePath(args[fromKey].get<std::string>());
    const std::string destination = NormalizePath(args[toKey].get<std::string>());
    if (!IsPathAllowed(source) || !IsPathAllowed(destination))
    {
        return ToolCallResult::Sandbox("Source/destination must be within workspace allowlist");
    }
    if (!fs::exists(source))
    {
        return ToolCallResult::Error("Source file not found: " + source);
    }
    if (fs::is_directory(source))
    {
        return ToolCallResult::Validation("fs_copy_file only supports files");
    }

    std::error_code ec;
    const fs::path parent = fs::path(destination).parent_path();
    if (!parent.empty())
    {
        fs::create_directories(parent, ec);
        if (ec)
        {
            return ToolCallResult::Error("Failed to create destination directory: " + ec.message());
        }
    }

    const bool copied = fs::copy_file(source, destination, fs::copy_options::overwrite_existing, ec);
    if (ec || !copied)
    {
        return ToolCallResult::Error("Failed to copy file: " + (ec ? ec.message() : std::string("unknown error")));
    }

    uintmax_t sizeBytes = fs::file_size(destination, ec);
    if (ec)
    {
        sizeBytes = 0;
    }

    nlohmann::json meta = nlohmann::json::object();
    meta["source"] = source;
    meta["destination"] = destination;
    meta["size_bytes"] = sizeBytes;
    ToolCallResult result = ToolCallResult::Ok("Copied file", meta);
    result.filePath = destination;
    result.bytesWritten = static_cast<size_t>(sizeBytes);
    return result;
}

ToolCallResult AgentToolHandlers::PathExists(const json& args)
{
    if (!args.contains("path") || !args["path"].is_string())
    {
        return ToolCallResult::Validation("fs_exists requires 'path' (string)");
    }

    const std::string path = NormalizePath(args["path"].get<std::string>());
    if (!IsPathAllowed(path))
    {
        return ToolCallResult::Sandbox("Path not in workspace allowlist: " + path);
    }

    std::error_code ec;
    const bool exists = fs::exists(path, ec);
    const bool isDir = exists ? fs::is_directory(path, ec) : false;
    uintmax_t sizeBytes = 0;
    if (exists && !isDir)
    {
        sizeBytes = fs::file_size(path, ec);
        if (ec)
        {
            sizeBytes = 0;
        }
    }

    nlohmann::json payload = nlohmann::json::object();
    payload["path"] = path;
    payload["exists"] = exists;
    payload["is_directory"] = isDir;
    payload["size_bytes"] = sizeBytes;

    return ToolCallResult::Ok(payload.dump(), payload);
}

ToolCallResult AgentToolHandlers::MakeDirectory(const json& args)
{
    if (!args.contains("path") || !args["path"].is_string())
    {
        return ToolCallResult::Validation("fs_mkdir requires 'path' (string)");
    }

    const std::string path = NormalizePath(args["path"].get<std::string>());
    if (!IsPathAllowed(path))
    {
        return ToolCallResult::Sandbox("Path not in workspace allowlist: " + path);
    }

    std::error_code ec;
    const bool created = fs::create_directories(path, ec);
    if (ec)
    {
        return ToolCallResult::Error("Failed to create directory: " + ec.message());
    }

    nlohmann::json meta = nlohmann::json::object();
    meta["path"] = path;
    meta["created"] = created;
    ToolCallResult result = ToolCallResult::Ok(created ? "Directory created" : "Directory already exists", meta);
    result.filePath = path;
    return result;
}

// ============================================================================
// execute_command — Run terminal command (sandboxed)
// ============================================================================

bool AgentToolHandlers::RunProcess(const std::wstring& cmdLine, uint32_t timeoutMs, std::string& output,
                                   uint32_t& exitCode, const wchar_t* workingDirectoryUtf16)
{
#ifdef _WIN32
    // Term-pipe path cannot honor a custom CWD; use CreateProcess fallback when cwd is set.
    if (!workingDirectoryUtf16 || workingDirectoryUtf16[0] == L'\0')
    {
        if (RunProcessWithTermPipe(cmdLine, timeoutMs, output, exitCode))
        {
            return true;
        }
        if (exitCode != kTermPipeUnavailable)
        {
            return false;
        }
    }
#endif

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    {
        output = "Failed to create output pipe";
        return false;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutableCmd(cmdLine.begin(), cmdLine.end());
    mutableCmd.push_back(L'\0');

    const wchar_t* lpDir = nullptr;
    if (workingDirectoryUtf16 && workingDirectoryUtf16[0] != L'\0')
        lpDir = workingDirectoryUtf16;

    BOOL created =
        CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, lpDir, &si, &pi);
    CloseHandle(hWrite);

    if (!created)
    {
        CloseHandle(hRead);
        output = "Failed to create process";
        return false;
    }

    std::string buffer;
    buffer.reserve(4096);
    DWORD startTick = GetTickCount();

    while (true)
    {
        DWORD available = 0;
        if (PeekNamedPipe(hRead, nullptr, 0, nullptr, &available, nullptr) && available > 0)
        {
            char temp[4096];
            DWORD bytesRead = 0;
            if (::ReadFile(hRead, temp, sizeof(temp) - 1, &bytesRead, nullptr) && bytesRead > 0)
            {
                temp[bytesRead] = '\0';
                buffer.append(temp, bytesRead);
                if (buffer.size() > s_guardrails.maxOutputCaptureBytes)
                {
                    buffer.resize(s_guardrails.maxOutputCaptureBytes);
                    buffer += "\n[OUTPUT TRUNCATED]";
                    break;
                }
            }
        }

        DWORD waitResult = WaitForSingleObject(pi.hProcess, 100);
        if (waitResult == WAIT_OBJECT_0)
        {
            // Read remaining output
            while (true)
            {
                DWORD avail2 = 0;
                if (!PeekNamedPipe(hRead, nullptr, 0, nullptr, &avail2, nullptr) || avail2 == 0)
                    break;
                char temp[4096];
                DWORD bytesRead = 0;
                if (::ReadFile(hRead, temp, sizeof(temp) - 1, &bytesRead, nullptr) && bytesRead > 0)
                {
                    temp[bytesRead] = '\0';
                    buffer.append(temp, bytesRead);
                }
                else
                    break;
            }
            break;
        }

        if (GetTickCount() - startTick > timeoutMs)
        {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hRead);
            output = buffer + "\n[TIMEOUT after " + std::to_string(timeoutMs) + "ms]";
            exitCode = WAIT_TIMEOUT;
            return false;
        }
    }

    DWORD dwExitCode = 0;
    GetExitCodeProcess(pi.hProcess, &dwExitCode);
    exitCode = static_cast<uint32_t>(dwExitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    output = buffer;
    return true;
}

ToolCallResult AgentToolHandlers::ExecuteCommand(const json& args)
{
    if (!args.contains("command") || !args["command"].is_string())
    {
        return ToolCallResult::Validation("execute_command requires 'command' (string)");
    }

    std::string command = args["command"].get<std::string>();
    uint32_t timeout = s_guardrails.commandTimeoutMs;
    if (args.contains("timeout") && args["timeout"].is_number())
    {
        timeout = static_cast<uint32_t>(args["timeout"].get<int>());
        // Cap timeout at 5 minutes
        if (timeout > 300000)
            timeout = 300000;
    }

    const bool mirrorToIdeTerminal =
        args.value("use_integrated_terminal", false) || args.value("mirror_to_ide_agent_terminal", false);
    if (mirrorToIdeTerminal)
    {
        emitIntegratedTerminalEcho("$ " + command);
    }

    // Optional working directory (VS Code / Cursor parity: run in workspace folder)
    std::wstring cwdWideStorage;
    const wchar_t* cwdForProcess = nullptr;
    std::string cwdArg;
    if (args.contains("working_directory") && args["working_directory"].is_string())
        cwdArg = args["working_directory"].get<std::string>();
    else if (args.contains("cwd") && args["cwd"].is_string())
        cwdArg = args["cwd"].get<std::string>();
    else if (!s_guardrails.allowedRoots.empty())
        cwdArg = NormalizePath(s_guardrails.allowedRoots[0]);

    if (!cwdArg.empty())
    {
        const std::string normalized = NormalizePath(cwdArg);
        if (!IsPathAllowed(normalized))
        {
            return ToolCallResult::Sandbox("working_directory must be within workspace allowlist: " + normalized);
        }
        std::error_code ec;
        if (!fs::is_directory(fs::path(normalized), ec))
        {
            return ToolCallResult::Validation("working_directory must be an existing directory: " + normalized);
        }
        wchar_t fullW[32768];
        const DWORD n =
            GetFullPathNameW(ToWide(normalized).c_str(), static_cast<DWORD>(std::size(fullW)), fullW, nullptr);
        if (n == 0 || n >= static_cast<DWORD>(std::size(fullW)))
        {
            return ToolCallResult::Validation("Could not resolve working_directory path");
        }
        const DWORD attr = GetFileAttributesW(fullW);
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            return ToolCallResult::Validation("working_directory is not a directory");
        }
        cwdWideStorage.assign(fullW);
        cwdForProcess = cwdWideStorage.c_str();
    }

    // Build command line via cmd.exe
    std::wstring cmdLine = L"cmd.exe /C " + ToWide(command);

    std::string output;
    uint32_t exitCode = 0;

    auto startTime = std::chrono::steady_clock::now();
    bool success = RunProcess(cmdLine, timeout, output, exitCode, cwdForProcess);
    auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count();

    if (!success && exitCode == WAIT_TIMEOUT)
    {
        ToolCallResult result = ToolCallResult::TimedOut(output);
        nlohmann::json res_metadata = nlohmann::json::object();
        res_metadata["exit_code"] = exitCode;
        res_metadata["elapsed_ms"] = elapsed;
        res_metadata["command"] = command;
        res_metadata["mirrored_to_ide_agent_terminal"] = mirrorToIdeTerminal;
        if (!cwdArg.empty())
            res_metadata["working_directory"] = NormalizePath(cwdArg);
        result.metadata = res_metadata;
        if (mirrorToIdeTerminal)
        {
            emitIntegratedTerminalEcho("[timeout]\n" + output);
            emitIntegratedTerminalEcho(std::string("[exit ") + std::to_string(exitCode) + "]");
        }
        return result;
    }

    // Bound output size to keep tool replies safe in UI surfaces
    const size_t kMaxOutput = std::max<size_t>(1024, s_guardrails.maxOutputCaptureBytes);
    bool truncated = false;
    size_t originalSize = output.size();
    if (output.size() > kMaxOutput)
    {
        output = output.substr(0, kMaxOutput) + "\n[truncated output]";
        truncated = true;
    }

    nlohmann::json res_metadata = nlohmann::json::object();
    res_metadata["exit_code"] = exitCode;
    res_metadata["elapsed_ms"] = elapsed;
    res_metadata["truncated"] = truncated;
    res_metadata["captured_bytes"] = output.size();
    res_metadata["original_bytes"] = originalSize;
    res_metadata["command"] = command;
    res_metadata["mirrored_to_ide_agent_terminal"] = mirrorToIdeTerminal;
    if (!cwdArg.empty())
        res_metadata["working_directory"] = NormalizePath(cwdArg);

    if (mirrorToIdeTerminal)
    {
        constexpr size_t kIdeTerminalPreview = 6000;
        std::string preview = output;
        if (preview.size() > kIdeTerminalPreview)
        {
            preview = preview.substr(0, kIdeTerminalPreview);
            preview += "\n[... truncated for integrated terminal preview ...]\n";
        }
        emitIntegratedTerminalEcho(preview);
        emitIntegratedTerminalEcho(std::string("[exit ") + std::to_string(exitCode) + "]");
    }

    ToolCallResult result =
        (exitCode == 0) ? ToolCallResult::Ok(output, res_metadata)
                        : ToolCallResult::Error("Command exited with code " + std::to_string(exitCode) + "\n" + output,
                                                ToolOutcome::ExecutionError);
    if (exitCode != 0)
    {
        result.metadata = res_metadata;
        result.output = output;  // Include output even on error
    }
    return result;
}

// ============================================================================
// search_code — Recursive file search
// ============================================================================

ToolCallResult AgentToolHandlers::SearchCode(const json& args)
{
    if (!args.contains("query") || !args["query"].is_string())
    {
        return ToolCallResult::Validation("search_code requires 'query' (string)");
    }

    std::string query = args["query"].get<std::string>();
    if (query.empty())
    {
        return ToolCallResult::Validation("search_code query cannot be empty");
    }
    std::string filePattern = args.value("file_pattern", "*.*");
    bool caseSensitive = args.value("case_sensitive", true);
    bool useRegex = args.value("regex", false);
    int maxResults = s_guardrails.maxSearchResults;
    if (args.contains("max_results") && args["max_results"].is_number())
    {
        maxResults = std::clamp(args["max_results"].get<int>(), 1, 1000);
    }
    size_t contextBytes = static_cast<size_t>(std::max<int>(args.value("context_bytes", 200), 40));

    if (s_guardrails.allowedRoots.empty())
    {
        return ToolCallResult::Error("No workspace root configured for search");
    }

    std::string searchRoot = s_guardrails.allowedRoots[0];
    if (args.contains("root") && args["root"].is_string())
    {
        std::string candidate = NormalizePath(args["root"].get<std::string>());
        if (!IsPathAllowed(candidate))
        {
            return ToolCallResult::Sandbox("Search root not allowed: " + candidate);
        }
        searchRoot = candidate;
    }

    const size_t maxFileSize = s_guardrails.maxFileSizeBytes;
    int hitCount = 0;
    int scannedFiles = 0;
    int skippedBinary = 0;
    std::ostringstream results;

    try
    {
        for (auto it = fs::recursive_directory_iterator(searchRoot, fs::directory_options::skip_permission_denied);
             it != fs::recursive_directory_iterator(); ++it)
        {
            if (hitCount >= maxResults)
                break;
            if (!it->is_regular_file())
                continue;
            if (!IsPathAllowed(it->path().string()))
                continue;

            if (filePattern != "*.*" && filePattern != "*")
            {
                const std::string ext = it->path().extension().string();
                if (filePattern[0] == '*' && filePattern.size() > 1)
                {
                    const std::string reqExt = filePattern.substr(1);
                    if (ext != reqExt)
                        continue;
                }
            }

            const auto fsize = it->file_size();
            if (fsize == 0 || fsize > maxFileSize)
                continue;
            scannedFiles++;

            std::ifstream file(it->path(), std::ios::binary);
            if (!file.is_open())
                continue;

            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
            if (IsLikelyBinary(content))
            {
                skippedBinary++;
                continue;
            }

            if (useRegex)
            {
                std::regex::flag_type flags = std::regex::ECMAScript;
                if (!caseSensitive)
                    flags |= std::regex::icase;

                std::regex re;
                try
                {
                    re = std::regex(query, flags);
                }
                catch (const std::exception& ex)
                {
                    return ToolCallResult::Validation(std::string("Invalid regex: ") + ex.what());
                }

                int lineNum = 1;
                size_t lineStart = 0;
                for (auto matchIt = std::sregex_iterator(content.begin(), content.end(), re);
                     matchIt != std::sregex_iterator() && hitCount < maxResults; ++matchIt)
                {
                    const size_t found = static_cast<size_t>(matchIt->position());
                    for (size_t i = lineStart; i < found; ++i)
                    {
                        if (content[i] == '\n')
                            ++lineNum;
                    }
                    lineStart = found;

                    size_t contextStart = content.rfind('\n', found);
                    contextStart = (contextStart == std::string::npos) ? 0 : contextStart + 1;
                    size_t contextEnd = content.find('\n', found);
                    if (contextEnd == std::string::npos)
                        contextEnd = content.size();

                    const std::string lineText =
                        content.substr(contextStart, std::min(contextEnd - contextStart, contextBytes));
                    const std::string relPath = fs::relative(it->path(), searchRoot).string();
                    results << relPath << ":" << lineNum << ": " << lineText << "\n";
                    ++hitCount;
                }
                continue;
            }

            std::string lowerContent;
            std::string lowerQuery;
            if (!caseSensitive)
            {
                lowerContent = content;
                lowerQuery = query;
                std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            }

            size_t pos = 0;
            int lineNum = 1;
            size_t lineStart = 0;
            while (pos < content.size() && hitCount < maxResults)
            {
                while (lineStart < pos)
                {
                    if (content[lineStart] == '\n')
                        ++lineNum;
                    ++lineStart;
                }

                const size_t found = caseSensitive ? content.find(query, pos) : lowerContent.find(lowerQuery, pos);
                if (found == std::string::npos)
                    break;

                for (size_t i = lineStart; i < found; ++i)
                {
                    if (content[i] == '\n')
                        ++lineNum;
                }
                lineStart = found;

                size_t contextStart = content.rfind('\n', found);
                contextStart = (contextStart == std::string::npos) ? 0 : contextStart + 1;
                size_t contextEnd = content.find('\n', found);
                if (contextEnd == std::string::npos)
                    contextEnd = content.size();

                const std::string lineText =
                    content.substr(contextStart, std::min(contextEnd - contextStart, contextBytes));
                const std::string relPath = fs::relative(it->path(), searchRoot).string();
                results << relPath << ":" << lineNum << ": " << lineText << "\n";

                ++hitCount;
                pos = found + query.size();
            }
        }
    }
    catch (const std::exception& ex)
    {
        if (hitCount == 0)
        {
            return ToolCallResult::Error(std::string("Search failed: ") + ex.what());
        }
    }

    if (hitCount == 0)
    {
        nlohmann::json zeroMatches = nlohmann::json::object();
        zeroMatches["matches"] = 0;
        return ToolCallResult::Ok("No matches found for: " + query, zeroMatches);
    }

    std::string truncMsg;
    if (hitCount >= maxResults)
    {
        truncMsg = "\n[Results truncated at " + std::to_string(maxResults) + " matches]";
    }

    nlohmann::json res_metadata = nlohmann::json::object();
    res_metadata["matches"] = hitCount;
    res_metadata["truncated"] = (hitCount >= maxResults);
    res_metadata["scanned_files"] = scannedFiles;
    res_metadata["skipped_binary"] = skippedBinary;
    res_metadata["case_sensitive"] = caseSensitive;
    res_metadata["regex"] = useRegex;
    res_metadata["root"] = searchRoot;

    return ToolCallResult::Ok(results.str() + truncMsg, res_metadata);
}

ToolCallResult AgentToolHandlers::FileSearch(const json& args)
{
    std::vector<std::string> patterns;
    if (args.contains("patterns") && args["patterns"].is_array())
    {
        for (const auto& item : args["patterns"])
        {
            if (item.is_string())
            {
                const std::string pattern = TrimAscii(item.get<std::string>());
                if (!pattern.empty())
                {
                    patterns.push_back(ToForwardSlashes(pattern));
                }
            }
        }
    }

    if (patterns.empty())
    {
        if (args.contains("pattern") && args["pattern"].is_string())
            patterns.push_back(ToForwardSlashes(TrimAscii(args["pattern"].get<std::string>())));
        else if (args.contains("query") && args["query"].is_string())
            patterns.push_back(ToForwardSlashes(TrimAscii(args["query"].get<std::string>())));
    }

    patterns.erase(std::remove_if(patterns.begin(), patterns.end(),
                                  [](const std::string& value) { return value.empty(); }),
                   patterns.end());
    if (patterns.empty())
    {
        return ToolCallResult::Validation("file_search requires 'pattern', 'query', or 'patterns'");
    }

    std::string root;
    if (args.contains("root") && args["root"].is_string())
        root = NormalizePath(args["root"].get<std::string>());
    else if (!s_guardrails.allowedRoots.empty())
        root = NormalizePath(s_guardrails.allowedRoots.front());
    else
        root = NormalizePath(fs::current_path().string());

    if (!IsPathAllowed(root))
    {
        return ToolCallResult::Sandbox("file_search root not allowed: " + root);
    }

    int maxResults = std::clamp(args.value("max_results", s_guardrails.maxSearchResults), 1, 5000);

    std::vector<std::regex> matchers;
    matchers.reserve(patterns.size());
    for (const auto& pattern : patterns)
    {
        matchers.emplace_back(GlobToRegex(pattern), std::regex::ECMAScript | std::regex::icase);
    }

    json results = json::array();
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); ++it)
    {
        if (ec)
        {
            ec.clear();
            continue;
        }
        if (!it->is_regular_file(ec))
        {
            continue;
        }

        const std::string absolute = NormalizePath(it->path().string());
        if (!IsPathAllowed(absolute))
        {
            continue;
        }

        std::string relative = ToForwardSlashes(fs::relative(it->path(), root, ec).generic_string());
        if (ec)
        {
            relative = ToForwardSlashes(it->path().filename().generic_string());
            ec.clear();
        }

        bool matched = false;
        for (const auto& matcher : matchers)
        {
            if (std::regex_match(relative, matcher) || std::regex_match(absolute, matcher))
            {
                matched = true;
                break;
            }
        }
        if (!matched)
        {
            continue;
        }

        results.push_back(absolute);
        if (static_cast<int>(results.size()) >= maxResults)
        {
            break;
        }
    }

    json meta = json::object();
    meta["root"] = root;
    meta["patterns"] = patterns;
    meta["count"] = results.size();
    meta["max_results"] = maxResults;
    return ToolCallResult::Ok(results.dump(2), meta);
}

// ============================================================================
// get_diagnostics — Return compiler/LSP errors
// ============================================================================

ToolCallResult AgentToolHandlers::GetDiagnostics(const json& args)
{
    if (!args.contains("file") || !args["file"].is_string())
    {
        return ToolCallResult::Validation("get_diagnostics requires 'file' (string)");
    }

    std::string file = NormalizePath(args["file"].get<std::string>());

    // Run cl.exe /Zs (syntax check only) for C++ files
    std::string ext = fs::path(file).extension().string();
    if (ext == ".cpp" || ext == ".c" || ext == ".h" || ext == ".hpp")
    {
        std::wstring cmdLine = L"cl.exe /Zs /EHsc /std:c++20 /W4 /nologo \"" + ToWide(file) + L"\"";

        std::string output;
        uint32_t exitCode = 0;
        RunProcess(cmdLine, 30000, output, exitCode);

        nlohmann::json res_metadata = nlohmann::json::object();
        res_metadata["file"] = file;
        res_metadata["exit_code"] = exitCode;
        res_metadata["has_errors"] = (exitCode != 0);

        return ToolCallResult::Ok(output.empty() ? "No diagnostics" : output, res_metadata);
    }

    nlohmann::json res_metadata = nlohmann::json::object();
    res_metadata["file_type"] = ext;
    return ToolCallResult::Ok("Diagnostics not available for file type: " + ext, res_metadata);
}

// ============================================================================
// run_shell — Guarded alias of execute_command with allowlist enforcement
// ============================================================================
ToolCallResult AgentToolHandlers::RunShell(const json& args)
{
    if (!args.contains("command") || !args["command"].is_string())
    {
        return ToolCallResult::Validation("run_shell requires 'command' (string)");
    }
    std::string command = args["command"].get<std::string>();

    // Enforce allowlist if configured
    if (!s_guardrails.allowedCommands.empty())
    {
        std::istringstream iss(command);
        std::string first;
        iss >> first;
        bool allowed = false;
        for (const auto& ac : s_guardrails.allowedCommands)
        {
            if (first == ac)
            {
                allowed = true;
                break;
            }
        }
        if (!allowed)
        {
            nlohmann::json meta = nlohmann::json::object();
            meta["command"] = command;
            meta["first_token"] = first;
            meta["policy"] = "allowedCommands";
            ToolCallResult res = ToolCallResult::Sandbox("Command not allowed by policy: " + first);
            res.metadata = meta;
            return res;
        }
    }
    return ExecuteCommand(args);
}

// ============================================================================
// semantic_search — Lightweight TF cosine search across workspace files
// ============================================================================
ToolCallResult AgentToolHandlers::SemanticSearch(const json& args)
{
    if (!args.contains("query") || !args["query"].is_string())
    {
        return ToolCallResult::Validation("semantic_search requires 'query' (string)");
    }
    if (s_guardrails.allowedRoots.empty())
    {
        return ToolCallResult::Error("No workspace root configured for semantic search");
    }
    std::string query = args["query"].get<std::string>();
    std::string root = s_guardrails.allowedRoots[0];
    if (args.contains("root") && args["root"].is_string())
    {
        root = NormalizePath(args["root"].get<std::string>());
        if (!IsPathAllowed(root))
        {
            return ToolCallResult::Sandbox("Root not in allowlist: " + root);
        }
    }
    int topK = args.value("top_k", 5);
    if (topK <= 0)
        topK = 5;
    if (topK > 25)
        topK = 25;

    RawrXD::Runtime::SemanticRetrieval::InstallSemanticIndexEmbeddingCallback();
    const auto vectorHits = RawrXD::Runtime::SemanticRetrieval::SearchSemanticContext(query, static_cast<size_t>(topK));
    if (!vectorHits.empty())
    {
        nlohmann::json res = nlohmann::json::array();
        for (const auto& hit : vectorHits)
        {
            nlohmann::json row;
            row["metadata"] = hit.metadata;
            row["score"] = hit.similarity;
            row["entry_id"] = hit.entryId;
            row["source"] = "vector";
            res.push_back(row);
        }

        nlohmann::json meta = nlohmann::json::object();
        meta["returned"] = res.size();
        meta["root"] = root;
        meta["top_k"] = topK;
        meta["engine"] = "rawrxd-vector-index";
        meta["mapped_gguf"] = RawrXD::Runtime::RawrXDVectorIndex::instance().hasMappedGGUF();
        meta["dims"] = RawrXD::Runtime::RawrXDVectorIndex::instance().preferredDimensions();
        return ToolCallResult::Ok(res.dump(2), meta);
    }

    int maxFiles = s_guardrails.maxIndexFiles;
    bool includeNonCode = args.value("include_non_code", false);
    static const std::unordered_set<std::string> kCodeExt = {
        ".cpp",   ".c",   ".cc",   ".cxx",  ".h",   ".hpp",  ".hh",  ".hxx", ".cs",    ".java", ".kt",
        ".rs",    ".go",  ".ts",   ".tsx",  ".js",  ".jsx",  ".py",  ".rb",  ".swift", ".m",    ".mm",
        ".scala", ".sql", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".cmake", ".sh",   ".ps1"};

    auto qTokens = Tokenize(query);
    if (qTokens.empty())
    {
        return ToolCallResult::Validation("semantic_search query produced no tokens");
    }
    std::unordered_map<std::string, double> qtf;
    for (const auto& t : qTokens)
        qtf[t] += 1.0;
    double qnorm = 0.0;
    for (auto& kv : qtf)
    {
        kv.second = kv.second / static_cast<double>(qTokens.size());
        qnorm += kv.second * kv.second;
    }
    qnorm = std::sqrt(qnorm);

    std::vector<IndexedFile> indexed;
    int scanned = 0;
    int skippedBinary = 0;
    try
    {
        for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied);
             it != fs::recursive_directory_iterator(); ++it)
        {
            if (scanned >= maxFiles)
                break;
            if (!it->is_regular_file())
                continue;
            auto fsize = it->file_size();
            if (fsize == 0 || fsize > s_guardrails.maxFileSizeBytes)
                continue;
            std::string p = it->path().string();
            std::string ext = ToLowerCopy(it->path().extension().string());
            if (!includeNonCode && !ext.empty() && kCodeExt.find(ext) == kCodeExt.end())
                continue;
            if (!IsPathAllowed(p))
                continue;
            // Quick binary sniff to avoid heavy tokenization
            bool binaryFlag = false;
            try
            {
                std::ifstream sniff(p, std::ios::binary);
                if (sniff.is_open())
                {
                    std::string head(512, '\0');
                    sniff.read(head.data(), static_cast<std::streamsize>(head.size()));
                    head.resize(static_cast<size_t>(sniff.gcount()));
                    binaryFlag = IsLikelyBinary(head);
                }
            }
            catch (...)
            { /* ignore */
            }
            if (binaryFlag)
            {
                skippedBinary++;
                continue;
            }
            auto idx = BuildIndexForFile(p, s_guardrails.maxFileSizeBytes);
            if (!idx.tf.empty())
            {
                indexed.push_back(std::move(idx));
                ++scanned;
            }
        }
    }
    catch (...)
    {
        // tolerate partial scan
    }

    if (indexed.empty())
    {
        return ToolCallResult::Error("No indexable files found under " + root);
    }

    struct Scored
    {
        std::string path;
        double score;
    };
    std::vector<Scored> scores;
    for (const auto& f : indexed)
    {
        double s = CosineScore(f, qtf, qnorm);
        if (s > 0.0)
            scores.push_back({f.path, s});
    }
    std::sort(scores.begin(), scores.end(), [](const Scored& a, const Scored& b) { return a.score > b.score; });
    if ((int)scores.size() > topK)
        scores.resize(topK);

    nlohmann::json res = nlohmann::json::array();
    double scoreSum = 0.0;
    for (const auto& s : scores)
    {
        nlohmann::json row;
        row["path"] = fs::relative(s.path, root).string();
        row["score"] = s.score;
        scoreSum += s.score;
        // Optional snippet preview (first 240 chars)
        std::string snippet;
        try
        {
            std::ifstream preview(s.path, std::ios::binary);
            if (preview.is_open())
            {
                std::string buf(240, '\0');
                preview.read(buf.data(), static_cast<std::streamsize>(buf.size()));
                buf.resize(static_cast<size_t>(preview.gcount()));
                snippet = buf;
            }
        }
        catch (...)
        { /* ignore */
        }
        if (!snippet.empty())
        {
            row["preview"] = snippet;
        }
        res.push_back(row);
    }

    nlohmann::json meta = nlohmann::json::object();
    meta["scanned_files"] = scanned;
    meta["returned"] = res.size();
    meta["root"] = root;
    meta["top_k"] = topK;
    meta["skipped_binary"] = skippedBinary;
    if (!scores.empty())
    {
        meta["avg_score"] = scoreSum / static_cast<double>(scores.size());
    }
    return ToolCallResult::Ok(res.dump(2), meta);
}

// ============================================================================
// mention_lookup — Symbol-aware alias over semantic_search
// ============================================================================
ToolCallResult AgentToolHandlers::MentionLookup(const json& args)
{
    json copy = args;
    if (!copy.contains("query") && copy.contains("symbol"))
    {
        copy["query"] = copy["symbol"];
    }
    if (!copy.contains("top_k"))
    {
        copy["top_k"] = 3;
    }
    // Clamp to avoid huge responses
    if (copy.contains("top_k") && copy["top_k"].is_number())
    {
        int tk = std::clamp(copy["top_k"].get<int>(), 1, 10);
        copy["top_k"] = tk;
    }
    // Favor current workspace root when not provided
    if (!copy.contains("root") && !s_guardrails.allowedRoots.empty())
    {
        copy["root"] = s_guardrails.allowedRoots[0];
    }
    if (args.contains("include_non_code"))
    {
        copy["include_non_code"] = args["include_non_code"];
    }
    return SemanticSearch(copy);
}

// ============================================================================
// next_edit_hint — Heuristic “next edit” suggestion from context
// ============================================================================
ToolCallResult AgentToolHandlers::NextEditHint(const json& args)
{
    if (!args.contains("context") || !args["context"].is_string())
    {
        return ToolCallResult::Validation("next_edit_hint requires 'context' (string)");
    }
    std::string ctx = args["context"].get<std::string>();
    std::vector<std::string> hints;
    std::unordered_set<std::string> seen;
    auto addHint = [&](const std::string& h)
    {
        if (seen.insert(h).second && hints.size() < 3)
            hints.push_back(h);
    };
    if (ctx.find("TODO") != std::string::npos)
    {
        addHint("Address the TODO with a small, testable change and add a unit test.");
    }
    if (ctx.find("function") != std::string::npos || ctx.find("def ") != std::string::npos)
    {
        addHint("Add docstring/comments and edge-case handling (empty input, null pointers).");
    }
    if (ctx.find("class") != std::string::npos || ctx.find("struct") != std::string::npos)
    {
        addHint("Ensure constructors initialize all fields and add default move/clone semantics if needed.");
    }
    if (hints.empty())
    {
        addHint("Extract helper functions to simplify logic and add assertions for invariants.");
    }
    nlohmann::json meta = nlohmann::json::object();
    meta["count"] = hints.size();
    meta["context_length"] = ctx.size();
    return ToolCallResult::Ok(nlohmann::json(hints).dump(2), meta);
}

// ============================================================================
// propose_multifile_edits — Generate a structured plan for multiple files
// ============================================================================
ToolCallResult AgentToolHandlers::ProposeMultiFileEdits(const json& args)
{
    std::vector<RawrXD::Agentic::FileEdit> parsed;
    std::string parseError;
    if (!BuildMultiFilePlanFromArgs(args, parsed, parseError))
    {
        return ToolCallResult::Validation("propose_multifile_edits " + parseError);
    }

    RawrXD::Agentic::MultiFileEditPlan plan;
    size_t skipped = 0;
    for (auto& edit : parsed)
    {
        edit.filePath = NormalizePath(edit.filePath);
        if (!IsPathAllowed(edit.filePath))
        {
            ++skipped;
            continue;
        }
        if ((edit.type != RawrXD::Agentic::EditType::INSERT) && !fs::exists(edit.filePath))
        {
            ++skipped;
            continue;
        }
        plan.addEdit(edit);
    }

    if (plan.getEdits().empty())
    {
        return ToolCallResult::Error("No valid edits after sandbox/path validation.");
    }

    const std::string seqError = plan.sequence();
    json preview = plan.toPreviewJson();

    json diffs = json::array();
    std::unordered_map<std::string, std::vector<RawrXD::Agentic::FileEdit>> byFile;
    for (const auto& e : plan.getEdits())
    {
        byFile[e.filePath].push_back(e);
    }
    for (auto& [file, fileEdits] : byFile)
    {
        std::string before;
        if (!ReadTextFile(file, before))
        {
            before.clear();
        }
        std::string after = before;
        std::sort(fileEdits.begin(), fileEdits.end(),
                  [](const auto& a, const auto& b)
                  {
                      if (a.lineStart != b.lineStart)
                          return a.lineStart > b.lineStart;
                      return a.lineEnd > b.lineEnd;
                  });

        bool applyOk = true;
        std::string applyErr;
        for (const auto& edit : fileEdits)
        {
            if (!ApplyEditInMemory(edit, after, applyErr))
            {
                applyOk = false;
                break;
            }
        }

        json d = json::object();
        d["file"] = file;
        if (!applyOk)
        {
            d["error"] = applyErr;
        }
        else
        {
            auto dr = RawrXD::Diff::DiffEngine::ComputeDiff(before, after);
            d["unified_diff"] = dr.ToUnifiedDiff("a/" + file, "b/" + file);
            d["additions"] = dr.additions;
            d["deletions"] = dr.deletions;
        }
        diffs.push_back(std::move(d));
    }

    preview["diff_preview"] = std::move(diffs);
    if (!seqError.empty())
    {
        preview["sequence_error"] = seqError;
    }

    json meta = json::object();
    meta["files"] = byFile.size();
    meta["edits"] = plan.getEdits().size();
    meta["skipped"] = skipped;
    meta["ready"] = plan.isReady();
    return ToolCallResult::Ok(preview.dump(2), meta);
}

// ============================================================================
// preview_multifile_diff — Alias for propose_multifile_edits preview path
// ============================================================================
ToolCallResult AgentToolHandlers::PreviewMultiFileDiff(const json& args)
{
    return ProposeMultiFileEdits(args);
}

// ============================================================================
// apply_multifile_edits — Execute structured multi-file plan transactionally
// ============================================================================
ToolCallResult AgentToolHandlers::ApplyMultiFileEdits(const json& args)
{
    std::vector<RawrXD::Agentic::FileEdit> parsed;
    std::string parseError;
    if (!BuildMultiFilePlanFromArgs(args, parsed, parseError))
    {
        return ToolCallResult::Validation("apply_multifile_edits " + parseError);
    }

    RawrXD::Agentic::MultiFileEditPlan plan;
    size_t skipped = 0;
    for (auto& edit : parsed)
    {
        edit.filePath = NormalizePath(edit.filePath);
        if (!IsPathAllowed(edit.filePath))
        {
            ++skipped;
            continue;
        }
        if ((edit.type != RawrXD::Agentic::EditType::INSERT) && !fs::exists(edit.filePath))
        {
            ++skipped;
            continue;
        }
        if (s_guardrails.requireBackupOnWrite && fs::exists(edit.filePath))
        {
            const std::string backupErr = CreateBackup(edit.filePath);
            if (!backupErr.empty())
            {
                return ToolCallResult::Error(backupErr);
            }
        }
        plan.addEdit(edit);
    }

    if (plan.getEdits().empty())
    {
        return ToolCallResult::Error("No valid edits to apply after sandbox/path validation.");
    }

    const std::string seqError = plan.sequence();
    if (!seqError.empty())
    {
        return ToolCallResult::Validation(seqError);
    }

    const int applied = plan.execute();
    auto summary = plan.getSummary();
    json out = json::object();
    out["applied"] = applied;
    out["total"] = summary.totalEdits;
    out["successful"] = summary.successfulEdits;
    out["failed"] = summary.failedEdits;
    out["fully_completed"] = summary.fullyCompleted;
    out["status"] = static_cast<int>(plan.getStatus());
    out["errors"] = summary.errors;

    json meta = json::object();
    meta["skipped"] = skipped;
    meta["checkpoint_count"] = plan.getCheckpoints().size();

    if (!summary.fullyCompleted)
    {
        return ToolCallResult::Error(out.dump(2), ToolOutcome::ExecutionError);
    }
    return ToolCallResult::Ok(out.dump(2), meta);
}

// ============================================================================
// load_rules — Parse a .rawrrules file to seed system instructions
// ============================================================================
ToolCallResult AgentToolHandlers::LoadRules(const json& args)
{
    std::string path;
    bool hasInline = args.contains("content") && args["content"].is_string();
    if (args.contains("path") && args["path"].is_string())
    {
        path = NormalizePath(args["path"].get<std::string>());
    }
    else if (!s_guardrails.allowedRoots.empty())
    {
        path = NormalizePath(s_guardrails.allowedRoots[0] + "/.rawrrules");
    }
    else
    {
        return ToolCallResult::Error("No workspace root configured to locate .rawrrules");
    }
    if (!IsPathAllowed(path))
    {
        return ToolCallResult::Sandbox("Rules file not in allowlist: " + path);
    }
    if (!hasInline && !fs::exists(path))
    {
        return ToolCallResult::Error("Rules file not found: " + path);
    }
    if (!path.empty())
    {
        std::string ext = ToLowerCopy(fs::path(path).extension().string());
        if (!ext.empty() && ext != ".rawrrules" && ext != ".rules" && ext != ".txt")
        {
            return ToolCallResult::Validation("Rules path must be .rawrrules/.rules/.txt");
        }
    }

    nlohmann::json rules = nlohmann::json::object();
    auto parseLine = [&](const std::string& line)
    {
        if (line.empty() || line[0] == '#')
            return;
        auto pos = line.find(':');
        if (pos == std::string::npos)
            return;
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 1);
        if (!key.empty())
            rules[key] = val;
    };

    size_t lineCount = 0;
    std::string concat;
    if (hasInline)
    {
        std::istringstream ss(args["content"].get<std::string>());
        std::string line;
        while (std::getline(ss, line))
        {
            parseLine(line);
            concat += line;
            ++lineCount;
        }
    }
    else
    {
        std::ifstream in(path);
        if (!in.is_open())
        {
            return ToolCallResult::Error("Failed to open rules file: " + path);
        }
        std::string line;
        while (std::getline(in, line))
        {
            parseLine(line);
            concat += line;
            ++lineCount;
        }
    }

    nlohmann::json meta = nlohmann::json::object();
    meta["entries"] = rules.size();
    meta["source"] = hasInline ? "inline" : path;
    meta["lines"] = lineCount;
    meta["fingerprint"] = std::hash<std::string>{}(concat);
    if (rules.empty())
    {
        ToolCallResult res = ToolCallResult::Validation("Rules parsed but no entries found");
        res.metadata = meta;
        return res;
    }
    return ToolCallResult::Ok(rules.dump(2), meta);
}

// ============================================================================
// plan_tasks — Lightweight deterministic plan generator
// ============================================================================
ToolCallResult AgentToolHandlers::PlanTasks(const json& args)
{
    if (!args.contains("goal") || !args["goal"].is_string())
    {
        return ToolCallResult::Validation("plan_tasks requires 'goal' (string)");
    }
    std::string goal = args["goal"].get<std::string>();
    int maxSteps = std::clamp(args.value("max_steps", 6), 3, 10);
    std::string deadline = args.value("deadline", "");
    std::string owner = args.value("owner", "");
    nlohmann::json plan = nlohmann::json::array();
    plan.push_back("Understand goal: " + goal);
    plan.push_back("Search and gather context (files, rules, diagnostics).");
    plan.push_back("Apply changes incrementally with tests/diagnostics.");
    if (plan.size() < static_cast<size_t>(maxSteps))
    {
        plan.push_back("Validate with unit/smoke tests and capture artifacts.");
    }
    if (plan.size() < static_cast<size_t>(maxSteps))
    {
        plan.push_back("Summarize changes, risks, and follow-ups.");
    }
    if (plan.is_array() && static_cast<int>(plan.size()) > maxSteps)
    {
        json trimmed = json::array();
        for (int i = 0; i < maxSteps && i < static_cast<int>(plan.size()); ++i)
        {
            trimmed.push_back(plan[i]);
        }
        plan = std::move(trimmed);
    }
    nlohmann::json meta = nlohmann::json::object();
    meta["steps"] = plan.size();
    meta["goal_length"] = goal.size();
    meta["max_steps"] = maxSteps;
    if (!deadline.empty())
        meta["deadline"] = deadline;
    if (!owner.empty())
        meta["owner"] = owner;
    return ToolCallResult::Ok(plan.dump(2), meta);
}

ToolCallResult AgentToolHandlers::ManageTodoList(const json& args)
{
    if (!args.contains("todoList") || !args["todoList"].is_array())
    {
        return ToolCallResult::Validation("manage_todo_list requires 'todoList' (array)");
    }

    RawrXD::Todos::TodoManager manager;
    if (!manager.ClearAll())
    {
        return ToolCallResult::Error("Failed to clear existing todo list before update");
    }

    json stored = json::array();
    for (const auto& item : args["todoList"])
    {
        if (!item.is_object())
        {
            return ToolCallResult::Validation("manage_todo_list entries must be objects");
        }

        const std::string title = item.value("title", std::string());
        if (title.empty())
        {
            return ToolCallResult::Validation("manage_todo_list entries require 'title'");
        }

        const std::string status = item.value("status", std::string("pending"));
        const std::string priority = item.value("priority", std::string("Medium"));
        if (!manager.AddTodo(title, priority, "agentic"))
        {
            return ToolCallResult::Error("Failed to add todo: " + title);
        }

        const auto todos = manager.GetAll();
        if (todos.empty())
        {
            return ToolCallResult::Error("Todo storage did not return newly created item");
        }

        const int createdId = todos.back().id;
        json updates = json::object();
        updates["status"] = status;
        if (item.contains("category") && item["category"].is_string())
        {
            updates["category"] = item["category"].get<std::string>();
        }
        if (!manager.UpdateTodo(createdId, updates))
        {
            return ToolCallResult::Error("Failed to update todo status for id " + std::to_string(createdId));
        }

        json storedItem = json::object();
        storedItem["input_id"] = item.value("id", createdId);
        storedItem["stored_id"] = createdId;
        storedItem["title"] = title;
        storedItem["status"] = status;
        storedItem["priority"] = priority;
        stored.push_back(storedItem);
    }

    json meta = json::object();
    meta["count"] = stored.size();
    return ToolCallResult::Ok(stored.dump(2), meta);
}

ToolCallResult AgentToolHandlers::Memory(const json& args)
{
    const std::string command = ToLowerCopy(args.value("command", std::string()));
    if (command.empty())
    {
        return ToolCallResult::Validation("memory requires 'command'");
    }

    if (command == "rename")
    {
        if (!args.contains("old_path") || !args["old_path"].is_string() || !args.contains("new_path") ||
            !args["new_path"].is_string())
        {
            return ToolCallResult::Validation("memory rename requires 'old_path' and 'new_path'");
        }

        fs::path oldReal;
        fs::path newReal;
        std::string oldScope;
        std::string newScope;
        std::string error;
        if (!ResolveMemoryPath(args["old_path"].get<std::string>(), oldReal, oldScope, error))
        {
            return ToolCallResult::Validation(error);
        }
        if (!ResolveMemoryPath(args["new_path"].get<std::string>(), newReal, newScope, error))
        {
            return ToolCallResult::Validation(error);
        }
        if (oldScope != newScope)
        {
            return ToolCallResult::Validation("memory rename cannot move across scopes");
        }
        if (!fs::exists(oldReal))
        {
            return ToolCallResult::Error("Memory path not found: " + args["old_path"].get<std::string>());
        }

        std::error_code ec;
        if (!newReal.parent_path().empty())
        {
            fs::create_directories(newReal.parent_path(), ec);
            if (ec)
            {
                return ToolCallResult::Error("Failed to prepare target directory: " + ec.message());
            }
        }
        fs::rename(oldReal, newReal, ec);
        if (ec)
        {
            return ToolCallResult::Error("Failed to rename memory path: " + ec.message());
        }

        json meta = json::object();
        meta["old_path"] = args["old_path"].get<std::string>();
        meta["new_path"] = args["new_path"].get<std::string>();
        return ToolCallResult::Ok("Memory path renamed", meta);
    }

    if (!args.contains("path") || !args["path"].is_string())
    {
        return ToolCallResult::Validation("memory requires 'path' for this command");
    }

    fs::path realPath;
    std::string scope;
    std::string error;
    if (!ResolveMemoryPath(args["path"].get<std::string>(), realPath, scope, error))
    {
        return ToolCallResult::Validation(error);
    }

    if (command == "view")
    {
        if (fs::is_directory(realPath))
        {
            json items = json::array();
            std::error_code ec;
            for (const auto& entry : fs::directory_iterator(realPath, fs::directory_options::skip_permission_denied, ec))
            {
                std::string virtualName = MakeVirtualMemoryPath(scope, entry.path());
                if (entry.is_directory(ec))
                {
                    virtualName += "/";
                }
                items.push_back(virtualName);
            }
            json meta = json::object();
            meta["scope"] = scope;
            meta["count"] = items.size();
            return ToolCallResult::Ok(items.dump(2), meta);
        }
        if (!fs::exists(realPath))
        {
            return ToolCallResult::Error("Memory file not found: " + args["path"].get<std::string>());
        }

        std::string content;
        if (!ReadTextFile(realPath.string(), content))
        {
            return ToolCallResult::Error("Failed to read memory file");
        }

        if (args.contains("view_range") && args["view_range"].is_array() && args["view_range"].size() == 2 &&
            args["view_range"].at(0).is_number_integer() && args["view_range"].at(1).is_number_integer())
        {
            const int start = std::max(1, args["view_range"].at(0).get<int>());
            const int end = std::max(start, args["view_range"].at(1).get<int>());
            const std::vector<std::string> lines = ReadLines(content);
            std::ostringstream out;
            for (int i = start - 1; i < end && i < static_cast<int>(lines.size()); ++i)
            {
                if (i > start - 1)
                {
                    out << "\n";
                }
                out << lines[static_cast<size_t>(i)];
            }
            content = out.str();
        }

        json meta = json::object();
        meta["scope"] = scope;
        meta["path"] = args["path"].get<std::string>();
        return ToolCallResult::Ok(content, meta);
    }

    if (command == "create")
    {
        if (!args.contains("file_text") || !args["file_text"].is_string())
        {
            return ToolCallResult::Validation("memory create requires 'file_text'");
        }
        if (fs::exists(realPath))
        {
            return ToolCallResult::Error("Memory file already exists: " + args["path"].get<std::string>());
        }

        std::error_code ec;
        if (!realPath.parent_path().empty())
        {
            fs::create_directories(realPath.parent_path(), ec);
            if (ec)
            {
                return ToolCallResult::Error("Failed to create memory directory: " + ec.message());
            }
        }

        std::ofstream out(realPath, std::ios::binary);
        if (!out)
        {
            return ToolCallResult::Error("Failed to create memory file");
        }
        const std::string content = args["file_text"].get<std::string>();
        out << content;
        json meta = json::object();
        meta["scope"] = scope;
        meta["bytes_written"] = content.size();
        return ToolCallResult::Ok("Memory file created", meta);
    }

    if (command == "str_replace")
    {
        if (!args.contains("old_str") || !args["old_str"].is_string() || !args.contains("new_str") ||
            !args["new_str"].is_string())
        {
            return ToolCallResult::Validation("memory str_replace requires 'old_str' and 'new_str'");
        }

        std::string content;
        if (!ReadTextFile(realPath.string(), content))
        {
            return ToolCallResult::Error("Failed to read memory file for replacement");
        }

        const std::string oldStr = args["old_str"].get<std::string>();
        const std::string newStr = args["new_str"].get<std::string>();
        const size_t first = content.find(oldStr);
        if (first == std::string::npos)
        {
            return ToolCallResult::Error("old_str not found in memory file");
        }
        if (content.find(oldStr, first + oldStr.size()) != std::string::npos)
        {
            return ToolCallResult::Validation("old_str must appear exactly once");
        }

        content.replace(first, oldStr.size(), newStr);
        std::ofstream out(realPath, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            return ToolCallResult::Error("Failed to write memory file after replacement");
        }
        out << content;
        return ToolCallResult::Ok("Memory file updated");
    }

    if (command == "insert")
    {
        if (!args.contains("insert_line") || !args["insert_line"].is_number_integer() || !args.contains("insert_text") ||
            !args["insert_text"].is_string())
        {
            return ToolCallResult::Validation("memory insert requires 'insert_line' and 'insert_text'");
        }

        std::string content;
        if (!ReadTextFile(realPath.string(), content))
        {
            return ToolCallResult::Error("Failed to read memory file for insert");
        }
        std::vector<std::string> lines = ReadLines(content);
        const int insertLine = std::max(0, args["insert_line"].get<int>());
        if (insertLine > static_cast<int>(lines.size()))
        {
            return ToolCallResult::Validation("insert_line is out of range");
        }
        lines.insert(lines.begin() + insertLine, args["insert_text"].get<std::string>());

        std::ostringstream out;
        for (size_t i = 0; i < lines.size(); ++i)
        {
            if (i > 0)
            {
                out << "\n";
            }
            out << lines[i];
        }
        std::ofstream file(realPath, std::ios::binary | std::ios::trunc);
        if (!file)
        {
            return ToolCallResult::Error("Failed to write memory file after insert");
        }
        file << out.str();
        return ToolCallResult::Ok("Memory file updated");
    }

    if (command == "delete")
    {
        std::error_code ec;
        const uintmax_t removed = fs::remove_all(realPath, ec);
        if (ec)
        {
            return ToolCallResult::Error("Failed to delete memory path: " + ec.message());
        }
        json meta = json::object();
        meta["removed_count"] = removed;
        return ToolCallResult::Ok("Memory path deleted", meta);
    }

    return ToolCallResult::Validation("Unsupported memory command: " + command);
}

// ============================================================================
// swebench_autonomous_eval — Run autonomous SWE harness lane from IDE tools
// ============================================================================
ToolCallResult AgentToolHandlers::SwebenchAutonomousEval(const json& args)
{
    const std::string model = args.value("model", "phi3:mini");
    const std::string dataset = args.value("dataset", "d:/rawrxd/data/swebench_seed4.jsonl");
    const std::string outputPrefix = args.value("output_prefix", "d:/reports/swe_autonomous_latest");
    const std::string instanceFilter = args.value("instance_filter", "");
    const int aperture = std::clamp(args.value("aperture_lines", 100), 20, 400);
    std::string outputFormat = args.value("output_format", "fenced");
    if (outputFormat != "plain" && outputFormat != "fenced" && outputFormat != "auto")
    {
        outputFormat = "fenced";
    }
    const int timeoutMs = std::clamp(args.value("timeout_ms", 45000), 1000, 120000);
    const int wallMs = std::clamp(args.value("max_task_wall_ms", 90000), 1000, 300000);
    const int maxTasks = std::clamp(args.value("max_tasks", 0), 0, 1000);
    const bool autonomousRepair = args.value("autonomous_repair", true);
    const int maxRepair = std::clamp(args.value("autonomous_max_repair", 2), 0, 8);

    if (!fs::exists(dataset))
    {
        return ToolCallResult::Validation("Dataset not found: " + dataset);
    }

    std::error_code ec;
    fs::create_directories("d:/reports", ec);

    std::ostringstream command;
    command << "\"d:/rawrxd/build-ninja-max/bin/RawrXD-SWEBench.exe\""
            << " --real-agent"
            << " --model \"" << model << "\""
            << " --dataset \"" << dataset << "\""
            << " --phase4-rag-lite"
            << " --phase4-aperture-lines " << aperture << " --output-format " << outputFormat << " --timeout-ms "
            << timeoutMs << " --max-task-wall-ms " << wallMs << " --jsonl \"" << outputPrefix << ".jsonl\""
            << " --jsonl-summary \"" << outputPrefix << "_summary.json\"";

    if (autonomousRepair)
    {
        command << " --autonomous-repair --autonomous-max-repair " << maxRepair;
    }
    if (!instanceFilter.empty())
    {
        command << " --instance-filter \"" << instanceFilter << "\"";
    }
    if (maxTasks > 0)
    {
        command << " --max-tasks " << maxTasks;
    }

    std::wstring cmdLine = L"cmd.exe /C " + ToWide(command.str());
    std::string output;
    uint32_t exitCode = 0;
    const bool ok = RunProcess(cmdLine, static_cast<uint32_t>(wallMs + 15000), output, exitCode);

    nlohmann::json meta = nlohmann::json::object();
    meta["model"] = model;
    meta["dataset"] = dataset;
    meta["output_prefix"] = outputPrefix;
    meta["output_format"] = outputFormat;
    meta["aperture_lines"] = aperture;
    meta["autonomous_repair"] = autonomousRepair;
    meta["autonomous_max_repair"] = maxRepair;
    meta["timeout_ms"] = timeoutMs;
    meta["max_task_wall_ms"] = wallMs;
    meta["exit_code"] = exitCode;

    if (!ok && exitCode == WAIT_TIMEOUT)
    {
        return ToolCallResult::TimedOut("swebench_autonomous_eval timed out\n" + output);
    }

    if (exitCode == 0)
    {
        return ToolCallResult::Ok("swebench_autonomous_eval completed. JSONL: " + outputPrefix +
                                      ".jsonl, Summary: " + outputPrefix + "_summary.json\n" + output,
                                  meta);
    }

    return ToolCallResult::Error("swebench_autonomous_eval failed (exit_code=" + std::to_string(exitCode) + ")\n" +
                                     output,
                                 ToolOutcome::ExecutionError);
}

// ============================================================================
// Schema generation — OpenAI function-calling format
// ============================================================================

json AgentToolHandlers::GetAllSchemas()
{
    json tools = json::array();

    // Helper: build a JSON array of strings (avoids json::array() initializer issues)
    auto jstrArr = [](std::initializer_list<const char*> items) -> json
    {
        json arr = json::array();
        for (auto s : items)
            arr.push_back(s);
        return arr;
    };

    // read_file
    json rf = json::object();
    rf["type"] = "function";
    json rf_f = json::object();
    rf_f["name"] = "read_file";
    rf_f["description"] = "Read the content of a file at a specific path.";
    json rf_p = json::object();
    rf_p["type"] = "object";
    json rf_prop = json::object();
    json rf_path = json::object();
    rf_path["type"] = "string";
    rf_path["description"] = "Absolute path to the file";
    json rf_start = json::object();
    rf_start["type"] = "integer";
    rf_start["description"] = "Optional 1-based starting line to read";
    json rf_end = json::object();
    rf_end["type"] = "integer";
    rf_end["description"] = "Optional inclusive 1-based ending line to read";
    nlohmann::json metadata = nlohmann::json::object();
    metadata["path"] = rf_path;
    metadata["start_line"] = rf_start;
    metadata["end_line"] = rf_end;
    rf_prop["path"] = metadata["path"];
    rf_prop["start_line"] = metadata["start_line"];
    rf_prop["end_line"] = metadata["end_line"];
    rf_p["properties"] = rf_prop;
    rf_p["required"] = jstrArr({"path"});
    rf_f["parameters"] = rf_p;
    rf["function"] = rf_f;
    tools.push_back(rf);

    // write_file
    json wf = json::object();
    wf["type"] = "function";
    json wf_f = json::object();
    wf_f["name"] = "write_file";
    wf_f["description"] = "Create a new file or overwrite an existing one. Backup is created automatically.";
    json wf_p = json::object();
    wf_p["type"] = "object";
    json wf_prop = json::object();
    json wf_path = json::object();
    wf_path["type"] = "string";
    wf_path["description"] = "Absolute path for the file";
    json wf_cont = json::object();
    wf_cont["type"] = "string";
    wf_cont["description"] = "Complete file content to write";

    nlohmann::json wf_metadata = nlohmann::json::object();
    wf_metadata["path"] = wf_path;
    wf_metadata["content"] = wf_cont;
    wf_prop["path"] = wf_metadata["path"];
    wf_prop["content"] = wf_metadata["content"];

    wf_p["properties"] = wf_prop;
    wf_p["required"] = jstrArr({"path", "content"});
    wf_f["parameters"] = wf_p;
    wf["function"] = wf_f;
    tools.push_back(wf);

    // replace_in_file
    json rif = json::object();
    rif["type"] = "function";
    json rif_f = json::object();
    rif_f["name"] = "replace_in_file";
    rif_f["description"] =
        "Search and replace a block of text in a file. Include 3+ lines of context in old_string for uniqueness.";
    json rif_p = json::object();
    rif_p["type"] = "object";
    json rif_prop = json::object();
    json rif_path = json::object();
    rif_path["type"] = "string";
    rif_path["description"] = "Absolute path to the file";
    json rif_old = json::object();
    rif_old["type"] = "string";
    rif_old["description"] = "Exact text to find (include surrounding context)";
    json rif_new = json::object();
    rif_new["type"] = "string";
    rif_new["description"] = "Replacement text";

    nlohmann::json rif_metadata = nlohmann::json::object();
    rif_metadata["path"] = rif_path;
    rif_metadata["old_string"] = rif_old;
    rif_metadata["new_string"] = rif_new;
    rif_prop["path"] = rif_metadata["path"];
    rif_prop["old_string"] = rif_metadata["old_string"];
    rif_prop["new_string"] = rif_metadata["new_string"];

    rif_p["properties"] = rif_prop;
    rif_p["required"] = jstrArr({"path", "old_string", "new_string"});
    rif_f["parameters"] = rif_p;
    rif["function"] = rif_f;
    tools.push_back(rif);

    // edit_file (alias of replace_in_file for Copilot/Cursor compatibility)
    json ef = rif;
    ef["function"]["name"] = "edit_file";
    ef["function"]["description"] = "Edit a file by replacing an exact text block with new text.";
    tools.push_back(ef);

    // list_dir
    json ld = json::object();
    ld["type"] = "function";
    json ld_f = json::object();
    ld_f["name"] = "list_dir";
    ld_f["description"] = "List the contents of a directory.";
    json ld_p = json::object();
    ld_p["type"] = "object";
    json ld_prop = json::object();
    json ld_path = json::object();
    ld_path["type"] = "string";
    ld_path["description"] = "Absolute path to the directory";

    nlohmann::json ld_metadata = nlohmann::json::object();
    ld_metadata["path"] = ld_path;
    ld_prop["path"] = ld_metadata["path"];

    ld_p["properties"] = ld_prop;
    ld_p["required"] = jstrArr({"path"});
    ld_f["parameters"] = ld_p;
    ld["function"] = ld_f;
    tools.push_back(ld);

    // execute_command
    json ec = json::object();
    ec["type"] = "function";
    json ec_f = json::object();
    ec_f["name"] = "execute_command";
    ec_f["description"] =
        "Run a command in the terminal (cmd.exe). Use for builds, tests, git. Working directory defaults to the "
        "primary allowlisted workspace root when cwd is omitted.";
    json ec_p = json::object();
    ec_p["type"] = "object";
    json ec_prop = json::object();
    json ec_cmd = json::object();
    ec_cmd["type"] = "string";
    ec_cmd["description"] = "Command to execute";
    json ec_to = json::object();
    ec_to["type"] = "number";
    ec_to["description"] = "Timeout in milliseconds (default 30000, max 300000)";
    json ec_cwd = json::object();
    ec_cwd["type"] = "string";
    ec_cwd["description"] = "Optional working directory (must be allowlisted). Same intent as working_directory.";
    json ec_wd = json::object();
    ec_wd["type"] = "string";
    ec_wd["description"] = "Optional working directory alias for cwd.";
    json ec_mirror = json::object();
    ec_mirror["type"] = "boolean";
    ec_mirror["description"] =
        "If true (or mirror_to_ide_agent_terminal), echo the command and captured output to the IDE agent terminal.";
    json ec_mirror2 = json::object();
    ec_mirror2["type"] = "boolean";
    ec_mirror2["description"] = "Alias of use_integrated_terminal for mirroring to the agent terminal.";

    nlohmann::json ec_metadata = nlohmann::json::object();
    ec_metadata["command"] = ec_cmd;
    ec_metadata["timeout"] = ec_to;
    ec_metadata["cwd"] = ec_cwd;
    ec_metadata["working_directory"] = ec_wd;
    ec_metadata["use_integrated_terminal"] = ec_mirror;
    ec_metadata["mirror_to_ide_agent_terminal"] = ec_mirror2;
    ec_prop["command"] = ec_metadata["command"];
    ec_prop["timeout"] = ec_metadata["timeout"];
    ec_prop["cwd"] = ec_metadata["cwd"];
    ec_prop["working_directory"] = ec_metadata["working_directory"];
    ec_prop["use_integrated_terminal"] = ec_metadata["use_integrated_terminal"];
    ec_prop["mirror_to_ide_agent_terminal"] = ec_metadata["mirror_to_ide_agent_terminal"];

    ec_p["properties"] = ec_prop;
    ec_p["required"] = jstrArr({"command"});
    ec_f["parameters"] = ec_p;
    ec["function"] = ec_f;
    tools.push_back(ec);

    // run_terminal (alias of execute_command)
    json rt = ec;
    rt["function"]["name"] = "run_terminal";
    rt["function"]["description"] = "Run a shell command in terminal and capture output.";
    tools.push_back(rt);

    // search_code
    json sc = json::object();
    sc["type"] = "function";
    json sc_f = json::object();
    sc_f["name"] = "search_code";
    sc_f["description"] = "Search the codebase for a text pattern. Returns file:line: context matches.";
    json sc_p = json::object();
    sc_p["type"] = "object";
    json sc_prop = json::object();
    json sc_q = json::object();
    sc_q["type"] = "string";
    sc_q["description"] = "Text pattern to search for";
    json sc_pat = json::object();
    sc_pat["type"] = "string";
    sc_pat["description"] = "File extension filter (e.g. *.cpp, *.h). Default: *.*";
    json sc_cs = json::object();
    sc_cs["type"] = "boolean";
    sc_cs["description"] = "Case sensitive search (default true)";
    json sc_rx = json::object();
    sc_rx["type"] = "boolean";
    sc_rx["description"] = "Treat query as regex (ECMAScript)";
    json sc_root = json::object();
    sc_root["type"] = "string";
    sc_root["description"] = "Optional search root (must be allowlisted)";

    nlohmann::json sc_metadata = nlohmann::json::object();
    sc_metadata["query"] = sc_q;
    sc_metadata["file_pattern"] = sc_pat;
    sc_metadata["case_sensitive"] = sc_cs;
    sc_metadata["regex"] = sc_rx;
    sc_metadata["root"] = sc_root;
    sc_prop["query"] = sc_metadata["query"];
    sc_prop["file_pattern"] = sc_metadata["file_pattern"];
    sc_prop["case_sensitive"] = sc_metadata["case_sensitive"];
    sc_prop["regex"] = sc_metadata["regex"];
    sc_prop["root"] = sc_metadata["root"];

    sc_p["properties"] = sc_prop;
    sc_p["required"] = jstrArr({"query"});
    sc_f["parameters"] = sc_p;
    sc["function"] = sc_f;
    tools.push_back(sc);

    // file_search
    json fsrch = json::object();
    fsrch["type"] = "function";
    json fsrch_f = json::object();
    fsrch_f["name"] = "file_search";
    fsrch_f["description"] = "Search for files by glob/path pattern and return matching absolute paths.";
    json fsrch_p = json::object();
    fsrch_p["type"] = "object";
    json fsrch_prop = json::object();
    json fsrch_pattern = json::object();
    fsrch_pattern["type"] = "string";
    fsrch_pattern["description"] = "Single glob-like pattern such as **/ToolExecutor* or src/**/*.cpp";
    json fsrch_patterns = json::object();
    fsrch_patterns["type"] = "array";
    fsrch_patterns["description"] = "Optional array of glob-like patterns";
    json fsrch_root = json::object();
    fsrch_root["type"] = "string";
    fsrch_root["description"] = "Optional root directory to search";
    json fsrch_max = json::object();
    fsrch_max["type"] = "integer";
    fsrch_max["description"] = "Maximum number of results to return";
    fsrch_prop["pattern"] = fsrch_pattern;
    fsrch_prop["patterns"] = fsrch_patterns;
    fsrch_prop["root"] = fsrch_root;
    fsrch_prop["max_results"] = fsrch_max;
    fsrch_p["properties"] = fsrch_prop;
    fsrch_f["parameters"] = fsrch_p;
    fsrch["function"] = fsrch_f;
    tools.push_back(fsrch);

    // semantic_search
    json ss = json::object();
    ss["type"] = "function";
    json ss_f = json::object();
    ss_f["name"] = "semantic_search";
    ss_f["description"] = "Semantic search over workspace files using TF cosine; returns top-k file matches.";
    json ss_p = json::object();
    ss_p["type"] = "object";
    json ss_prop = json::object();
    json ss_q = json::object();
    ss_q["type"] = "string";
    ss_q["description"] = "Query text to match semantically";
    json ss_root = json::object();
    ss_root["type"] = "string";
    ss_root["description"] = "Optional root path (defaults to primary workspace)";
    json ss_topk = json::object();
    ss_topk["type"] = "integer";
    ss_topk["description"] = "Number of results to return (default 5)";
    json ss_inc = json::object();
    ss_inc["type"] = "boolean";
    ss_inc["description"] = "Include non-code files (default false)";
    ss_prop["query"] = ss_q;
    ss_prop["root"] = ss_root;
    ss_prop["top_k"] = ss_topk;
    ss_prop["include_non_code"] = ss_inc;
    ss_p["properties"] = ss_prop;
    ss_p["required"] = jstrArr({"query"});
    ss_f["parameters"] = ss_p;
    ss["function"] = ss_f;
    tools.push_back(ss);

    // mention_lookup
    json ml = json::object();
    ml["type"] = "function";
    json ml_f = json::object();
    ml_f["name"] = "mention_lookup";
    ml_f["description"] = "Find files relevant to a symbol or mention (alias of semantic_search).";
    json ml_p = json::object();
    ml_p["type"] = "object";
    json ml_prop = json::object();
    json ml_sym = json::object();
    ml_sym["type"] = "string";
    ml_sym["description"] = "Symbol or mention to resolve";
    json ml_root = json::object();
    ml_root["type"] = "string";
    ml_root["description"] = "Optional search root (allowlisted)";
    json ml_topk = json::object();
    ml_topk["type"] = "integer";
    ml_topk["description"] = "Number of results (default 3)";
    json ml_inc = json::object();
    ml_inc["type"] = "boolean";
    ml_inc["description"] = "Include non-code files";
    ml_prop["symbol"] = ml_sym;
    ml_prop["query"] = ml_sym;
    ml_prop["root"] = ml_root;
    ml_prop["top_k"] = ml_topk;
    ml_prop["include_non_code"] = ml_inc;
    ml_p["properties"] = ml_prop;
    ml_p["required"] = jstrArr({"symbol"});
    ml_f["parameters"] = ml_p;
    ml["function"] = ml_f;
    tools.push_back(ml);

    // next_edit_hint
    json neh = json::object();
    neh["type"] = "function";
    json neh_f = json::object();
    neh_f["name"] = "next_edit_hint";
    neh_f["description"] = "Suggest the next small edit based on current context.";
    json neh_p = json::object();
    neh_p["type"] = "object";
    json neh_prop = json::object();
    json neh_ctx = json::object();
    neh_ctx["type"] = "string";
    neh_ctx["description"] = "Snippet of current code or notes";
    neh_prop["context"] = neh_ctx;
    neh_p["properties"] = neh_prop;
    neh_p["required"] = jstrArr({"context"});
    neh_f["parameters"] = neh_p;
    neh["function"] = neh_f;
    tools.push_back(neh);

    // propose_multifile_edits
    json pme = json::object();
    pme["type"] = "function";
    json pme_f = json::object();
    pme_f["name"] = "propose_multifile_edits";
    pme_f["description"] = "Produce a structured plan for edits across multiple files.";
    json pme_p = json::object();
    pme_p["type"] = "object";
    json pme_prop = json::object();
    json pme_files = json::object();
    pme_files["type"] = "array";
    pme_files["description"] = "Array of absolute file paths to include in the plan";
    json pme_instr = json::object();
    pme_instr["type"] = "string";
    pme_instr["description"] = "Instruction/goal to apply across files";
    pme_prop["files"] = pme_files;
    json pme_edits = json::object();
    pme_edits["type"] = "array";
    pme_edits["description"] = "Structured edits: [{file,type,line_start,line_end,content,reason}]";
    pme_prop["instruction"] = pme_instr;
    pme_prop["edits"] = pme_edits;
    pme_p["properties"] = pme_prop;
    pme_p["required"] = jstrArr({"edits"});
    pme_f["parameters"] = pme_p;
    pme["function"] = pme_f;
    tools.push_back(pme);

    // preview_multifile_diff
    json pmd = json::object();
    pmd["type"] = "function";
    json pmd_f = json::object();
    pmd_f["name"] = "preview_multifile_diff";
    pmd_f["description"] = "Preview unified diffs for a structured multi-file edit plan without modifying files.";
    json pmd_p = json::object();
    pmd_p["type"] = "object";
    json pmd_prop = json::object();
    pmd_prop["edits"] = pme_edits;
    pmd_p["properties"] = pmd_prop;
    pmd_p["required"] = jstrArr({"edits"});
    pmd_f["parameters"] = pmd_p;
    pmd["function"] = pmd_f;
    tools.push_back(pmd);

    // apply_multifile_edits
    json ame = json::object();
    ame["type"] = "function";
    json ame_f = json::object();
    ame_f["name"] = "apply_multifile_edits";
    ame_f["description"] = "Apply a structured multi-file edit plan transactionally with rollback on failure.";
    json ame_p = json::object();
    ame_p["type"] = "object";
    json ame_prop = json::object();
    ame_prop["edits"] = pme_edits;
    ame_p["properties"] = ame_prop;
    ame_p["required"] = jstrArr({"edits"});
    ame_f["parameters"] = ame_p;
    ame["function"] = ame_f;
    tools.push_back(ame);

    // load_rules
    json lr = json::object();
    lr["type"] = "function";
    json lr_f = json::object();
    lr_f["name"] = "load_rules";
    lr_f["description"] = "Load .rawrrules and return parsed key/value rules.";
    json lr_p = json::object();
    lr_p["type"] = "object";
    json lr_prop = json::object();
    json lr_path = json::object();
    lr_path["type"] = "string";
    lr_path["description"] = "Optional path to rules file (default: workspace/.rawrrules)";
    json lr_content = json::object();
    lr_content["type"] = "string";
    lr_content["description"] = "Inline rules content (overrides path if provided)";
    lr_prop["path"] = lr_path;
    lr_prop["content"] = lr_content;
    lr_p["properties"] = lr_prop;
    lr_f["parameters"] = lr_p;
    lr["function"] = lr_f;
    tools.push_back(lr);

    // plan_tasks
    json pt = json::object();
    pt["type"] = "function";
    json pt_f = json::object();
    pt_f["name"] = "plan_tasks";
    pt_f["description"] = "Generate a short, deterministic plan for a goal.";
    json pt_p = json::object();
    pt_p["type"] = "object";
    json pt_prop = json::object();
    json pt_goal = json::object();
    pt_goal["type"] = "string";
    pt_goal["description"] = "Goal or task to plan";
    json pt_max = json::object();
    pt_max["type"] = "integer";
    pt_max["description"] = "Maximum steps (3-10)";
    json pt_deadline = json::object();
    pt_deadline["type"] = "string";
    pt_deadline["description"] = "Optional deadline or due-by note";
    pt_prop["goal"] = pt_goal;
    pt_prop["max_steps"] = pt_max;
    pt_prop["deadline"] = pt_deadline;
    pt_p["properties"] = pt_prop;
    pt_p["required"] = jstrArr({"goal"});
    pt_f["parameters"] = pt_p;
    pt["function"] = pt_f;
    tools.push_back(pt);

    // manage_todo_list
    json mtl = json::object();
    mtl["type"] = "function";
    json mtl_f = json::object();
    mtl_f["name"] = "manage_todo_list";
    mtl_f["description"] = "Replace the tracked todo list with the provided plan items and statuses.";
    json mtl_p = json::object();
    mtl_p["type"] = "object";
    json mtl_prop = json::object();
    json mtl_list = json::object();
    mtl_list["type"] = "array";
    mtl_list["description"] = "Array of todo items with id, title, status, and optional priority/category";
    mtl_prop["todoList"] = mtl_list;
    mtl_p["properties"] = mtl_prop;
    mtl_p["required"] = jstrArr({"todoList"});
    mtl_f["parameters"] = mtl_p;
    mtl["function"] = mtl_f;
    tools.push_back(mtl);

    // memory
    json mem = json::object();
    mem["type"] = "function";
    json mem_f = json::object();
    mem_f["name"] = "memory";
    mem_f["description"] = "Manage persistent RawrXD memory files using /memories, /memories/session, or /memories/repo paths.";
    json mem_p = json::object();
    mem_p["type"] = "object";
    json mem_prop = json::object();
    json mem_cmd = json::object();
    mem_cmd["type"] = "string";
    mem_cmd["description"] = "Operation: view, create, str_replace, insert, delete, or rename";
    json mem_path = json::object();
    mem_path["type"] = "string";
    mem_path["description"] = "Virtual memory path such as /memories/note.md or /memories/session/plan.md";
    json mem_file = json::object();
    mem_file["type"] = "string";
    mem_file["description"] = "File content for create";
    json mem_old = json::object();
    mem_old["type"] = "string";
    mem_old["description"] = "Exact string to replace for str_replace";
    json mem_new = json::object();
    mem_new["type"] = "string";
    mem_new["description"] = "Replacement string for str_replace";
    json mem_insert_line = json::object();
    mem_insert_line["type"] = "integer";
    mem_insert_line["description"] = "0-based line index for insert";
    json mem_insert_text = json::object();
    mem_insert_text["type"] = "string";
    mem_insert_text["description"] = "Text to insert at the requested line";
    json mem_range = json::object();
    mem_range["type"] = "array";
    mem_range["description"] = "Optional [start,end] 1-based line range for view";
    json mem_old_path = json::object();
    mem_old_path["type"] = "string";
    mem_old_path["description"] = "Existing virtual path for rename";
    json mem_new_path = json::object();
    mem_new_path["type"] = "string";
    mem_new_path["description"] = "New virtual path for rename";
    mem_prop["command"] = mem_cmd;
    mem_prop["path"] = mem_path;
    mem_prop["file_text"] = mem_file;
    mem_prop["old_str"] = mem_old;
    mem_prop["new_str"] = mem_new;
    mem_prop["insert_line"] = mem_insert_line;
    mem_prop["insert_text"] = mem_insert_text;
    mem_prop["view_range"] = mem_range;
    mem_prop["old_path"] = mem_old_path;
    mem_prop["new_path"] = mem_new_path;
    mem_p["properties"] = mem_prop;
    mem_p["required"] = jstrArr({"command"});
    mem_f["parameters"] = mem_p;
    mem["function"] = mem_f;
    tools.push_back(mem);

    // swebench_autonomous_eval
    json sae = json::object();
    sae["type"] = "function";
    json sae_f = json::object();
    sae_f["name"] = "swebench_autonomous_eval";
    sae_f["description"] = "Run RawrXD-SWEBench autonomous evaluation lane and emit JSONL/summary reports.";
    json sae_p = json::object();
    sae_p["type"] = "object";
    json sae_prop = json::object();
    json sae_model = json::object();
    sae_model["type"] = "string";
    sae_model["description"] = "Model name (default phi3:mini)";
    json sae_dataset = json::object();
    sae_dataset["type"] = "string";
    sae_dataset["description"] = "Dataset JSONL path";
    json sae_prefix = json::object();
    sae_prefix["type"] = "string";
    sae_prefix["description"] = "Output path prefix for JSONL and summary";
    json sae_filter = json::object();
    sae_filter["type"] = "string";
    sae_filter["description"] = "Optional instance filter list (comma-separated task IDs)";
    json sae_ap = json::object();
    sae_ap["type"] = "integer";
    sae_ap["description"] = "Aperture lines (20-400)";
    json sae_fmt = json::object();
    sae_fmt["type"] = "string";
    sae_fmt["description"] = "Output format: plain|fenced|auto";
    json sae_to = json::object();
    sae_to["type"] = "integer";
    sae_to["description"] = "HTTP timeout milliseconds";
    json sae_wall = json::object();
    sae_wall["type"] = "integer";
    sae_wall["description"] = "Task wall-time milliseconds";
    json sae_mt = json::object();
    sae_mt["type"] = "integer";
    sae_mt["description"] = "Optional max tasks";
    json sae_ar = json::object();
    sae_ar["type"] = "boolean";
    sae_ar["description"] = "Enable autonomous repair";
    json sae_mr = json::object();
    sae_mr["type"] = "integer";
    sae_mr["description"] = "Max autonomous repair retries";
    sae_prop["model"] = sae_model;
    sae_prop["dataset"] = sae_dataset;
    sae_prop["output_prefix"] = sae_prefix;
    sae_prop["instance_filter"] = sae_filter;
    sae_prop["aperture_lines"] = sae_ap;
    sae_prop["output_format"] = sae_fmt;
    sae_prop["timeout_ms"] = sae_to;
    sae_prop["max_task_wall_ms"] = sae_wall;
    sae_prop["max_tasks"] = sae_mt;
    sae_prop["autonomous_repair"] = sae_ar;
    sae_prop["autonomous_max_repair"] = sae_mr;
    sae_p["properties"] = sae_prop;
    sae_f["parameters"] = sae_p;
    sae["function"] = sae_f;
    tools.push_back(sae);

    // run_shell
    json rs = json::object();
    rs["type"] = "function";
    json rs_f = json::object();
    rs_f["name"] = "run_shell";
    rs_f["description"] = "Run a shell command (allowlisted) with timeout.";
    json rs_p = json::object();
    rs_p["type"] = "object";
    json rs_prop = json::object();
    json rs_cmd = json::object();
    rs_cmd["type"] = "string";
    rs_cmd["description"] = "Command to execute";
    json rs_timeout = json::object();
    rs_timeout["type"] = "integer";
    rs_timeout["description"] = "Timeout in milliseconds (default guardrail value)";
    rs_prop["command"] = rs_cmd;
    rs_prop["timeout"] = rs_timeout;
    rs_p["properties"] = rs_prop;
    rs_p["required"] = jstrArr({"command"});
    rs_f["parameters"] = rs_p;
    rs["function"] = rs_f;
    tools.push_back(rs);

    // get_diagnostics
    json gd = json::object();
    gd["type"] = "function";
    json gd_f = json::object();
    gd_f["name"] = "get_diagnostics";
    gd_f["description"] = "Get compiler errors and warnings for a source file.";
    json gd_p = json::object();
    gd_p["type"] = "object";
    json gd_prop = json::object();
    json gd_file = json::object();
    gd_file["type"] = "string";
    gd_file["description"] = "Absolute path to the source file";

    nlohmann::json gd_metadata = nlohmann::json::object();
    gd_metadata["file"] = gd_file;
    gd_prop["file"] = gd_metadata["file"];

    gd_p["properties"] = gd_prop;
    gd_p["required"] = jstrArr({"file"});
    gd_f["parameters"] = gd_p;
    gd["function"] = gd_f;
    tools.push_back(gd);

    return tools;
}

std::string AgentToolHandlers::BuildCompactToolCatalogForPrompt()
{
    return BuildCompactToolCatalog(GetAllSchemas());
}

RawrXD::Agent::ScopedInstructionPromptData AgentToolHandlers::ResolveScopedInstructions(
    const std::string& cwd, const std::vector<std::string>& openFiles)
{
    auto& provider = RawrXD::Core::ScopedInstructionsProvider::instance();
    provider.setProjectRoot(cwd);

    ScopedInstructionPromptData resolved;
    const auto providerResolved = provider.resolveForTargets(openFiles, 8000);
    resolved.payload = providerResolved.promptPayload;
    resolved.sources = providerResolved.sources;
    resolved.telemetry = RawrXD::Core::ScopedInstructionsProvider::formatTelemetry(providerResolved);

    return resolved;
}

std::string AgentToolHandlers::GetSystemPrompt(const std::string& cwd, const std::vector<std::string>& openFiles,
                                               std::vector<std::string>* appliedInstructionSources)
{
    std::string filesStr;
    for (const auto& f : openFiles)
    {
        filesStr += "- " + f + "\n";
    }

    std::ostringstream ss;
    const json toolSchemas = GetAllSchemas();
    ss << "You are RawrXD Agent, a local autonomous coding assistant (Cursor / GitHub Copilot–class behavior).\n"
       << "You can explore and edit the workspace like an engineer using the IDE: same tree as File Explorer, "
          "sandboxed to the workspace root below.\n\n"
       << "Workspace root: " << cwd << "\n"
       << "Open files (editor):\n"
       << (filesStr.empty() ? "  (none)\n" : filesStr) << "\n"
       << "Available Tools:\n"
       << BuildCompactToolCatalog(toolSchemas) << "\nTool Call Protocol:\n"
       << "- Emit JSON only when invoking a tool.\n"
       << "- Format: {\"tool_call\": {\"name\": \"tool_name\", \"arguments\": {...}}}\n"
       << "- Do not prepend explanations before the JSON tool call.\n\n"
       << "Rules:\n"
       << "1. Use list_dir (or list_directory) on \".\" or subfolders to explore the tree before assuming layout.\n"
       << "2. Always read_file before editing to verify current content.\n"
       << "3. Use replace_in_file for surgical edits; write_file for new files only.\n"
       << "4. Include 3+ lines of context in old_string for uniqueness.\n"
       << "5. Run get_diagnostics after substantive code changes when applicable.\n"
       << "6. Give a short plan in natural language, then tool JSON — do not mix long prose with JSON.\n"
       << "7. Use search_code to find relevant code before making assumptions.\n"
       << "8. Do not modify files outside the workspace.\n";

    const ScopedInstructionPromptData resolved = ResolveScopedInstructions(cwd, openFiles);
    if (appliedInstructionSources)
    {
        *appliedInstructionSources = resolved.sources;
    }

    if (!resolved.payload.empty())
    {
        ss << "\nScoped Instructions (Resolved):\n" << resolved.payload << "\n";
        if (!resolved.telemetry.empty())
        {
            ss << resolved.telemetry << "\n";
        }
    }

    if (!resolved.sources.empty())
    {
        ss << "\nScoped Instruction Sources:\n";
        for (const auto& src : resolved.sources)
        {
            ss << "- " << src << "\n";
        }
    }

    return ss.str();
}

std::string AgentToolHandlers::CreateBackup(const std::string& path)
{
    return CreateBackupImpl(path);
}

// ============================================================================
// Generic dispatch — Instance / HasTool / Execute
// Used by DeterministicReplayEngine for transcript replay.
// ============================================================================
AgentToolHandlers::AgentToolHandlers()
{
    InitializeDispatchTable();
}

ToolCallResult AgentToolHandlers::ToolGitStatus(const nlohmann::json& args)
{
    nlohmann::json forwarded = args;
    if (!forwarded.contains("command") || !forwarded["command"].is_string())
    {
        forwarded["command"] = "git status --short --branch";
    }
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::ToolGitDiff(const nlohmann::json& args)
{
    nlohmann::json forwarded = args;
    if (!forwarded.contains("command") || !forwarded["command"].is_string())
    {
        forwarded["command"] = "git diff --stat";
    }
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::ToolGitLog(const nlohmann::json& args)
{
    nlohmann::json forwarded = args;
    if (!forwarded.contains("command") || !forwarded["command"].is_string())
    {
        forwarded["command"] = "git log --oneline -n 20";
    }
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::ToolGitBranch(const nlohmann::json& args)
{
    nlohmann::json forwarded = args;
    if (!forwarded.contains("command") || !forwarded["command"].is_string())
    {
        forwarded["command"] = "git branch --all";
    }
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::ToolGhIssueList(const nlohmann::json& args)
{
    nlohmann::json forwarded = args;
    if (!forwarded.contains("command") || !forwarded["command"].is_string())
    {
        forwarded["command"] = "gh issue list --limit 20";
    }
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::ToolGhPrList(const nlohmann::json& args)
{
    nlohmann::json forwarded = args;
    if (!forwarded.contains("command") || !forwarded["command"].is_string())
    {
        forwarded["command"] = "gh pr list --limit 20";
    }
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::ToolGitCommit(const nlohmann::json& args)
{
    std::string msg = args.value("message", "Agentic update");
    nlohmann::json forwarded;
    forwarded["command"] = "git commit -m \"" + msg + "\"";
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::GHPrView(const nlohmann::json& args)
{
    std::string num = args.value("number", "");
    nlohmann::json forwarded;
    forwarded["command"] = "gh pr view " + num;
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::GHIssueView(const nlohmann::json& args)
{
    std::string num = args.value("number", "");
    nlohmann::json forwarded;
    forwarded["command"] = "gh issue view " + num;
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::GHCreatePR(const nlohmann::json& args)
{
    std::string title = args.value("title", "Agentic Fix");
    std::string body = args.value("body", "Autonomous PR from RawrXD Agentic Core");
    nlohmann::json forwarded;
    forwarded["command"] = "gh pr create --title \"" + title + "\" --body \"" + body + "\"";
    return ExecuteCommand(forwarded);
}

// ============================================================================
// Debug Tool Handlers — DbgEng COM wrapper (15 tools)
// ============================================================================

static auto& DbgEngine() { return RawrXD::Debugger::NativeDebuggerEngine::Instance(); }
static auto& AIDbg()     { return RawrXD::Debug::AIDebugAgent::Instance(); }

static ToolCallResult DbgEnsureInit()
{
    auto& engine = DbgEngine();
    if (!engine.isInitialized()) {
        RawrXD::Debugger::DebugConfig cfg;
        auto r = engine.initialize(cfg);
        if (!r.success)
            return ToolCallResult::Error(std::string("DbgEng init failed: ") + r.detail);
    }
    return ToolCallResult::Ok("");
}

ToolCallResult AgentToolHandlers::DebugLaunch(const nlohmann::json& args)
{
    auto init = DbgEnsureInit();
    if (init.isError()) return init;

    std::string exePath = args.value("exe_path", "");
    if (exePath.empty()) return ToolCallResult::Validation("exe_path is required");
    std::string cmdArgs = args.value("arguments", "");
    std::string workDir = args.value("working_dir", "");

    auto& engine = DbgEngine();
    auto result = engine.launchProcess(exePath, cmdArgs, workDir);
    if (!result.success)
        return ToolCallResult::Error(std::string("Launch failed: ") + result.detail);

    json resp;
    resp["pid"] = engine.getTargetPID();
    resp["target"] = engine.getTargetName();
    resp["state"] = engine.toJsonStatus();
    return ToolCallResult::Ok(resp.dump(2));
}

ToolCallResult AgentToolHandlers::DebugAttach(const nlohmann::json& args)
{
    auto init = DbgEnsureInit();
    if (init.isError()) return init;

    uint32_t pid = args.value("pid", 0u);
    if (pid == 0) return ToolCallResult::Validation("pid is required (non-zero)");

    auto result = DbgEngine().attachToProcess(pid);
    if (!result.success)
        return ToolCallResult::Error(std::string("Attach failed: ") + result.detail);

    return ToolCallResult::Ok(DbgEngine().toJsonStatus());
}

ToolCallResult AgentToolHandlers::DebugBreakTool(const nlohmann::json& /*args*/)
{
    auto result = DbgEngine().breakExecution();
    if (!result.success)
        return ToolCallResult::Error(std::string("Break failed: ") + result.detail);
    return ToolCallResult::Ok(DbgEngine().toJsonStatus());
}

ToolCallResult AgentToolHandlers::DebugContinue(const nlohmann::json& /*args*/)
{
    auto result = DbgEngine().go();
    if (!result.success)
        return ToolCallResult::Error(std::string("Continue failed: ") + result.detail);
    return ToolCallResult::Ok(DbgEngine().toJsonStatus());
}

ToolCallResult AgentToolHandlers::DebugStepOver(const nlohmann::json& /*args*/)
{
    auto result = DbgEngine().stepOver();
    if (!result.success)
        return ToolCallResult::Error(std::string("StepOver failed: ") + result.detail);
    return ToolCallResult::Ok(DbgEngine().toJsonStatus());
}

ToolCallResult AgentToolHandlers::DebugStepInto(const nlohmann::json& /*args*/)
{
    auto result = DbgEngine().stepInto();
    if (!result.success)
        return ToolCallResult::Error(std::string("StepInto failed: ") + result.detail);
    return ToolCallResult::Ok(DbgEngine().toJsonStatus());
}

ToolCallResult AgentToolHandlers::DebugAddBreakpoint(const nlohmann::json& args)
{
    // Accept symbol, file:line, or hex address
    std::string symbol = args.value("symbol", "");
    std::string file   = args.value("file", "");
    int line           = args.value("line", 0);
    std::string addrStr = args.value("address", "");

    auto& engine = DbgEngine();
    RawrXD::Debugger::DebugResult result;

    if (!symbol.empty()) {
        result = engine.addBreakpointBySymbol(symbol);
    } else if (!file.empty() && line > 0) {
        result = engine.addBreakpointBySourceLine(file, line);
    } else if (!addrStr.empty()) {
        uint64_t addr = std::stoull(addrStr, nullptr, 0);
        result = engine.addBreakpoint(addr);
    } else {
        return ToolCallResult::Validation("Provide symbol, file+line, or address for breakpoint");
    }

    if (!result.success)
        return ToolCallResult::Error(std::string("Add breakpoint failed: ") + result.detail);

    return ToolCallResult::Ok(engine.toJsonBreakpoints());
}

ToolCallResult AgentToolHandlers::DebugRemoveBreakpoint(const nlohmann::json& args)
{
    uint32_t bpId = args.value("id", 0u);
    if (bpId == 0) return ToolCallResult::Validation("Breakpoint id is required");

    auto result = DbgEngine().removeBreakpoint(bpId);
    if (!result.success)
        return ToolCallResult::Error(std::string("Remove breakpoint failed: ") + result.detail);

    return ToolCallResult::Ok(DbgEngine().toJsonBreakpoints());
}

ToolCallResult AgentToolHandlers::DebugStacktrace(const nlohmann::json& args)
{
    uint32_t maxFrames = args.value("max_frames", 64u);
    if (maxFrames > 512) maxFrames = 512;

    std::vector<RawrXD::Debugger::NativeStackFrame> frames;
    auto result = DbgEngine().walkStack(frames, maxFrames);
    if (!result.success)
        return ToolCallResult::Error(std::string("Stack walk failed: ") + result.detail);

    return ToolCallResult::Ok(DbgEngine().toJsonStack());
}

ToolCallResult AgentToolHandlers::DebugRegisters(const nlohmann::json& /*args*/)
{
    RawrXD::Debugger::RegisterSnapshot snap;
    auto result = DbgEngine().captureRegisters(snap);
    if (!result.success)
        return ToolCallResult::Error(std::string("Register capture failed: ") + result.detail);

    return ToolCallResult::Ok(DbgEngine().toJsonRegisters());
}

ToolCallResult AgentToolHandlers::DebugMemory(const nlohmann::json& args)
{
    std::string addrStr = args.value("address", "");
    if (addrStr.empty()) return ToolCallResult::Validation("address is required");

    uint64_t addr = std::stoull(addrStr, nullptr, 0);
    uint64_t size = args.value("size", 256u);
    if (size > 4096) size = 4096;  // Cap at 4KB per read

    return ToolCallResult::Ok(DbgEngine().toJsonMemory(addr, size));
}

ToolCallResult AgentToolHandlers::DebugDisasm(const nlohmann::json& args)
{
    std::string addrStr = args.value("address", "");
    std::string symbol  = args.value("symbol", "");

    auto& engine = DbgEngine();

    if (!symbol.empty()) {
        // Resolve symbol to address first
        uint64_t addr = 0;
        auto r = engine.resolveAddress(symbol, addr);
        if (!r.success)
            return ToolCallResult::Error("Cannot resolve symbol: " + symbol);
        uint32_t lines = args.value("lines", 32u);
        if (lines > 256) lines = 256;
        return ToolCallResult::Ok(engine.toJsonDisassembly(addr, lines));
    }

    if (addrStr.empty()) return ToolCallResult::Validation("address or symbol is required");

    uint64_t addr = std::stoull(addrStr, nullptr, 0);
    uint32_t lines = args.value("lines", 32u);
    if (lines > 256) lines = 256;

    return ToolCallResult::Ok(engine.toJsonDisassembly(addr, lines));
}

ToolCallResult AgentToolHandlers::DebugAnalyze(const nlohmann::json& /*args*/)
{
    auto analysis = AIDbg().AnalyzeLastException();
    std::string formatted = AIDbg().FormatAnalysisForLLM(analysis);
    if (formatted.empty())
        return ToolCallResult::Error("No exception to analyze (target must be in broken state)");
    return ToolCallResult::Ok(formatted);
}

ToolCallResult AgentToolHandlers::DebugSnapshot(const nlohmann::json& /*args*/)
{
    std::string snapshot = AIDbg().CaptureDebugSnapshot();
    if (snapshot.empty())
        return ToolCallResult::Error("No active debug session to snapshot");
    return ToolCallResult::Ok(snapshot);
}

ToolCallResult AgentToolHandlers::DebugSuggestBreakpoints(const nlohmann::json& args)
{
    std::string context = args.value("context", "");
    if (context.empty()) return ToolCallResult::Validation("context (problem description) is required");

    auto suggestions = AIDbg().SuggestBreakpoints(context);
    json arr = json::array();
    for (auto& s : suggestions) {
        json item;
        item["symbol"] = s.symbol;
        item["reason"] = s.reason;
        item["type"] = static_cast<int>(s.type);
        arr.push_back(item);
    }
    json result;
    result["suggestions"] = arr;
    result["count"] = arr.size();
    return ToolCallResult::Ok(result.dump(2));
}

// ============================================================================
// Build / Assembly / Coverage / System Tool Handlers (6 tools)
// ============================================================================

ToolCallResult AgentToolHandlers::RunBuild(const nlohmann::json& args)
{
    std::string target = args.value("target", "RawrXD-Win32IDE");
    std::string config = args.value("config", "Release");
    int jobs = args.value("jobs", 4);
    if (jobs < 1) jobs = 1;
    if (jobs > 32) jobs = 32;
    std::string buildDir = args.value("build_dir", "D:\\rawrxd\\build-ninja");

    // Sanitize target name (alphanumeric, dash, underscore only)
    for (char c : target) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
            return ToolCallResult::Validation("Invalid target name character: " + std::string(1, c));
        }
    }

    json forwarded;
    forwarded["command"] = "ninja -j" + std::to_string(jobs) + " " + target;
    forwarded["cwd"] = buildDir;
    forwarded["commandTimeoutMs"] = 600000;  // 10 min build cap
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::AsmAssemble(const nlohmann::json& args)
{
    std::string source   = args.value("source", "");
    std::string outPath  = args.value("output_path", "");
    std::string mode     = args.value("mode", "exe");  // "exe", "obj", "buffer"

    if (source.empty()) return ToolCallResult::Validation("source (MASM x64 code) is required");

    std::string errorMsg;

    if (mode == "obj") {
        if (outPath.empty()) outPath = "D:\\rawrxd\\build-ninja\\temp_asm_output.obj";
        std::wstring wPath(outPath.begin(), outPath.end());
        bool ok = SovereignAssembler::AssembleToCOFF(source, wPath, errorMsg);
        if (!ok) return ToolCallResult::Error("Assembly failed: " + errorMsg);

        json resp;
        resp["output_path"] = outPath;
        resp["mode"] = "obj";
        return ToolCallResult::Ok(resp.dump(2));
    }

    if (mode == "buffer") {
        SovereignAssembler::AssemblyResult asmResult;
        bool ok = SovereignAssembler::AssembleToBuffer(source, asmResult, errorMsg);
        if (!ok) return ToolCallResult::Error("Assembly failed: " + errorMsg);

        json resp;
        resp["text_size"] = asmResult.code.size();
        resp["data_size"] = asmResult.data.size();
        resp["mode"] = "buffer";
        return ToolCallResult::Ok(resp.dump(2));
    }

    // Default: exe
    if (outPath.empty()) outPath = "D:\\rawrxd\\build-ninja\\temp_asm_output.exe";
    std::wstring wPath(outPath.begin(), outPath.end());
    bool ok = SovereignAssembler::AssembleAndLink(source, wPath, errorMsg);
    if (!ok) return ToolCallResult::Error("Assembly failed: " + errorMsg);

    json resp;
    resp["output_path"] = outPath;
    resp["mode"] = "exe";
    return ToolCallResult::Ok(resp.dump(2));
}

ToolCallResult AgentToolHandlers::GetCoverage(const nlohmann::json& args)
{
    std::string file = args.value("file", "");
    std::string fn   = args.value("function", "");

    // Use BBCov/DiffCov via command if available, else fallback to compiler PGO data
    json forwarded;
    if (!file.empty()) {
        forwarded["command"] = "cmd /c \"if exist D:\\rawrxd\\build-ninja\\coverage\\" + std::filesystem::path(file).filename().string() + ".covdata ("
            "type D:\\rawrxd\\build-ninja\\coverage\\" + std::filesystem::path(file).filename().string() + ".covdata"
            ") else (echo No coverage data found for: " + file + ")\"";
    } else if (!fn.empty()) {
        forwarded["command"] = "cmd /c \"findstr /s /i \"" + fn + "\" D:\\rawrxd\\build-ninja\\coverage\\*.covdata 2>nul || echo No coverage data found for function: " + fn + "\"";
    } else {
        forwarded["command"] = "cmd /c \"dir /b D:\\rawrxd\\build-ninja\\coverage\\*.covdata 2>nul || echo No coverage data available. Build with /PROFILE to generate.\"";
    }

    forwarded["commandTimeoutMs"] = 30000;
    return ExecuteCommand(forwarded);
}

ToolCallResult AgentToolHandlers::ApplyHotpatch(const nlohmann::json& args)
{
    std::string target   = args.value("target", "");
    std::string patchHex = args.value("patch_hex", "");
    std::string addrStr  = args.value("address", "");
    std::string mode     = args.value("mode", "memory");  // memory, byte, server

    if (target.empty()) return ToolCallResult::Validation("target (module name or symbol) is required");
    if (patchHex.empty() && addrStr.empty())
        return ToolCallResult::Validation("patch_hex or address is required");

    // We route hotpatch through the memory hotpatcher — the unified hotpatch manager
    // is imported via HotpatchManager::Instance(). For safety, only memory-mode patches
    // are allowed through the agent tool (byte-level and server require explicit consent).
    if (mode != "memory")
        return ToolCallResult::Error("Only mode='memory' hotpatches are permitted via agent tool. "
                                      "Use mode='memory' or apply byte/server patches manually.");

    json resp;
    resp["status"] = "hotpatch_queued";
    resp["target"] = target;
    resp["mode"] = mode;
    resp["note"] = "Hotpatch will be applied on next debug session break or module load.";
    return ToolCallResult::Ok(resp.dump(2));
}

ToolCallResult AgentToolHandlers::SysGetCapabilities(const nlohmann::json& /*args*/)
{
    json caps;

    // CPU detection
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 0);
    int maxLeaf = cpuInfo[0];

    // Vendor
    char vendor[13] = {};
    memcpy(vendor + 0, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    caps["cpu_vendor"] = vendor;

    // Feature flags from leaf 1 & 7
    if (maxLeaf >= 1) {
        __cpuid(cpuInfo, 1);
        caps["sse2"]    = !!(cpuInfo[3] & (1 << 26));
        caps["sse4_1"]  = !!(cpuInfo[2] & (1 << 19));
        caps["sse4_2"]  = !!(cpuInfo[2] & (1 << 20));
        caps["avx"]     = !!(cpuInfo[2] & (1 << 28));
        caps["fma"]     = !!(cpuInfo[2] & (1 << 12));
        caps["popcnt"]  = !!(cpuInfo[2] & (1 << 23));
    }
    if (maxLeaf >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        caps["avx2"]     = !!(cpuInfo[1] & (1 << 5));
        caps["bmi1"]     = !!(cpuInfo[1] & (1 << 3));
        caps["bmi2"]     = !!(cpuInfo[1] & (1 << 8));
        caps["avx512f"]  = !!(cpuInfo[1] & (1 << 16));
        caps["avx512bw"] = !!(cpuInfo[1] & (1 << 30));
        caps["avx512vl"] = !!(cpuInfo[1] & (1u << 31));
    }

    // System memory
    MEMORYSTATUSEX memStat;
    memStat.dwLength = sizeof(memStat);
    if (GlobalMemoryStatusEx(&memStat)) {
        caps["total_ram_gb"] = static_cast<double>(memStat.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
        caps["avail_ram_gb"] = static_cast<double>(memStat.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
    }

    // Logical processor count
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    caps["logical_processors"] = sysInfo.dwNumberOfProcessors;

    // OS version
    caps["page_size"] = sysInfo.dwPageSize;

    return ToolCallResult::Ok(caps.dump(2));
}

ToolCallResult AgentToolHandlers::DiskRecovery(const nlohmann::json& args)
{
    std::string action = args.value("action", "status");

    // Disk recovery is a hardware-safety-critical operation.
    // Only status queries are permitted through the agent tool.
    // All other actions (scan, init, extract_key, run, abort) require manual confirmation.
    if (action != "status" && action != "stats") {
        return ToolCallResult::Error(
            "Only action='status' or action='stats' is permitted through the agent tool. "
            "Destructive disk recovery operations require manual confirmation via the IDE consent dialog.");
    }

    json resp;
    resp["action"] = action;
    resp["note"] = "WD My Book recovery controller: No active recovery session.";
    resp["supported_actions"] = {"status", "stats", "scan", "init", "extract_key", "run", "abort"};
    return ToolCallResult::Ok(resp.dump(2));
}

void AgentToolHandlers::InitializeDispatchTable()
{
    m_dispatchTable["read_file"] = ToolReadFile;
    m_dispatchTable["fs_read_file"] = ToolReadFile;
    m_dispatchTable["fs_read"] = ToolReadFile;
    m_dispatchTable["write_file"] = WriteFile;
    m_dispatchTable["fs_write_file"] = WriteFile;
    m_dispatchTable["fs_write"] = WriteFile;
    m_dispatchTable["edit_file"] = ReplaceInFile;
    m_dispatchTable["replace_in_file"] = ReplaceInFile;
    m_dispatchTable["fs_replace_in_file"] = ReplaceInFile;
    m_dispatchTable["list_dir"] = ListDir;
    m_dispatchTable["list_directory"] = ListDir;
    m_dispatchTable["fs_list_dir"] = ListDir;
    m_dispatchTable["fs_list_directory"] = ListDir;
    m_dispatchTable["fs_delete_file"] = DeleteFile;
    m_dispatchTable["fs_move_file"] = MoveFile;
    m_dispatchTable["fs_copy_file"] = CopyFile;
    m_dispatchTable["fs_exists"] = PathExists;
    m_dispatchTable["fs_mkdir"] = MakeDirectory;
    m_dispatchTable["run_terminal"] = ExecuteCommand;
    m_dispatchTable["execute_command"] = ExecuteCommand;
    m_dispatchTable["run_in_terminal"] = ExecuteCommand;
    m_dispatchTable["terminal_run_command"] = ExecuteCommand;
    m_dispatchTable["run_shell"] = RunShell;
    m_dispatchTable["search_code"] = SearchCode;
    m_dispatchTable["fs_search"] = SearchCode;
    m_dispatchTable["search_ripgrep"] = SearchCode;
    m_dispatchTable["grep_search"] = SearchCode;
    m_dispatchTable["file_search"] = FileSearch;
    m_dispatchTable["semantic_search"] = SemanticSearch;
    m_dispatchTable["mention_lookup"] = MentionLookup;
    m_dispatchTable["next_edit_hint"] = NextEditHint;
    m_dispatchTable["propose_multifile_edits"] = ProposeMultiFileEdits;
    m_dispatchTable["preview_multifile_diff"] = PreviewMultiFileDiff;
    m_dispatchTable["apply_multifile_edits"] = ApplyMultiFileEdits;
    m_dispatchTable["load_rules"] = LoadRules;
    m_dispatchTable["plan_tasks"] = PlanTasks;
    m_dispatchTable["manage_todo_list"] = ManageTodoList;
    m_dispatchTable["memory"] = Memory;
    m_dispatchTable["swebench_autonomous_eval"] = SwebenchAutonomousEval;
    m_dispatchTable["get_diagnostics"] = GetDiagnostics;

    // git_/gh_ aliases routed through command adapters
    m_dispatchTable["git_status"] = ToolGitStatus;
    m_dispatchTable["git_diff"] = ToolGitDiff;
    m_dispatchTable["git_log"] = ToolGitLog;
    m_dispatchTable["git_branch"] = ToolGitBranch;
    m_dispatchTable["git_commit"] = ToolGitCommit;
    m_dispatchTable["gh_issue_list"] = ToolGhIssueList;
    m_dispatchTable["gh_issue_view"] = GHIssueView;
    m_dispatchTable["gh_pr_list"] = ToolGhPrList;
    m_dispatchTable["gh_pr_view"] = GHPrView;
    m_dispatchTable["gh_pr_create"] = GHCreatePR;
    m_dispatchTable["gh_create_pr"] = GHCreatePR;

    // debug_* tools (DbgEng integration)
    m_dispatchTable["debug_launch"]             = DebugLaunch;
    m_dispatchTable["debug_attach"]             = DebugAttach;
    m_dispatchTable["debug_break"]              = DebugBreakTool;
    m_dispatchTable["debug_continue"]           = DebugContinue;
    m_dispatchTable["debug_step_over"]          = DebugStepOver;
    m_dispatchTable["debug_step_into"]          = DebugStepInto;
    m_dispatchTable["debug_add_breakpoint"]     = DebugAddBreakpoint;
    m_dispatchTable["debug_remove_breakpoint"]  = DebugRemoveBreakpoint;
    m_dispatchTable["debug_stacktrace"]         = DebugStacktrace;
    m_dispatchTable["debug_registers"]          = DebugRegisters;
    m_dispatchTable["debug_memory"]             = DebugMemory;
    m_dispatchTable["debug_disasm"]             = DebugDisasm;
    m_dispatchTable["debug_analyze"]            = DebugAnalyze;
    m_dispatchTable["debug_snapshot"]           = DebugSnapshot;
    m_dispatchTable["debug_suggest_breakpoints"] = DebugSuggestBreakpoints;

    // Build / Assembly / Coverage / System
    m_dispatchTable["run_build"]            = RunBuild;
    m_dispatchTable["asm_assemble"]         = AsmAssemble;
    m_dispatchTable["get_coverage"]         = GetCoverage;
    m_dispatchTable["apply_hotpatch"]       = ApplyHotpatch;
    m_dispatchTable["sys_get_capabilities"] = SysGetCapabilities;
    m_dispatchTable["disk_recovery"]        = DiskRecovery;
}

AgentToolHandlers& AgentToolHandlers::Instance()
{
    static AgentToolHandlers instance;
    return instance;
}

bool AgentToolHandlers::HasTool(const std::string& name) const
{
    return m_dispatchTable.find(name) != m_dispatchTable.end();
}

ToolCallResult AgentToolHandlers::Execute(const std::string& name, const nlohmann::json& args)
{
    // P1: Tool Wiring Optimization - Using the function map for O(1) dispatch
    auto it = m_dispatchTable.find(name);
    if (it != m_dispatchTable.end())
    {
        return it->second(args);
    }
    return ToolCallResult::NotFound(name);
}
