// Win32IDE_MCP.cpp — Model Context Protocol client (stdio transport)
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <cstdio>

namespace RawrXD::IDE {

struct MCPTool {
    std::string name;
    std::string description;
    std::string inputSchema; // raw JSON
};

struct MCPState {
    HANDLE hStdinWr  = INVALID_HANDLE_VALUE;
    HANDLE hStdoutRd = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION pi{};
    std::atomic<bool> running{false};
    std::thread readerThread;
    int nextId = 1;
    std::vector<MCPTool> tools;
    std::unordered_map<int, std::function<void(const std::string&)>> pendingCallbacks;
    std::function<void(const std::vector<MCPTool>&)> onToolsListed;
    std::function<void(const std::string& tool, const std::string& result)> onToolResult;
};

static MCPState g_mcp;

// ── Minimal JSON helpers ──────────────────────────────────────────────────────
static std::string jStr(const std::string& s)
{
    std::string o = "\"";
    for (char c : s) {
        if (c == '"')  o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else o += c;
    }
    return o + "\"";
}

static std::string jField(const std::string& json, const std::string& key)
{
    std::string needle = "\"" + key + "\"";
    size_t p = json.find(needle);
    if (p == std::string::npos) return "";
    p = json.find(':', p + needle.size());
    if (p == std::string::npos) return "";
    ++p;
    while (p < json.size() && json[p] == ' ') ++p;
    if (p >= json.size()) return "";
    if (json[p] == '"') {
        size_t e = json.find('"', p + 1);
        return (e == std::string::npos) ? "" : json.substr(p + 1, e - p - 1);
    }
    size_t e = json.find_first_of(",}]", p);
    return json.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

static std::string makeMsg(const std::string& body)
{
    return "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

static bool mcpWrite(const std::string& msg)
{
    if (g_mcp.hStdinWr == INVALID_HANDLE_VALUE) return false;
    DWORD w; return WriteFile(g_mcp.hStdinWr, msg.data(), (DWORD)msg.size(), &w, nullptr);
}

static std::string mcpReadMsg()
{
    std::string hdr;
    char c; DWORD rb;
    while (ReadFile(g_mcp.hStdoutRd, &c, 1, &rb, nullptr) && rb > 0) {
        hdr += c;
        if (hdr.size() >= 4 && hdr.substr(hdr.size() - 4) == "\r\n\r\n") break;
    }
    size_t p = hdr.find("Content-Length: ");
    if (p == std::string::npos) return "";
    int len = std::stoi(hdr.substr(p + 16));
    if (len <= 0 || len > 4 * 1024 * 1024) return "";
    std::string body(len, '\0');
    DWORD total = 0;
    while (total < (DWORD)len) {
        DWORD r = 0;
        if (!ReadFile(g_mcp.hStdoutRd, &body[total], len - total, &r, nullptr) || r == 0) break;
        total += r;
    }
    return body;
}

// ── Parse tools/list response ─────────────────────────────────────────────────
static void ParseToolsList(const std::string& json)
{
    g_mcp.tools.clear();
    size_t arr = json.find("\"tools\"");
    if (arr == std::string::npos) return;
    size_t bracket = json.find('[', arr);
    if (bracket == std::string::npos) return;
    size_t obj = bracket;
    while ((obj = json.find('{', obj + 1)) != std::string::npos) {
        size_t end = json.find('}', obj);
        if (end == std::string::npos) break;
        std::string d = json.substr(obj, end - obj + 1);
        MCPTool t;
        t.name        = jField(d, "name");
        t.description = jField(d, "description");
        if (!t.name.empty()) g_mcp.tools.push_back(t);
        obj = end;
    }
    if (g_mcp.onToolsListed) g_mcp.onToolsListed(g_mcp.tools);
}

// ── Reader thread ─────────────────────────────────────────────────────────────
static void MCPReaderLoop()
{
    while (g_mcp.running.load()) {
        std::string msg = mcpReadMsg();
        if (msg.empty()) { Sleep(10); continue; }

        std::string id  = jField(msg, "id");
        std::string method = jField(msg, "method");

        if (!id.empty() && msg.find("\"result\"") != std::string::npos) {
            int iid = std::stoi(id);
            // Check if tools/list response
            if (msg.find("\"tools\"") != std::string::npos)
                ParseToolsList(msg);

            auto it = g_mcp.pendingCallbacks.find(iid);
            if (it != g_mcp.pendingCallbacks.end()) {
                // Extract result content
                size_t rp = msg.find("\"result\"");
                std::string result = (rp != std::string::npos) ? msg.substr(rp) : msg;
                it->second(result);
                g_mcp.pendingCallbacks.erase(it);
            }
        }
    }
}

// Forward declarations
void MCP_ListTools();

// ── Public API ────────────────────────────────────────────────────────────────
bool MCP_Connect(const std::string& serverCmd)
{
    HANDLE hStdinRd, hStdinWr, hStdoutRd, hStdoutWr;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    if (!CreatePipe(&hStdinRd,  &hStdinWr,  &sa, 0)) return false;
    if (!CreatePipe(&hStdoutRd, &hStdoutWr, &sa, 0)) {
        CloseHandle(hStdinRd); CloseHandle(hStdinWr); return false;
    }
    SetHandleInformation(hStdinWr,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdoutRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.hStdInput  = hStdinRd;
    si.hStdOutput = hStdoutWr;
    si.hStdError  = hStdoutWr;
    si.dwFlags    = STARTF_USESTDHANDLES;

    if (!CreateProcessA(nullptr, (LPSTR)serverCmd.c_str(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &g_mcp.pi)) {
        CloseHandle(hStdinRd); CloseHandle(hStdinWr);
        CloseHandle(hStdoutRd); CloseHandle(hStdoutWr);
        return false;
    }
    CloseHandle(hStdinRd); CloseHandle(hStdoutWr);
    g_mcp.hStdinWr  = hStdinWr;
    g_mcp.hStdoutRd = hStdoutRd;
    g_mcp.running.store(true);

    // Send initialize
    int id = g_mcp.nextId++;
    std::string init = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
        ",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\""
        ",\"capabilities\":{},\"clientInfo\":{\"name\":\"RawrXD\",\"version\":\"3.0\"}}}";
    mcpWrite(makeMsg(init));

    g_mcp.readerThread = std::thread(MCPReaderLoop);
    g_mcp.readerThread.detach();

    // Request tool list
    MCP_ListTools();
    return true;
}

void MCP_Disconnect()
{
    g_mcp.running.store(false);
    if (g_mcp.hStdinWr  != INVALID_HANDLE_VALUE) { CloseHandle(g_mcp.hStdinWr);  g_mcp.hStdinWr  = INVALID_HANDLE_VALUE; }
    if (g_mcp.hStdoutRd != INVALID_HANDLE_VALUE) { CloseHandle(g_mcp.hStdoutRd); g_mcp.hStdoutRd = INVALID_HANDLE_VALUE; }
    if (g_mcp.pi.hProcess) { TerminateProcess(g_mcp.pi.hProcess, 0); CloseHandle(g_mcp.pi.hProcess); CloseHandle(g_mcp.pi.hThread); g_mcp.pi = {}; }
}

void MCP_ListTools()
{
    int id = g_mcp.nextId++;
    std::string msg = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                      ",\"method\":\"tools/list\",\"params\":{}}";
    mcpWrite(makeMsg(msg));
}

void MCP_CallTool(const std::string& toolName, const std::string& argsJson,
                  std::function<void(const std::string&)> callback)
{
    int id = g_mcp.nextId++;
    if (callback) g_mcp.pendingCallbacks[id] = std::move(callback);
    std::string msg = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
        ",\"method\":\"tools/call\",\"params\":{\"name\":" + jStr(toolName) +
        ",\"arguments\":" + argsJson + "}}";
    mcpWrite(makeMsg(msg));
}

const std::vector<MCPTool>& MCP_GetTools() { return g_mcp.tools; }
bool MCP_IsConnected() { return g_mcp.running.load(); }

void MCP_SetToolsListedCallback(std::function<void(const std::vector<MCPTool>&)> cb)
{ g_mcp.onToolsListed = std::move(cb); }

void MCP_SetToolResultCallback(std::function<void(const std::string&, const std::string&)> cb)
{ g_mcp.onToolResult = std::move(cb); }

} // namespace RawrXD::IDE
