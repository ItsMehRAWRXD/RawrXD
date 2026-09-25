// Win32IDE_LSPClient.cpp — JSON-RPC LSP client over stdio process
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <sstream>
#include <cstdio>
#include <cstring>

namespace RawrXD::IDE {

struct LSPDiagnostic {
    int line, col;
    std::string severity; // "error" | "warning" | "info"
    std::string message;
    std::string source;
};

struct LSPCompletion {
    std::string label;
    std::string insertText;
    std::string kind; // "function" | "variable" | "keyword" etc.
};

// ── LSP state ─────────────────────────────────────────────────────────────────
struct LSPClient {
    HANDLE hChildStdinWr  = INVALID_HANDLE_VALUE;
    HANDLE hChildStdoutRd = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION pi{};
    std::atomic<bool> running{false};
    std::thread readerThread;
    int nextId = 1;
    std::string serverPath;
    std::string rootUri;

    std::function<void(const std::vector<LSPDiagnostic>&, const std::string&)> onDiagnostics;
    std::function<void(const std::vector<LSPCompletion>&)> onCompletions;
    std::function<void(const std::string&)> onHover;
};

static LSPClient g_lsp;

// ── JSON helpers (minimal, no deps) ──────────────────────────────────────────
static std::string jsonStr(const std::string& s)
{
    std::string out = "\"";
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    out += "\"";
    return out;
}

static std::string makeRequest(int id, const std::string& method, const std::string& params)
{
    std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                       ",\"method\":" + jsonStr(method) +
                       ",\"params\":" + params + "}";
    return "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

static std::string makeNotification(const std::string& method, const std::string& params)
{
    std::string body = "{\"jsonrpc\":\"2.0\",\"method\":" + jsonStr(method) +
                       ",\"params\":" + params + "}";
    return "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

// ── Send raw bytes to server stdin ────────────────────────────────────────────
static bool lspWrite(const std::string& msg)
{
    if (g_lsp.hChildStdinWr == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    return WriteFile(g_lsp.hChildStdinWr, msg.data(), (DWORD)msg.size(), &written, nullptr)
           && written == (DWORD)msg.size();
}

// ── Parse Content-Length header and read body ─────────────────────────────────
static std::string lspReadMessage()
{
    // Read headers
    std::string headers;
    char c = 0; DWORD rb = 0;
    while (true) {
        if (!ReadFile(g_lsp.hChildStdoutRd, &c, 1, &rb, nullptr) || rb == 0) return "";
        headers += c;
        if (headers.size() >= 4 &&
            headers.substr(headers.size() - 4) == "\r\n\r\n") break;
    }
    // Parse Content-Length
    size_t pos = headers.find("Content-Length: ");
    if (pos == std::string::npos) return "";
    int len = std::stoi(headers.substr(pos + 16));
    if (len <= 0 || len > 1024 * 1024) return "";
    std::string body(len, '\0');
    DWORD totalRead = 0;
    while (totalRead < (DWORD)len) {
        DWORD r = 0;
        if (!ReadFile(g_lsp.hChildStdoutRd, &body[totalRead], len - totalRead, &r, nullptr) || r == 0) break;
        totalRead += r;
    }
    return body;
}

// ── Minimal JSON field extractor ──────────────────────────────────────────────
static std::string jsonField(const std::string& json, const std::string& key)
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
        if (e == std::string::npos) return "";
        return json.substr(p + 1, e - p - 1);
    }
    size_t e = json.find_first_of(",}]", p);
    return json.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

// ── Reader thread ─────────────────────────────────────────────────────────────
static void lspReaderLoop()
{
    while (g_lsp.running.load()) {
        std::string msg = lspReadMessage();
        if (msg.empty()) { Sleep(10); continue; }

        std::string method = jsonField(msg, "method");

        if (method == "textDocument/publishDiagnostics") {
            // Parse diagnostics array (simplified)
            std::vector<LSPDiagnostic> diags;
            std::string uri = jsonField(msg, "uri");
            size_t arrStart = msg.find("\"diagnostics\"");
            if (arrStart != std::string::npos) {
                size_t bracket = msg.find('[', arrStart);
                size_t end     = msg.find(']', bracket);
                if (bracket != std::string::npos && end != std::string::npos) {
                    std::string arr = msg.substr(bracket, end - bracket + 1);
                    // Each diagnostic object
                    size_t obj = 0;
                    while ((obj = arr.find('{', obj)) != std::string::npos) {
                        size_t objEnd = arr.find('}', obj);
                        if (objEnd == std::string::npos) break;
                        std::string d = arr.substr(obj, objEnd - obj + 1);
                        LSPDiagnostic diag;
                        diag.message  = jsonField(d, "message");
                        diag.severity = jsonField(d, "severity");
                        diag.source   = jsonField(d, "source");
                        // line/col from range.start
                        size_t rp = d.find("\"start\"");
                        if (rp != std::string::npos) {
                            std::string startObj = d.substr(rp);
                            std::string lineStr = jsonField(startObj, "line");
                            std::string colStr  = jsonField(startObj, "character");
                            if (!lineStr.empty()) diag.line = std::stoi(lineStr);
                            if (!colStr.empty())  diag.col  = std::stoi(colStr);
                        }
                        if (!diag.message.empty()) diags.push_back(diag);
                        obj = objEnd + 1;
                    }
                }
            }
            if (g_lsp.onDiagnostics) g_lsp.onDiagnostics(diags, uri);
        }
        // Completion response handled via id matching (simplified: fire callback on any result)
        else if (!jsonField(msg, "id").empty() && msg.find("\"result\"") != std::string::npos) {
            // Check if it's a completion result
            if (msg.find("\"insertText\"") != std::string::npos ||
                msg.find("\"label\"") != std::string::npos) {
                std::vector<LSPCompletion> completions;
                size_t obj = 0;
                while ((obj = msg.find("{\"label\"", obj)) != std::string::npos) {
                    size_t objEnd = msg.find('}', obj);
                    if (objEnd == std::string::npos) break;
                    std::string d = msg.substr(obj, objEnd - obj + 1);
                    LSPCompletion c;
                    c.label      = jsonField(d, "label");
                    c.insertText = jsonField(d, "insertText");
                    c.kind       = jsonField(d, "kind");
                    if (!c.label.empty()) completions.push_back(c);
                    obj = objEnd + 1;
                }
                if (g_lsp.onCompletions && !completions.empty())
                    g_lsp.onCompletions(completions);
            }
            // Hover response
            else if (msg.find("\"contents\"") != std::string::npos) {
                std::string contents = jsonField(msg, "value");
                if (contents.empty()) contents = jsonField(msg, "contents");
                if (g_lsp.onHover && !contents.empty()) g_lsp.onHover(contents);
            }
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────
bool LSPClient_Start(const std::string& serverExe, const std::string& rootPath)
{
    g_lsp.serverPath = serverExe;
    g_lsp.rootUri    = "file:///" + rootPath;

    HANDLE hStdinRd, hStdinWr, hStdoutRd, hStdoutWr;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};

    if (!CreatePipe(&hStdinRd,  &hStdinWr,  &sa, 0)) return false;
    if (!CreatePipe(&hStdoutRd, &hStdoutWr, &sa, 0)) { CloseHandle(hStdinRd); CloseHandle(hStdinWr); return false; }

    SetHandleInformation(hStdinWr,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdoutRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb          = sizeof(si);
    si.hStdInput   = hStdinRd;
    si.hStdOutput  = hStdoutWr;
    si.hStdError   = hStdoutWr;
    si.dwFlags     = STARTF_USESTDHANDLES;

    if (!CreateProcessA(nullptr, (LPSTR)serverExe.c_str(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &g_lsp.pi)) {
        CloseHandle(hStdinRd); CloseHandle(hStdinWr);
        CloseHandle(hStdoutRd); CloseHandle(hStdoutWr);
        return false;
    }

    CloseHandle(hStdinRd);
    CloseHandle(hStdoutWr);
    g_lsp.hChildStdinWr  = hStdinWr;
    g_lsp.hChildStdoutRd = hStdoutRd;
    g_lsp.running.store(true);

    // Send initialize
    std::string initParams =
        "{\"processId\":" + std::to_string(GetCurrentProcessId()) +
        ",\"rootUri\":" + jsonStr(g_lsp.rootUri) +
        ",\"capabilities\":{\"textDocument\":{\"completion\":{\"completionItem\":{\"snippetSupport\":false}}"
        ",\"hover\":{\"contentFormat\":[\"plaintext\"]}"
        ",\"publishDiagnostics\":{}}}}";
    lspWrite(makeRequest(g_lsp.nextId++, "initialize", initParams));

    g_lsp.readerThread = std::thread(lspReaderLoop);
    g_lsp.readerThread.detach();
    return true;
}

void LSPClient_Stop()
{
    g_lsp.running.store(false);
    lspWrite(makeNotification("exit", "{}"));
    if (g_lsp.hChildStdinWr  != INVALID_HANDLE_VALUE) { CloseHandle(g_lsp.hChildStdinWr);  g_lsp.hChildStdinWr  = INVALID_HANDLE_VALUE; }
    if (g_lsp.hChildStdoutRd != INVALID_HANDLE_VALUE) { CloseHandle(g_lsp.hChildStdoutRd); g_lsp.hChildStdoutRd = INVALID_HANDLE_VALUE; }
    if (g_lsp.pi.hProcess) { TerminateProcess(g_lsp.pi.hProcess, 0); CloseHandle(g_lsp.pi.hProcess); CloseHandle(g_lsp.pi.hThread); g_lsp.pi = {}; }
}

void LSPClient_DidOpen(const std::string& uri, const std::string& lang, const std::string& text)
{
    std::string params = "{\"textDocument\":{\"uri\":" + jsonStr(uri) +
        ",\"languageId\":" + jsonStr(lang) +
        ",\"version\":1,\"text\":" + jsonStr(text) + "}}";
    lspWrite(makeNotification("textDocument/didOpen", params));
}

void LSPClient_DidChange(const std::string& uri, int version, const std::string& text)
{
    std::string params = "{\"textDocument\":{\"uri\":" + jsonStr(uri) +
        ",\"version\":" + std::to_string(version) + "}"
        ",\"contentChanges\":[{\"text\":" + jsonStr(text) + "}]}";
    lspWrite(makeNotification("textDocument/didChange", params));
}

void LSPClient_RequestCompletion(const std::string& uri, int line, int col)
{
    std::string params = "{\"textDocument\":{\"uri\":" + jsonStr(uri) + "}"
        ",\"position\":{\"line\":" + std::to_string(line) +
        ",\"character\":" + std::to_string(col) + "}}";
    lspWrite(makeRequest(g_lsp.nextId++, "textDocument/completion", params));
}

void LSPClient_RequestHover(const std::string& uri, int line, int col)
{
    std::string params = "{\"textDocument\":{\"uri\":" + jsonStr(uri) + "}"
        ",\"position\":{\"line\":" + std::to_string(line) +
        ",\"character\":" + std::to_string(col) + "}}";
    lspWrite(makeRequest(g_lsp.nextId++, "textDocument/hover", params));
}

void LSPClient_SetDiagnosticsCallback(std::function<void(const std::vector<LSPDiagnostic>&, const std::string&)> cb)
{ g_lsp.onDiagnostics = std::move(cb); }

void LSPClient_SetCompletionsCallback(std::function<void(const std::vector<LSPCompletion>&)> cb)
{ g_lsp.onCompletions = std::move(cb); }

void LSPClient_SetHoverCallback(std::function<void(const std::string&)> cb)
{ g_lsp.onHover = std::move(cb); }

bool LSPClient_IsRunning() { return g_lsp.running.load(); }

} // namespace RawrXD::IDE
