// Win32IDE_LSPServer.cpp — built-in lightweight LSP server for C/C++ basic completions
#include <windows.h>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <thread>
#include <atomic>
#include <cstdio>
#include <cctype>

namespace RawrXD::IDE {
namespace LSPServer {

// ── JSON helpers (minimal, production-quality) ───────────────────────────────
static std::string jsonEscape(const std::string& s)
{
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\b': r += "\\b"; break;
            case '\f': r += "\\f"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default: r += c; break;
        }
    }
    return r;
}

static std::string jsonStr(const std::string& s) { return "\"" + jsonEscape(s) + "\""; }

static std::string makeResponse(int id, const std::string& result)
{
    std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                       ",\"result\":" + result + "}";
    return "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

static std::string makeNotification(const std::string& method, const std::string& params)
{
    std::string body = "{\"jsonrpc\":\"2.0\",\"method\":" + jsonStr(method) +
                       ",\"params\":" + params + "}";
    return "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

// ── Built-in C/C++ keyword completions ─────────────────────────────────────
static const char* s_cppKeywords[] = {
    "alignas","alignof","and","and_eq","asm","auto","bitand","bitor","bool","break",
    "case","catch","char","char8_t","char16_t","char32_t","class","compl","concept",
    "const","consteval","constexpr","constinit","const_cast","continue","co_await",
    "co_return","co_yield","decltype","default","delete","do","double","dynamic_cast",
    "else","enum","explicit","export","extern","false","float","for","friend","goto",
    "if","inline","int","long","mutable","namespace","new","noexcept","not","not_eq",
    "nullptr","operator","or","or_eq","private","protected","public","register",
    "reinterpret_cast","requires","return","short","signed","sizeof","static",
    "static_assert","static_cast","struct","switch","template","this","thread_local",
    "throw","true","try","typedef","typeid","typename","union","unsigned","using",
    "virtual","void","volatile","wchar_t","while","xor","xor_eq",
    nullptr
};

static const char* s_cppTypes[] = {
    "int8_t","int16_t","int32_t","int64_t","uint8_t","uint16_t","uint32_t","uint64_t",
    "size_t","ptrdiff_t","intptr_t","uintptr_t","ssize_t","off_t","time_t","clock_t",
    "std::string","std::vector","std::map","std::unordered_map","std::set","std::deque",
    "std::unique_ptr","std::shared_ptr","std::optional","std::variant","std::function",
    nullptr
};

static const char* s_stdFunctions[] = {
    "std::move","std::forward","std::swap","std::min","std::max","std::clamp",
    "std::make_unique","std::make_shared","std::static_pointer_cast",
    nullptr
};

struct CompletionItem {
    std::string label;
    std::string kind; // "Keyword", "Type", "Function", "Snippet"
    std::string detail;
};

static std::vector<CompletionItem> GetCompletions(const std::string& prefix)
{
    std::vector<CompletionItem> results;
    auto addIfPrefix = [&](const char** arr, const char* kind) {
        for (int i = 0; arr[i]; ++i) {
            std::string s(arr[i]);
            if (s.size() >= prefix.size() &&
                std::equal(prefix.begin(), prefix.end(), s.begin(),
                          [](char a, char b){ return tolower((unsigned char)a) == tolower((unsigned char)b); })) {
                results.push_back({s, kind, ""});
            }
        }
    };
    addIfPrefix(s_cppKeywords, "Keyword");
    addIfPrefix(s_cppTypes, "Type");
    addIfPrefix(s_stdFunctions, "Function");

    // Sort by label
    std::sort(results.begin(), results.end(),
              [](const CompletionItem& a, const CompletionItem& b) { return a.label < b.label; });

    // Limit to 50
    if (results.size() > 50) results.resize(50);
    return results;
}

// ── Server state ─────────────────────────────────────────────────────────────
struct ServerState {
    std::atomic<bool> running{false};
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    std::unordered_map<std::string, std::string> openDocs;
};

static ServerState g_srv;

static std::string readLSPMessage()
{
    // Read Content-Length header
    std::string header;
    char c;
    DWORD read;
    while (ReadFile(g_srv.hStdin, &c, 1, &read, nullptr) && read == 1) {
        header += c;
        if (header.size() >= 4 && header.substr(header.size() - 4) == "\r\n\r\n")
            break;
    }
    size_t clPos = header.find("Content-Length: ");
    if (clPos == std::string::npos) return "";
    size_t numStart = clPos + 16;
    size_t numEnd = header.find_first_of("\r\n", numStart);
    if (numEnd == std::string::npos) return "";
    int len = std::stoi(header.substr(numStart, numEnd - numStart));
    std::string body;
    body.resize(len);
    DWORD totalRead = 0;
    while (totalRead < (DWORD)len) {
        DWORD r = 0;
        if (!ReadFile(g_srv.hStdin, &body[totalRead], len - totalRead, &r, nullptr) || r == 0) break;
        totalRead += r;
    }
    return body;
}

static void writeLSPMessage(const std::string& msg)
{
    DWORD written;
    WriteFile(g_srv.hStdout, msg.c_str(), (DWORD)msg.size(), &written, nullptr);
    FlushFileBuffers(g_srv.hStdout);
}

static std::string jsonField(const std::string& json, const std::string& key)
{
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + key.size() + 2);
    if (pos == std::string::npos) return "";
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    if (pos < json.size() && json[pos] == '"') {
        ++pos;
        size_t end = json.find('"', pos);
        if (end != std::string::npos) return json.substr(pos, end - pos);
    }
    return "";
}

static void serverLoop()
{
    while (g_srv.running.load()) {
        std::string msg = readLSPMessage();
        if (msg.empty()) break;

        if (msg.find("\"method\":\"initialize\"") != std::string::npos) {
            int id = 0;
            size_t idPos = msg.find("\"id\":");
            if (idPos != std::string::npos) {
                id = std::stoi(msg.substr(idPos + 5));
            }
            std::string caps = "{\"capabilities\":{\"textDocumentSync\":1,"
                               "\"completionProvider\":{\"resolveProvider\":false,"
                               "\"triggerCharacters\":[\".\",\"::\",\"->\"]},"
                               "\"hoverProvider\":true}}";
            writeLSPMessage(makeResponse(id, caps));
        }
        else if (msg.find("\"method\":\"textDocument/completion\"") != std::string::npos) {
            int id = 0;
            size_t idPos = msg.find("\"id\":");
            if (idPos != std::string::npos) id = std::stoi(msg.substr(idPos + 5));

            // Extract prefix from context (simplified: get last word before cursor)
            std::string uri = jsonField(msg, "uri");
            auto it = g_srv.openDocs.find(uri);
            std::string prefix;
            if (it != g_srv.openDocs.end()) {
                const std::string& text = it->second;
                size_t linePos = msg.find("\"line\":");
                int line = 0;
                if (linePos != std::string::npos) line = std::stoi(msg.substr(linePos + 8));
                // Simple: just use empty prefix for now
                prefix = "";
            }

            auto items = GetCompletions(prefix);
            std::string result = "[";
            for (size_t i = 0; i < items.size(); ++i) {
                if (i > 0) result += ",";
                int kind = 14; // Keyword default
                if (items[i].kind == "Function") kind = 3;
                else if (items[i].kind == "Type") kind = 22;
                else if (items[i].kind == "Snippet") kind = 15;
                result += "{\"label\":" + jsonStr(items[i].label) +
                          ",\"kind\":" + std::to_string(kind) +
                          ",\"detail\":" + jsonStr(items[i].detail) + "}";
            }
            result += "]";
            writeLSPMessage(makeResponse(id, result));
        }
        else if (msg.find("\"method\":\"textDocument/didOpen\"") != std::string::npos) {
            std::string uri = jsonField(msg, "uri");
            std::string text = jsonField(msg, "text");
            g_srv.openDocs[uri] = text;
        }
        else if (msg.find("\"method\":\"textDocument/didChange\"") != std::string::npos) {
            std::string uri = jsonField(msg, "uri");
            size_t tPos = msg.find("\"text\":");
            if (tPos != std::string::npos) {
                tPos = msg.find('"', tPos + 7);
                if (tPos != std::string::npos) {
                    size_t end = msg.find('"', tPos + 1);
                    if (end != std::string::npos) {
                        g_srv.openDocs[uri] = msg.substr(tPos + 1, end - tPos - 1);
                    }
                }
            }
        }
        else if (msg.find("\"method\":\"shutdown\"") != std::string::npos) {
            int id = 0;
            size_t idPos = msg.find("\"id\":");
            if (idPos != std::string::npos) id = std::stoi(msg.substr(idPos + 5));
            writeLSPMessage(makeResponse(id, "null"));
        }
        else if (msg.find("\"method\":\"exit\"") != std::string::npos) {
            g_srv.running.store(false);
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────
void LSPServer_Start()
{
    if (g_srv.running.load()) return;
    g_srv.running.store(true);
    std::thread(serverLoop).detach();
}

void LSPServer_Stop()
{
    g_srv.running.store(false);
}

bool LSPServer_IsRunning() { return g_srv.running.load(); }

} // namespace LSPServer
} // namespace RawrXD::IDE
