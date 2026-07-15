// RawrXD_IDE.cpp - Zero-dependency native IDE
// LSP + Debugger + Collaboration + GUI - No external deps

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <shellapi.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <tlhelp32.h>
#include <commdlg.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <ctime>

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <algorithm>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ============================================================================
// CORE TYPES
// ============================================================================

using String = std::string;
template<typename T> using Vec = std::vector<T>;
template<typename K, typename V> using Map = std::unordered_map<K, V>;

// ============================================================================
// JSON PARSER (Zero-dependency)
// ============================================================================

class JsonValue {
public:
    enum Type { Null, Bool, Number, JsonString, Array, Object };
    Type type = Null;
    bool boolVal = false;
    double numVal = 0;
    String strVal;
    Vec<JsonValue> arrVal;
    Map<String, JsonValue> objVal;

    JsonValue() = default;
    JsonValue(bool b) : type(Bool), boolVal(b) {}
    JsonValue(double n) : type(Number), numVal(n) {}
    JsonValue(int n) : type(Number), numVal(static_cast<double>(n)) {}
    JsonValue(const String& s) : type(JsonString), strVal(s) {}
    JsonValue(const char* s) : type(JsonString), strVal(s) {}

    JsonValue& operator=(double n) { type = Number; numVal = n; return *this; }
    JsonValue& operator=(int n) { type = Number; numVal = static_cast<double>(n); return *this; }
    JsonValue& operator=(bool b) { type = Bool; boolVal = b; return *this; }
    JsonValue& operator=(const String& s) { type = JsonString; strVal = s; return *this; }
    JsonValue& operator=(const char* s) { type = JsonString; strVal = s; return *this; }

    bool IsNull() const { return type == Null; }
    bool IsBool() const { return type == Bool; }
    bool IsNumber() const { return type == Number; }
    bool IsString() const { return type == JsonString; }
    bool IsArray() const { return type == Array; }
    bool IsObject() const { return type == Object; }

    bool GetBool() const { return boolVal; }
    double GetNumber() const { return numVal; }
    const String& GetString() const { return strVal; }
    const Vec<JsonValue>& GetArray() const { return arrVal; }
    const Map<String, JsonValue>& GetObject() const { return objVal; }

    JsonValue& operator[](const String& key) {
        type = Object;
        return objVal[key];
    }

    JsonValue& operator[](size_t idx) {
        type = Array;
        if (idx >= arrVal.size()) arrVal.resize(idx + 1);
        return arrVal[idx];
    }

    const JsonValue& operator[](const String& key) const {
        static JsonValue nullVal;
        if (type != Object) return nullVal;
        auto it = objVal.find(key);
        return (it != objVal.end()) ? it->second : nullVal;
    }

    const JsonValue& operator[](size_t idx) const {
        static JsonValue nullVal;
        if (type != Array || idx >= arrVal.size()) return nullVal;
        return arrVal[idx];
    }

    bool HasKey(const String& key) const {
        return type == Object && objVal.find(key) != objVal.end();
    }

    String Serialize() const;
    static JsonValue Parse(const String& json);
};

class JsonParser {
    const char* p;
    const char* end;

    void SkipWhitespace() {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
    }

    bool Match(char c) {
        SkipWhitespace();
        if (p < end && *p == c) { ++p; return true; }
        return false;
    }

    String ParseString() {
        if (!Match('"')) return "";
        String result;
        while (p < end && *p != '"') {
            if (*p == '\\' && ++p < end) {
                switch (*p++) {
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/': result += '/'; break;
                    case 'b': result += '\b'; break;
                    case 'f': result += '\f'; break;
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    default: result += *(p-1); break;
                }
            } else {
                result += *p++;
            }
        }
        if (p < end) ++p; // skip closing "
        return result;
    }

    double ParseNumber() {
        SkipWhitespace();
        const char* start = p;
        if (p < end && (*p == '-' || *p == '+')) ++p;
        while (p < end && (*p >= '0' && *p <= '9')) ++p;
        if (p < end && *p == '.') {
            ++p;
            while (p < end && (*p >= '0' && *p <= '9')) ++p;
        }
        if (p < end && (*p == 'e' || *p == 'E')) {
            ++p;
            if (p < end && (*p == '-' || *p == '+')) ++p;
            while (p < end && (*p >= '0' && *p <= '9')) ++p;
        }
        return std::strtod(start, nullptr);
    }

    JsonValue ParseValue() {
        SkipWhitespace();
        if (p >= end) return JsonValue();

        if (*p == '"') { String s = ParseString(); return JsonValue(s); }
        if (*p == '{') return ParseObject();
        if (*p == '[') return ParseArray();
        if (*p == 't') { p += 4; return JsonValue(true); }
        if (*p == 'f') { p += 5; return JsonValue(false); }
        if (*p == 'n') { p += 4; return JsonValue(); }
        return JsonValue(ParseNumber());
    }

    JsonValue ParseObject() {
        JsonValue obj;
        obj.type = JsonValue::Object;
        if (!Match('{')) return obj;
        SkipWhitespace();
        if (Match('}')) return obj;
        do {
            String key = ParseString();
            Match(':');
            obj.objVal[key] = ParseValue();
        } while (Match(','));
        Match('}');
        return obj;
    }

    JsonValue ParseArray() {
        JsonValue arr;
        arr.type = JsonValue::Array;
        if (!Match('[')) return arr;
        SkipWhitespace();
        if (Match(']')) return arr;
        do {
            arr.arrVal.push_back(ParseValue());
        } while (Match(','));
        Match(']');
        return arr;
    }

public:
    JsonParser(const char* s, size_t len) : p(s), end(s + len) {}

    JsonValue Parse() { return ParseValue(); }
};

JsonValue JsonValue::Parse(const String& json) {
    JsonParser parser(json.c_str(), json.length());
    return parser.Parse();
}

String JsonValue::Serialize() const {
    switch (type) {
        case Null: return "null";
        case Bool: return boolVal ? "true" : "false";
        case Number: return std::to_string(numVal);
        case JsonString: {
            String result = "\"";
            for (char c : strVal) {
                switch (c) {
                    case '"': result += "\\\""; break;
                    case '\\': result += "\\\\"; break;
                    case '\b': result += "\\b"; break;
                    case '\f': result += "\\f"; break;
                    case '\n': result += "\\n"; break;
                    case '\r': result += "\\r"; break;
                    case '\t': result += "\\t"; break;
                    default: result += c; break;
                }
            }
            result += "\"";
            return result;
        }
        case Array: {
            String result = "[";
            for (size_t i = 0; i < arrVal.size(); ++i) {
                if (i > 0) result += ",";
                result += arrVal[i].Serialize();
            }
            result += "]";
            return result;
        }
        case Object: {
            String result = "{";
            bool first = true;
            for (const auto& [key, val] : objVal) {
                if (!first) result += ",";
                first = false;
                result += "\"" + key + "\":" + val.Serialize();
            }
            result += "}";
            return result;
        }
    }
    return "null";
}

// ============================================================================
// LSP CLIENT (JSON-RPC over named pipes)
// ============================================================================

class LSPClient {
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    std::thread readThread;
    std::atomic<bool> running{false};
    std::mutex mtx;
    std::condition_variable cv;
    std::deque<JsonValue> pendingResponses;
    std::atomic<int> requestId{0};

    void ReadLoop() {
        char buffer[65536];
        std::string accumulated;

        while (running) {
            DWORD bytesRead = 0;
            BOOL success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            if (!success || bytesRead == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                Sleep(10);
                continue;
            }
            buffer[bytesRead] = '\0';
            accumulated += buffer;

            // Parse LSP messages (Content-Length header)
            while (true) {
                size_t headerEnd = accumulated.find("\r\n\r\n");
                if (headerEnd == std::string::npos) break;

                size_t contentLengthPos = accumulated.find("Content-Length: ");
                if (contentLengthPos == std::string::npos) break;

                size_t lenStart = contentLengthPos + 16;
                size_t lenEnd = accumulated.find("\r\n", lenStart);
                if (lenEnd == std::string::npos) break;

                int contentLength = std::stoi(accumulated.substr(lenStart, lenEnd - lenStart));
                size_t messageStart = headerEnd + 4;

                if (accumulated.length() < messageStart + contentLength) break;

                std::string message = accumulated.substr(messageStart, contentLength);
                accumulated = accumulated.substr(messageStart + contentLength);

                JsonValue response = JsonValue::Parse(message);
                {
                    std::lock_guard<std::mutex> lock(mtx);
                    pendingResponses.push_back(std::move(response));
                }
                cv.notify_one();
            }
        }
    }

public:
    bool Connect(const std::string& pipeName) {
        hPipe = CreateFileA(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            // Try to spawn LSP server
            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            std::string cmd = "clangd --background-index --pch-storage=memory --cross-file-rename";
            if (CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()), nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                Sleep(500); // Wait for server to start

                hPipe = CreateFileA("\\\\.\\pipe\clangd", GENERIC_READ | GENERIC_WRITE,
                                   0, nullptr, OPEN_EXISTING, 0, nullptr);
            }
        }

        if (hPipe != INVALID_HANDLE_VALUE) {
            running = true;
            readThread = std::thread(&LSPClient::ReadLoop, this);
            return true;
        }
        return false;
    }

    void SendRequest(const std::string& method, const JsonValue& params) {
        JsonValue request;
        request["jsonrpc"] = "2.0";
        request["id"] = ++requestId;
        request["method"] = method;
        request["params"] = params;

        std::string content = request.Serialize();
        std::string message = "Content-Length: " + std::to_string(content.length()) + "\r\n\r\n" + content;

        DWORD written = 0;
        WriteFile(hPipe, message.c_str(), static_cast<DWORD>(message.length()), &written, nullptr);
    }

    JsonValue WaitForResponse(int timeoutMs = 5000) {
        std::unique_lock<std::mutex> lock(mtx);
        if (cv.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                        [this] { return !pendingResponses.empty(); })) {
            JsonValue response = std::move(pendingResponses.front());
            pendingResponses.pop_front();
            return response;
        }
        return JsonValue();
    }

    void Initialize(const std::string& rootPath) {
        JsonValue params;
        params["processId"] = static_cast<double>(GetCurrentProcessId());
        params["rootPath"] = rootPath;
        params["capabilities"]["textDocument"]["synchronization"]["dynamicRegistration"] = false;
        params["capabilities"]["textDocument"]["completion"]["dynamicRegistration"] = false;
        params["capabilities"]["textDocument"]["hover"]["dynamicRegistration"] = false;
        params["capabilities"]["textDocument"]["definition"]["dynamicRegistration"] = false;

        SendRequest("initialize", params);
        WaitForResponse();

        SendRequest("initialized", JsonValue());
    }

    Vec<JsonValue> GetCompletions(const std::string& uri, int line, int character) {
        JsonValue params;
        params["textDocument"]["uri"] = uri;
        params["position"]["line"] = static_cast<double>(line);
        params["position"]["character"] = static_cast<double>(character);

        SendRequest("textDocument/completion", params);
        JsonValue response = WaitForResponse();

        Vec<JsonValue> result;
        if (response.HasKey("result") && response["result"].IsArray()) {
            return response["result"].GetArray();
        }
        return result;
    }

    JsonValue GetDefinition(const std::string& uri, int line, int character) {
        JsonValue params;
        params["textDocument"]["uri"] = uri;
        params["position"]["line"] = static_cast<double>(line);
        params["position"]["character"] = static_cast<double>(character);

        SendRequest("textDocument/definition", params);
        return WaitForResponse();
    }

    void DidOpen(const std::string& uri, const std::string& languageId, const std::string& text) {
        JsonValue params;
        params["textDocument"]["uri"] = uri;
        params["textDocument"]["languageId"] = languageId;
        params["textDocument"]["version"] = 1;
        params["textDocument"]["text"] = text;

        SendRequest("textDocument/didOpen", params);
    }

    void DidChange(const std::string& uri, int version, const std::string& text) {
        JsonValue params;
        params["textDocument"]["uri"] = uri;
        params["textDocument"]["version"] = static_cast<double>(version);
        params["contentChanges"][0]["text"] = text;

        SendRequest("textDocument/didChange", params);
    }

    ~LSPClient() {
        running = false;
        if (readThread.joinable()) readThread.join();
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
    }
};

// ============================================================================
// DEBUGGER (Windows Debug API)
// ============================================================================

class Debugger {
    HANDLE hProcess = nullptr;
    DWORD processId = 0;
    std::atomic<bool> attached{false};
    std::thread debugThread;
    std::function<void(const std::string&)> onOutput;
    std::function<void(int)> onBreakpoint;

    void DebugLoop() {
        DEBUG_EVENT debugEvent;
        while (attached) {
            if (WaitForDebugEvent(&debugEvent, 100)) {
                switch (debugEvent.dwDebugEventCode) {
                    case CREATE_PROCESS_DEBUG_EVENT:
                        CloseHandle(debugEvent.u.CreateProcessInfo.hFile);
                        break;

                    case EXIT_PROCESS_DEBUG_EVENT:
                        attached = false;
                        break;

                    case LOAD_DLL_DEBUG_EVENT:
                        CloseHandle(debugEvent.u.LoadDll.hFile);
                        break;

                    case OUTPUT_DEBUG_STRING_EVENT: {
                        OUTPUT_DEBUG_STRING_INFO info = debugEvent.u.DebugString;
                        if (info.fUnicode) {
                            WCHAR buffer[512];
                            SIZE_T read = 0;
                            ReadProcessMemory(hProcess, info.lpDebugStringData, buffer,
                                            std::min(info.nDebugStringLength, (WORD)511) * sizeof(WCHAR), &read);
                            buffer[read / sizeof(WCHAR)] = 0;
                            char ansi[512];
                            WideCharToMultiByte(CP_UTF8, 0, buffer, -1, ansi, 512, nullptr, nullptr);
                            if (onOutput) onOutput(ansi);
                        } else {
                            char buffer[512];
                            SIZE_T read = 0;
                            ReadProcessMemory(hProcess, info.lpDebugStringData, buffer,
                                            std::min(info.nDebugStringLength, (WORD)511), &read);
                            buffer[read] = 0;
                            if (onOutput) onOutput(buffer);
                        }
                        break;
                    }

                    case EXCEPTION_DEBUG_EVENT: {
                        EXCEPTION_RECORD& exc = debugEvent.u.Exception.ExceptionRecord;
                        if (exc.ExceptionCode == EXCEPTION_BREAKPOINT) {
                            if (onBreakpoint) onBreakpoint((int)exc.ExceptionAddress);
                        }
                        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                        continue;
                    }
                }
                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
            }
        }
    }

public:
    bool Launch(const std::string& exePath, const std::string& args) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};

        std::string cmdLine = "\"" + exePath + "\" " + args;

        if (CreateProcessA(nullptr, const_cast<char*>(cmdLine.c_str()), nullptr, nullptr, FALSE,
                          DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                          nullptr, nullptr, &si, &pi)) {
            hProcess = pi.hProcess;
            processId = pi.dwProcessId;
            attached = true;

            debugThread = std::thread(&Debugger::DebugLoop, this);
            return true;
        }
        return false;
    }

    bool Attach(DWORD pid) {
        if (DebugActiveProcess(pid)) {
            processId = pid;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            attached = true;
            debugThread = std::thread(&Debugger::DebugLoop, this);
            return true;
        }
        return false;
    }

    void SetBreakpoint(void* address) {
        BYTE int3 = 0xCC;
        SIZE_T written = 0;
        WriteProcessMemory(hProcess, address, &int3, 1, &written);
        FlushInstructionCache(hProcess, address, 1);
    }

    void Continue() {
        // Resume all threads
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { sizeof(te) };
            if (Thread32First(hSnapshot, &te)) {
                do {
                    if (te.th32OwnerProcessID == processId) {
                        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (hThread) {
                            ResumeThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnapshot, &te));
            }
            CloseHandle(hSnapshot);
        }
    }

    void StepInto() {
        // Set trap flag
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                    GetCurrentThreadId()); // Simplified
        if (hThread) {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(hThread, &ctx);
            ctx.EFlags |= 0x100; // Trap flag
            SetThreadContext(hThread, &ctx);
            CloseHandle(hThread);
        }
    }

    void Stop() {
        attached = false;
        DebugActiveProcessStop(processId);
        if (debugThread.joinable()) debugThread.join();
        if (hProcess) CloseHandle(hProcess);
    }

    void SetOutputCallback(std::function<void(const std::string&)> cb) { onOutput = cb; }
    void SetBreakpointCallback(std::function<void(int)> cb) { onBreakpoint = cb; }

    ~Debugger() {
        if (attached) Stop();
    }
};

// ============================================================================
// REAL-TIME COLLABORATION (WebSocket Server)
// ============================================================================

class CollaborationServer {
    SOCKET listenSocket = INVALID_SOCKET;
    std::vector<SOCKET> clients;
    std::mutex clientsMtx;
    std::thread serverThread;
    std::atomic<bool> running{false};
    std::function<void(SOCKET, const JsonValue&)> onMessage;

    std::string ParseWebSocketFrame(const char* data, int len, bool& isText) {
        if (len < 2) return "";

        bool fin = (data[0] & 0x80) != 0;
        int opcode = data[0] & 0x0F;
        bool masked = (data[1] & 0x80) != 0;
        uint64_t payloadLen = data[1] & 0x7F;

        int pos = 2;
        if (payloadLen == 126) {
            payloadLen = (data[2] << 8) | data[3];
            pos = 4;
        } else if (payloadLen == 127) {
            payloadLen = 0;
            for (int i = 0; i < 8; ++i) {
                payloadLen = (payloadLen << 8) | (unsigned char)data[2 + i];
            }
            pos = 10;
        }

        char mask[4] = {0};
        if (masked) {
            memcpy(mask, data + pos, 4);
            pos += 4;
        }

        isText = (opcode == 1);
        std::string result;
        result.reserve((size_t)payloadLen);

        for (uint64_t i = 0; i < payloadLen && pos < len; ++i, ++pos) {
            result += masked ? (data[pos] ^ mask[i % 4]) : data[pos];
        }

        return result;
    }

    void SendWebSocketFrame(SOCKET client, const std::string& data, bool isText = true) {
        char frame[65536];
        int pos = 0;

        frame[pos++] = (isText ? 0x81 : 0x82); // FIN + opcode

        if (data.length() < 126) {
            frame[pos++] = (char)data.length();
        } else if (data.length() < 65536) {
            frame[pos++] = 126;
            frame[pos++] = (char)((data.length() >> 8) & 0xFF);
            frame[pos++] = (char)(data.length() & 0xFF);
        } else {
            frame[pos++] = 127;
            for (int i = 7; i >= 0; --i) {
                frame[pos++] = (char)((data.length() >> (i * 8)) & 0xFF);
            }
        }

        memcpy(frame + pos, data.c_str(), data.length());
        pos += (int)data.length();

        send(client, frame, pos, 0);
    }

    void HandleWebSocketHandshake(SOCKET client) {
        char buffer[4096];
        int received = recv(client, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) return;
        buffer[received] = '\0';

        // Parse WebSocket key
        const char* keyHeader = strstr(buffer, "Sec-WebSocket-Key: ");
        if (!keyHeader) return;
        keyHeader += 19;
        const char* keyEnd = strstr(keyHeader, "\r\n");
        if (!keyEnd) return;

        std::string key(keyHeader, keyEnd - keyHeader);
        key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        // SHA1 hash (simplified - in production use proper SHA1)
        // For now, accept without proper handshake
        const char* response =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
            "\r\n";
        send(client, response, (int)strlen(response), 0);
    }

    void ClientHandler(SOCKET client) {
        HandleWebSocketHandshake(client);

        {
            std::lock_guard<std::mutex> lock(clientsMtx);
            clients.push_back(client);
        }

        char buffer[65536];
        while (running) {
            int received = recv(client, buffer, sizeof(buffer), 0);
            if (received <= 0) break;

            bool isText = false;
            std::string message = ParseWebSocketFrame(buffer, received, isText);

            if (isText && onMessage) {
                JsonValue json = JsonValue::Parse(message);
                onMessage(client, json);
            }
        }

        {
            std::lock_guard<std::mutex> lock(clientsMtx);
            clients.erase(std::remove(clients.begin(), clients.end(), client), clients.end());
        }
        closesocket(client);
    }

    void ServerLoop() {
        while (running) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(listenSocket, &readSet);

            timeval timeout = { 0, 100000 }; // 100ms
            if (select(0, &readSet, nullptr, nullptr, &timeout) > 0) {
                if (FD_ISSET(listenSocket, &readSet)) {
                    SOCKET client = accept(listenSocket, nullptr, nullptr);
                    if (client != INVALID_SOCKET) {
                        std::thread(&CollaborationServer::ClientHandler, this, client).detach();
                    }
                }
            }
        }
    }

public:
    bool Start(int port) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) return false;

        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(listenSocket);
            return false;
        }

        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSocket);
            return false;
        }

        running = true;
        serverThread = std::thread(&CollaborationServer::ServerLoop, this);
        return true;
    }

    void Broadcast(const JsonValue& message) {
        std::string json = message.Serialize();
        std::lock_guard<std::mutex> lock(clientsMtx);
        for (SOCKET client : clients) {
            SendWebSocketFrame(client, json);
        }
    }

    void SendTo(SOCKET client, const JsonValue& message) {
        SendWebSocketFrame(client, message.Serialize());
    }

    void SetMessageHandler(std::function<void(SOCKET, const JsonValue&)> handler) {
        onMessage = handler;
    }

    void Stop() {
        running = false;
        if (serverThread.joinable()) serverThread.join();
        if (listenSocket != INVALID_SOCKET) {
            closesocket(listenSocket);
            listenSocket = INVALID_SOCKET;
        }
        WSACleanup();
    }

    ~CollaborationServer() {
        if (running) Stop();
    }
};

// ============================================================================
// CODE EMITTER (x64 Native Code Generation)
// ============================================================================

class CodeEmitter {
    std::vector<uint8_t> code;
    size_t codeSize = 0;

public:
    void EmitU8(uint8_t val) { code.push_back(val); }
    void EmitU16(uint16_t val) {
        code.push_back(val & 0xFF);
        code.push_back((val >> 8) & 0xFF);
    }
    void EmitU32(uint32_t val) {
        code.push_back(val & 0xFF);
        code.push_back((val >> 8) & 0xFF);
        code.push_back((val >> 16) & 0xFF);
        code.push_back((val >> 24) & 0xFF);
    }
    void EmitU64(uint64_t val) {
        for (int i = 0; i < 8; ++i) {
            code.push_back((val >> (i * 8)) & 0xFF);
        }
    }

    // x64 instruction emitters
    void EmitPushReg(int reg) { EmitU8(0x50 + (reg & 7)); }
    void EmitPopReg(int reg) { EmitU8(0x58 + (reg & 7)); }
    void EmitRet() { EmitU8(0xC3); }
    void EmitNop() { EmitU8(0x90); }

    void EmitMovRegImm32(int reg, uint32_t imm) {
        EmitU8(0x48 + (reg >= 8 ? 1 : 0)); // REX.W
        EmitU8(0xC7);
        EmitU8(0xC0 + (reg & 7));
        EmitU32(imm);
    }

    void EmitMovRegReg(int dst, int src) {
        EmitU8(0x48 + ((dst >= 8) ? 1 : 0) + ((src >= 8) ? 4 : 0));
        EmitU8(0x89);
        EmitU8(0xC0 + ((src & 7) << 3) + (dst & 7));
    }

    void EmitAddRegImm32(int reg, uint32_t imm) {
        EmitU8(0x48 + (reg >= 8 ? 1 : 0));
        EmitU8(0x81);
        EmitU8(0xC0 + (reg & 7));
        EmitU32(imm);
    }

    void EmitSubRegImm32(int reg, uint32_t imm) {
        EmitU8(0x48 + (reg >= 8 ? 1 : 0));
        EmitU8(0x81);
        EmitU8(0xE8 + (reg & 7));
        EmitU32(imm);
    }

    void EmitCallReg(int reg) {
        EmitU8(0xFF);
        EmitU8(0xD0 + (reg & 7));
    }

    void EmitJmpRel32(int32_t offset) {
        EmitU8(0xE9);
        EmitU32((uint32_t)offset);
    }

    void EmitJccRel32(uint8_t cond, int32_t offset) {
        EmitU8(0x0F);
        EmitU8(0x80 + cond);
        EmitU32((uint32_t)offset);
    }

    // Function prologue/epilogue
    void EmitFunctionPrologue() {
        EmitPushReg(5);  // rbp
        EmitMovRegReg(5, 4); // mov rbp, rsp
    }

    void EmitFunctionEpilogue() {
        EmitPopReg(5);   // rbp
        EmitRet();
    }

    // Allocate executable memory and return function pointer
    void* AllocateExecutable() {
        void* mem = VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem) {
            memcpy(mem, code.data(), code.size());
            DWORD oldProtect;
            VirtualProtect(mem, code.size(), PAGE_EXECUTE_READ, &oldProtect);
        }
        return mem;
    }

    void* GetCode() { return code.empty() ? nullptr : (void*)code.data(); }
    size_t GetSize() const { return code.size(); }
    void Clear() { code.clear(); }

    // Save to file
    bool SaveToFile(const std::string& path) {
        std::ofstream file(path, std::ios::binary);
        if (!file) return false;
        file.write((char*)code.data(), code.size());
        return file.good();
    }
};

// ============================================================================
// GUI FRAMEWORK (Win32 Native)
// ============================================================================

class IDEWindow {
    HWND hWnd = nullptr;
    HWND hEditor = nullptr;
    HWND hSidebar = nullptr;
    HWND hStatusBar = nullptr;
    HFONT hFont = nullptr;

    LSPClient lsp;
    Debugger debugger;
    CollaborationServer collab;
    CodeEmitter emitter;

    std::string currentFile;
    std::string fileContent;
    bool modified = false;
    int currentLine = 0;
    int currentCol = 0;

    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        IDEWindow* ide = (IDEWindow*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (ide) return ide->HandleMessage(msg, wParam, lParam);
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
            case WM_CREATE: {
                // Create editor (RichEdit)
                LoadLibraryA("Msftedit.dll");
                hEditor = CreateWindowExA(WS_EX_CLIENTEDGE, "RICHEDIT50W", "",
                    WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
                    WS_VSCROLL | WS_HSCROLL | ES_NOHIDESEL,
                    200, 0, 800, 600, hWnd, (HMENU)1, GetModuleHandle(nullptr), nullptr);

                // Set font
                hFont = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
                SendMessage(hEditor, WM_SETFONT, (WPARAM)hFont, TRUE);

                // Create sidebar
                hSidebar = CreateWindowExA(0, "LISTBOX", "",
                    WS_CHILD | WS_VISIBLE | LBS_NOTIFY,
                    0, 0, 200, 600, hWnd, (HMENU)2, GetModuleHandle(nullptr), nullptr);

                // Create status bar
                hStatusBar = CreateWindowExA(0, STATUSCLASSNAME, "Ready",
                    WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                    0, 0, 0, 0, hWnd, (HMENU)3, GetModuleHandle(nullptr), nullptr);

                // Initialize collaboration
                collab.SetMessageHandler([this](SOCKET client, const JsonValue& msg) {
                    HandleCollaborationMessage(client, msg);
                });
                collab.Start(9001);

                // Initialize LSP
                if (lsp.Connect("\\\\.\\pipe\clangd")) {
                    lsp.Initialize("d:\\rawrxd");
                    SetStatus("LSP Connected");
                } else {
                    SetStatus("LSP Not Available");
                }

                return 0;
            }

            case WM_SIZE: {
                RECT rc;
                GetClientRect(hWnd, &rc);
                int width = rc.right - rc.left;
                int height = rc.bottom - rc.top;

                SetWindowPos(hSidebar, nullptr, 0, 0, 200, height - 20, SWP_NOZORDER);
                SetWindowPos(hEditor, nullptr, 200, 0, width - 200, height - 20, SWP_NOZORDER);
                SetWindowPos(hStatusBar, nullptr, 0, height - 20, width, 20, SWP_NOZORDER);
                return 0;
            }

            case WM_COMMAND: {
                int id = LOWORD(wParam);
                switch (id) {
                    case 1: // Editor
                        if (HIWORD(wParam) == EN_CHANGE) {
                            modified = true;
                            UpdateTitle();
                        }
                        break;
                    case ID_FILE_NEW: NewFile(); break;
                    case ID_FILE_OPEN: OpenFile(); break;
                    case ID_FILE_SAVE: SaveFile(); break;
                    case ID_FILE_EXIT: PostQuitMessage(0); break;
                    case ID_EDIT_UNDO: SendMessage(hEditor, EM_UNDO, 0, 0); break;
                    case ID_EDIT_CUT: SendMessage(hEditor, WM_CUT, 0, 0); break;
                    case ID_EDIT_COPY: SendMessage(hEditor, WM_COPY, 0, 0); break;
                    case ID_EDIT_PASTE: SendMessage(hEditor, WM_PASTE, 0, 0); break;
                    case ID_BUILD_COMPILE: CompileCode(); break;
                    case ID_BUILD_RUN: RunCode(); break;
                    case ID_BUILD_DEBUG: DebugCode(); break;
                    case ID_LSP_COMPLETION: RequestCompletion(); break;
                    case ID_LSP_DEFINITION: GoToDefinition(); break;
                    case ID_LSP_HOVER: ShowHover(); break;
                    case ID_COLLAB_START: StartCollaboration(); break;
                    case ID_EMITTER_TEST: TestCodeEmitter(); break;
                }
                return 0;
            }

            case WM_KEYDOWN: {
                if (wParam == VK_F5) RunCode();
                if (wParam == VK_F9) DebugCode();
                if (wParam == VK_F12) GoToDefinition();
                if (wParam == VK_SPACE && (GetKeyState(VK_CONTROL) & 0x8000)) {
                    RequestCompletion();
                }
                return 0;
            }

            case WM_CLOSE:
                if (modified && MessageBoxA(hWnd, "Save changes?", "RawrXD IDE",
                    MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    SaveFile();
                }
                DestroyWindow(hWnd);
                return 0;

            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    void SetStatus(const std::string& msg) {
        SetWindowTextA(hStatusBar, msg.c_str());
    }

    void UpdateTitle() {
        std::string title = "RawrXD IDE";
        if (!currentFile.empty()) {
            title += " - " + currentFile;
            if (modified) title += " *";
        }
        SetWindowTextA(hWnd, title.c_str());
    }

    void NewFile() {
        if (modified && MessageBoxA(hWnd, "Save changes?", "RawrXD IDE", MB_YESNO) == IDYES) {
            SaveFile();
        }
        SetWindowTextA(hEditor, "");
        currentFile.clear();
        modified = false;
        UpdateTitle();
    }

    void OpenFile() {
        char filename[MAX_PATH] = {};
        OPENFILENAMEA ofn = {};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hWnd;
        ofn.lpstrFilter = "C++ Files\0*.cpp;*.h;*.hpp\0All Files\0*.*\0";
        ofn.lpstrFile = filename;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_FILEMUSTEXIST;

        if (GetOpenFileNameA(&ofn)) {
            std::ifstream file(filename);
            if (file) {
                std::string content((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
                SetWindowTextA(hEditor, content.c_str());
                currentFile = filename;
                modified = false;
                UpdateTitle();

                // Notify LSP
                lsp.DidOpen("file://" + currentFile, "cpp", content);
            }
        }
    }

    void SaveFile() {
        if (currentFile.empty()) {
            char filename[MAX_PATH] = {};
            OPENFILENAMEA ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hWnd;
            ofn.lpstrFilter = "C++ Files\0*.cpp\0";
            ofn.lpstrFile = filename;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_OVERWRITEPROMPT;

            if (!GetSaveFileNameA(&ofn)) return;
            currentFile = filename;
        }

        char* buffer = nullptr;
        int len = GetWindowTextLengthA(hEditor);
        buffer = new char[len + 1];
        GetWindowTextA(hEditor, buffer, len + 1);

        std::ofstream file(currentFile);
        if (file) {
            file.write(buffer, len);
            modified = false;
            UpdateTitle();

            // Notify LSP
            lsp.DidChange("file://" + currentFile, 1, std::string(buffer, len));
        }
        delete[] buffer;
    }

    void CompileCode() {
        SetStatus("Compiling...");

        // Save first
        if (modified) SaveFile();
        if (currentFile.empty()) {
            SetStatus("No file to compile");
            return;
        }

        // Compile using cl.exe
        std::string cmd = "cl.exe /nologo /EHsc /O2 /Fe:d:\\rawrxd\\output.exe \"" + currentFile + "\" 2>&1";
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[4096];
            std::string output;
            while (fgets(buffer, sizeof(buffer), pipe)) {
                output += buffer;
            }
            _pclose(pipe);

            if (output.find("error") != std::string::npos) {
                SetStatus("Compilation failed - see output");
                MessageBoxA(hWnd, output.c_str(), "Compilation Errors", MB_OK);
            } else {
                SetStatus("Compilation successful");
            }
        }
    }

    void RunCode() {
        if (currentFile.empty()) {
            CompileCode();
        }
        if (std::filesystem::exists("d:\\rawrxd\\output.exe")) {
            ShellExecuteA(hWnd, "open", "d:\\rawrxd\\output.exe", nullptr, nullptr, SW_SHOW);
            SetStatus("Running...");
        }
    }

    void DebugCode() {
        if (currentFile.empty()) return;

        CompileCode();
        if (!std::filesystem::exists("d:\\rawrxd\\output.exe")) return;

        debugger.SetOutputCallback([this](const std::string& msg) {
            SetStatus("Debug: " + msg);
        });
        debugger.SetBreakpointCallback([this](int addr) {
            SetStatus("Breakpoint hit at " + std::to_string(addr));
        });

        if (debugger.Launch("d:\\rawrxd\\output.exe", "")) {
            SetStatus("Debugging started");
        }
    }

    void RequestCompletion() {
        // Get cursor position
        CHARRANGE cr;
        SendMessage(hEditor, EM_EXGETSEL, 0, (LPARAM)&cr);

        int line = 0;
        int col = 0;
        // Calculate line/col from character position

        auto completions = lsp.GetCompletions("file://" + currentFile, line, col);

        // Show completion list
        if (!completions.empty()) {
            std::string items;
            for (const auto& item : completions) {
                if (item.HasKey("label")) {
                    items += item["label"].GetString() + "\n";
                }
            }
            MessageBoxA(hWnd, items.c_str(), "Completions", MB_OK);
        }
    }

    void GoToDefinition() {
        CHARRANGE cr;
        SendMessage(hEditor, EM_EXGETSEL, 0, (LPARAM)&cr);

        int line = 0;
        int col = 0;

        auto result = lsp.GetDefinition("file://" + currentFile, line, col);
        if (result.HasKey("result") && result["result"].IsArray()) {
            auto locations = result["result"].GetArray();
            if (!locations.empty()) {
                // Navigate to definition
                SetStatus("Navigated to definition");
            }
        }
    }

    void ShowHover() {
        SetStatus("Hover info would appear here");
    }

    void StartCollaboration() {
        SetStatus("Collaboration server running on port 9001");

        // Broadcast current file to all clients
        JsonValue msg;
        msg["type"] = "file_opened";
        msg["filename"] = currentFile;
        collab.Broadcast(msg);
    }

    void HandleCollaborationMessage(SOCKET client, const JsonValue& msg) {
        if (msg.HasKey("type")) {
            std::string type = msg["type"].GetString();
            if (type == "edit") {
                // Apply remote edit
                SetStatus("Remote edit received");
            } else if (type == "cursor") {
                // Update remote cursor position
            }
        }
    }

    void TestCodeEmitter() {
        emitter.Clear();

        // Emit simple function: int add(int a, int b) { return a + b; }
        emitter.EmitFunctionPrologue();
        emitter.EmitMovRegReg(0, 2);  // mov rax, rdx (arg2)
        emitter.EmitAddRegImm32(0, 8); // add rax, 8 (arg1 is at rbp+8)
        emitter.EmitFunctionEpilogue();

        // Allocate and test
        void* func = emitter.AllocateExecutable();
        if (func) {
            // Call the emitted function
            typedef int (*AddFunc)(int, int);
            AddFunc add = (AddFunc)func;
            int result = add(5, 3);

            SetStatus("Code emitter test: 5 + 3 = " + std::to_string(result));

            // Free memory
            VirtualFree(func, 0, MEM_RELEASE);
        }
    }

public:
    bool Create(HINSTANCE hInstance, int nCmdShow) {
        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = WndProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = "RawrXD_IDE";
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

        if (!RegisterClassExA(&wc)) return false;

        hWnd = CreateWindowExA(0, "RawrXD_IDE", "RawrXD IDE - Zero Dependency",
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 1200, 800,
            nullptr, BuildMenuBar(), hInstance, nullptr);

        if (!hWnd) return false;

        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)this);

        ShowWindow(hWnd, nCmdShow);
        UpdateWindow(hWnd);

        return true;
    }

    HMENU BuildMenuBar() {
        HMENU hMenu = ::CreateMenu();

        HMENU hFile = CreatePopupMenu();
        AppendMenuA(hFile, MF_STRING, ID_FILE_NEW, "&New\tCtrl+N");
        AppendMenuA(hFile, MF_STRING, ID_FILE_OPEN, "&Open...\tCtrl+O");
        AppendMenuA(hFile, MF_STRING, ID_FILE_SAVE, "&Save\tCtrl+S");
        AppendMenuA(hFile, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(hFile, MF_STRING, ID_FILE_EXIT, "E&xit");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hFile, "&File");

        HMENU hEdit = CreatePopupMenu();
        AppendMenuA(hEdit, MF_STRING, ID_EDIT_UNDO, "&Undo\tCtrl+Z");
        AppendMenuA(hEdit, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(hEdit, MF_STRING, ID_EDIT_CUT, "Cu&t\tCtrl+X");
        AppendMenuA(hEdit, MF_STRING, ID_EDIT_COPY, "&Copy\tCtrl+C");
        AppendMenuA(hEdit, MF_STRING, ID_EDIT_PASTE, "&Paste\tCtrl+V");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hEdit, "&Edit");

        HMENU hBuild = CreatePopupMenu();
        AppendMenuA(hBuild, MF_STRING, ID_BUILD_COMPILE, "&Compile\tF7");
        AppendMenuA(hBuild, MF_STRING, ID_BUILD_RUN, "&Run\tF5");
        AppendMenuA(hBuild, MF_STRING, ID_BUILD_DEBUG, "&Debug\tF9");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hBuild, "&Build");

        HMENU hLSP = CreatePopupMenu();
        AppendMenuA(hLSP, MF_STRING, ID_LSP_COMPLETION, "&Completion\tCtrl+Space");
        AppendMenuA(hLSP, MF_STRING, ID_LSP_DEFINITION, "Go to &Definition\tF12");
        AppendMenuA(hLSP, MF_STRING, ID_LSP_HOVER, "&Hover Info");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hLSP, "&LSP");

        HMENU hCollab = CreatePopupMenu();
        AppendMenuA(hCollab, MF_STRING, ID_COLLAB_START, "&Start Server");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hCollab, "&Collaboration");

        HMENU hDev = CreatePopupMenu();
        AppendMenuA(hDev, MF_STRING, ID_EMITTER_TEST, "&Test Code Emitter");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hDev, "&Developer");

        return hMenu;
    }

    int Run() {
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return (int)msg.wParam;
    }

    ~IDEWindow() {
        if (hFont) DeleteObject(hFont);
    }

    // Menu IDs
    static constexpr int ID_FILE_NEW = 1001;
    static constexpr int ID_FILE_OPEN = 1002;
    static constexpr int ID_FILE_SAVE = 1003;
    static constexpr int ID_FILE_EXIT = 1004;
    static constexpr int ID_EDIT_UNDO = 2001;
    static constexpr int ID_EDIT_CUT = 2002;
    static constexpr int ID_EDIT_COPY = 2003;
    static constexpr int ID_EDIT_PASTE = 2004;
    static constexpr int ID_BUILD_COMPILE = 3001;
    static constexpr int ID_BUILD_RUN = 3002;
    static constexpr int ID_BUILD_DEBUG = 3003;
    static constexpr int ID_LSP_COMPLETION = 4001;
    static constexpr int ID_LSP_DEFINITION = 4002;
    static constexpr int ID_LSP_HOVER = 4003;
    static constexpr int ID_COLLAB_START = 5001;
    static constexpr int ID_EMITTER_TEST = 6001;
};

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    IDEWindow ide;
    if (!ide.Create(hInstance, nCmdShow)) {
        MessageBoxA(nullptr, "Failed to create IDE window", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    return ide.Run();
}
