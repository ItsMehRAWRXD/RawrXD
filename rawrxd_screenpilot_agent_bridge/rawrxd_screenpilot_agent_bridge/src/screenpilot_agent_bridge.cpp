#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <climits>
#include <cwctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace fs = std::filesystem;

struct Config {
    unsigned short port = 11437;
    fs::path rawrExe = L"rawr.exe";
    fs::path workspaceRoot = L"F:\\~dev";
};

struct RunningJob {
    HANDLE process = nullptr;
    HANDLE job = nullptr;
};

static std::mutex g_jobsMutex;
static std::map<std::string, RunningJob> g_jobs;
static std::atomic_bool g_running{true};
static std::string g_sessionToken;

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

static std::string jsonEscape(std::string_view s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (c < 0x20) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << int(c);
                } else {
                    o << char(c);
                }
        }
    }
    return o.str();
}

static std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

static std::string narrow(std::wstring_view s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

static std::optional<std::string> jsonGetString(std::string_view json, std::string_view key) {
    std::string needle = "\"" + std::string(key) + "\"";
    size_t p = json.find(needle);
    if (p == std::string_view::npos) return std::nullopt;
    p = json.find(':', p + needle.size());
    if (p == std::string_view::npos) return std::nullopt;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (p >= json.size() || json[p] != '"') return std::nullopt;
    ++p;

    std::string out;
    while (p < json.size()) {
        char c = json[p++];
        if (c == '"') return out;
        if (c != '\\') {
            out.push_back(c);
            continue;
        }
        if (p >= json.size()) return std::nullopt;
        char e = json[p++];
        switch (e) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                if (p + 4 > json.size()) return std::nullopt;
                unsigned value = 0;
                for (int i = 0; i < 4; ++i) {
                    char h = json[p++];
                    value <<= 4;
                    if (h >= '0' && h <= '9') value |= unsigned(h - '0');
                    else if (h >= 'a' && h <= 'f') value |= unsigned(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') value |= unsigned(h - 'A' + 10);
                    else return std::nullopt;
                }
                if (value <= 0x7F) out.push_back(static_cast<char>(value));
                else {
                    wchar_t wc = static_cast<wchar_t>(value);
                    out += narrow(std::wstring_view(&wc, 1));
                }
                break;
            }
            default: return std::nullopt;
        }
    }
    return std::nullopt;
}

static std::string randomToken(size_t bytes = 32) {
    std::vector<unsigned char> b(bytes);
    if (BCryptGenRandom(nullptr, b.data(), static_cast<ULONG>(b.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(bytes * 2);
    for (auto v : b) {
        s.push_back(hex[v >> 4]);
        s.push_back(hex[v & 15]);
    }
    return s;
}

static bool sendAll(SOCKET s, const char* data, size_t len) {
    while (len) {
        int n = send(s, data, static_cast<int>(std::min<size_t>(len, INT_MAX)), 0);
        if (n <= 0) return false;
        data += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

static bool sendAll(SOCKET s, const std::string& text) {
    return sendAll(s, text.data(), text.size());
}

static std::string corsHeaders(std::string_view origin) {
    std::ostringstream o;
    if (origin == "null" ||
        origin.starts_with("http://127.0.0.1") ||
        origin.starts_with("http://localhost")) {
        o << "Access-Control-Allow-Origin: " << origin << "\r\n"
          << "Vary: Origin\r\n";
    }
    o << "Access-Control-Allow-Headers: Content-Type, X-RawrXD-Session\r\n"
      << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    return o.str();
}

static void sendJson(SOCKET s, int code, std::string_view status, std::string_view body, std::string_view origin = {}) {
    std::ostringstream h;
    h << "HTTP/1.1 " << code << ' ' << status << "\r\n"
      << "Content-Type: application/json; charset=utf-8\r\n"
      << corsHeaders(origin)
      << "Cache-Control: no-store\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n\r\n";
    sendAll(s, h.str());
    sendAll(s, body.data(), body.size());
}

static bool sendChunk(SOCKET s, std::string_view payload) {
    std::ostringstream h;
    h << std::hex << payload.size() << "\r\n";
    return sendAll(s, h.str()) &&
           sendAll(s, payload.data(), payload.size()) &&
           sendAll(s, "\r\n", 2);
}

static bool isAllowedHost(std::string host, unsigned short port) {
    host = lower(trim(host));
    const std::string p = std::to_string(port);
    return host == "127.0.0.1:" + p ||
           host == "localhost:" + p ||
           host == "127.0.0.1" ||
           host == "localhost";
}

static bool isAllowedOrigin(const std::string& origin) {
    if (origin.empty()) return true;
    if (origin == "null") return true; // file:// HTML
    return origin.starts_with("http://127.0.0.1") ||
           origin.starts_with("http://localhost");
}

struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string,std::string> headers;
    std::string body;
};

static std::optional<HttpRequest> readRequest(SOCKET s) {
    constexpr size_t MAX_HEADER = 64 * 1024;
    constexpr size_t MAX_BODY = 2 * 1024 * 1024;

    std::string data;
    data.reserve(8192);
    char buf[4096];

    while (data.find("\r\n\r\n") == std::string::npos) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) return std::nullopt;
        data.append(buf, buf + n);
        if (data.size() > MAX_HEADER) return std::nullopt;
    }

    size_t split = data.find("\r\n\r\n");
    std::string head = data.substr(0, split);
    std::string body = data.substr(split + 4);

    std::istringstream hs(head);
    HttpRequest r;
    std::string line;

    if (!std::getline(hs, line)) return std::nullopt;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    {
        std::istringstream first(line);
        std::string version;
        first >> r.method >> r.path >> version;
        if (r.method.empty() || r.path.empty()) return std::nullopt;
    }

    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string k = lower(trim(line.substr(0,pos)));
        std::string v = trim(line.substr(pos+1));
        r.headers[k] = v;
    }

    size_t contentLength = 0;
    if (auto it = r.headers.find("content-length"); it != r.headers.end()) {
        try { contentLength = static_cast<size_t>(std::stoull(it->second)); }
        catch (...) { return std::nullopt; }
    }
    if (contentLength > MAX_BODY) return std::nullopt;

    while (body.size() < contentLength) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) return std::nullopt;
        body.append(buf, buf+n);
        if (body.size() > MAX_BODY) return std::nullopt;
    }
    if (body.size() > contentLength) body.resize(contentLength);
    r.body = std::move(body);
    return r;
}

static std::wstring quoteWinArg(std::wstring_view arg) {
    if (arg.empty()) return L"\"\"";
    bool needs = false;
    for (wchar_t c : arg) {
        if (std::iswspace(c) || c == L'"') { needs = true; break; }
    }
    if (!needs) return std::wstring(arg);

    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') {
            ++slashes;
        } else if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(L'"');
            slashes = 0;
        } else {
            out.append(slashes, L'\\');
            slashes = 0;
            out.push_back(c);
        }
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

static bool safeModelName(std::string_view s) {
    if (s.empty() || s.size() > 256) return false;
    for (unsigned char c : s) {
        if (std::isalnum(c)) continue;
        switch (c) {
            case '.': case '_': case '-': case ':': case '/': case '\\':
                continue;
            default:
                return false;
        }
    }
    return true;
}

static std::optional<fs::path> canonicalWorkspace(const fs::path& root, std::string_view requestedUtf8) {
    try {
        fs::path r = fs::weakly_canonical(root);
        fs::path q = fs::weakly_canonical(widen(requestedUtf8));
        auto norm = [](std::wstring s) {
            std::transform(s.begin(), s.end(), s.begin(), ::towlower);
            if (!s.empty() && s.back() != L'\\' && s.back() != L'/') s.push_back(L'\\');
            return s;
        };
        std::wstring rp = norm(r.wstring());
        std::wstring qp = norm(q.wstring());

        if (!qp.starts_with(rp)) return std::nullopt;
        if (!fs::exists(q) || !fs::is_directory(q)) return std::nullopt;
        return q;
    } catch (...) {
        return std::nullopt;
    }
}

static std::string modePrefix(std::string mode) {
    mode = lower(std::move(mode));
    if (mode == "ask") {
        return "[RAWRXD_MODE=ASK] Inspect and answer. Do not modify files or execute mutating tools unless explicitly requested. ";
    }
    if (mode == "plan") {
        return "[RAWRXD_MODE=PLAN] Inspect as needed and produce a concrete plan. Do not modify source. ";
    }
    if (mode == "build") {
        return "[RAWRXD_MODE=BUILD] You may edit source, build, test, and repair within the workspace using canonical RawrXD Tool Authority. ";
    }
    return "[RAWRXD_MODE=AGENT] Operate autonomously within the workspace using canonical RawrXD Tool Authority; inspect, edit, build, test, and return receipts. ";
}

static int runRawrStreaming(
    SOCKET client,
    const Config& cfg,
    const std::string& requestId,
    const std::string& mode,
    const std::string& model,
    const fs::path& workspace,
    const std::string& prompt
) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return -100;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        return -101;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};

    std::string effectivePrompt = modePrefix(mode) + prompt;

    std::wstring cmd;
    cmd += quoteWinArg(cfg.rawrExe.wstring());
    cmd += L" run ";
    cmd += quoteWinArg(widen(model));
    cmd += L" ";
    cmd += quoteWinArg(widen(effectivePrompt));

    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');

    BOOL ok = CreateProcessW(
        cfg.rawrExe.c_str(),
        mutableCmd.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        workspace.c_str(),
        &si, &pi
    );

    CloseHandle(writePipe);

    if (!ok) {
        DWORD e = GetLastError();
        CloseHandle(readPipe);
        CloseHandle(job);
        return -static_cast<int>(e);
    }

    AssignProcessToJobObject(job, pi.hProcess);
    CloseHandle(pi.hThread);

    {
        std::scoped_lock lock(g_jobsMutex);
        g_jobs[requestId] = RunningJob{pi.hProcess, job};
    }

    auto emit = [&](std::string_view type, std::string_view data) {
        std::string line = "{\"type\":\"" + jsonEscape(type) +
                           "\",\"requestId\":\"" + jsonEscape(requestId) +
                           "\",\"data\":\"" + jsonEscape(data) + "\"}\n";
        return sendChunk(client, line);
    };

    emit("started", "rawr run");

    char outBuf[4096];
    DWORD nread = 0;
    bool clientAlive = true;
    while (clientAlive && ReadFile(readPipe, outBuf, sizeof(outBuf), &nread, nullptr) && nread > 0) {
        clientAlive = emit("output", std::string_view(outBuf, nread));
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    {
        std::scoped_lock lock(g_jobsMutex);
        g_jobs.erase(requestId);
    }

    CloseHandle(readPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(job);

    emit("exit", std::to_string(exitCode));
    return static_cast<int>(exitCode);
}

static void handleClient(SOCKET client, Config cfg) {
    auto closeClient = [&] { shutdown(client, SD_BOTH); closesocket(client); };

    auto reqOpt = readRequest(client);
    if (!reqOpt) { closeClient(); return; }
    auto& req = *reqOpt;

    std::string host = req.headers.count("host") ? req.headers["host"] : "";
    std::string origin = req.headers.count("origin") ? req.headers["origin"] : "";

    if (!isAllowedHost(host, cfg.port) || !isAllowedOrigin(origin)) {
        sendJson(client, 403, "Forbidden", R"({"ok":false,"error":"host/origin rejected"})", origin);
        closeClient();
        return;
    }

    if (req.method == "OPTIONS") {
        std::ostringstream h;
        h << "HTTP/1.1 204 No Content\r\n"
          << corsHeaders(origin)
          << "Content-Length: 0\r\nConnection: close\r\n\r\n";
        sendAll(client, h.str());
        closeClient();
        return;
    }

    if (req.method == "GET" && req.path == "/api/health") {
        std::string rawrPath = jsonEscape(narrow(cfg.rawrExe.wstring()));
        std::string rootPath = jsonEscape(narrow(cfg.workspaceRoot.wstring()));
        std::string body = "{\"ok\":true,\"service\":\"RawrXD ScreenPilot Agent Bridge\","
                           "\"rawr\":\"" + rawrPath + "\",\"workspaceRoot\":\"" + rootPath + "\"}";
        sendJson(client, 200, "OK", body, origin);
        closeClient();
        return;
    }

    if (req.method == "POST" && req.path == "/api/session") {
        std::string body = "{\"ok\":true,\"token\":\"" + g_sessionToken + "\"}";
        sendJson(client, 200, "OK", body, origin);
        closeClient();
        return;
    }

    auto tokenIt = req.headers.find("x-rawrxd-session");
    if (tokenIt == req.headers.end() || tokenIt->second != g_sessionToken) {
        sendJson(client, 401, "Unauthorized", R"({"ok":false,"error":"bad session"})", origin);
        closeClient();
        return;
    }

    if (req.method == "POST" && req.path == "/api/agent/cancel") {
        auto id = jsonGetString(req.body, "requestId");
        if (!id || id->empty()) {
            sendJson(client, 400, "Bad Request", R"({"ok":false,"error":"requestId required"})", origin);
            closeClient();
            return;
        }

        bool cancelled = false;
        {
            std::scoped_lock lock(g_jobsMutex);
            auto it = g_jobs.find(*id);
            if (it != g_jobs.end() && it->second.job) {
                cancelled = TerminateJobObject(it->second.job, ERROR_CANCELLED) != FALSE;
            }
        }
        sendJson(client, 200, "OK",
                 cancelled ? R"({"ok":true,"cancelled":true})"
                           : R"({"ok":true,"cancelled":false})",
                 origin);
        closeClient();
        return;
    }

    if (req.method == "POST" && req.path == "/api/agent/run") {
        auto mode = jsonGetString(req.body, "mode").value_or("agent");
        auto model = jsonGetString(req.body, "model");
        auto workspace = jsonGetString(req.body, "workspace");
        auto prompt = jsonGetString(req.body, "prompt");
        auto requestId = jsonGetString(req.body, "requestId").value_or(randomToken(8));

        if (!model || !workspace || !prompt || prompt->empty()) {
            sendJson(client, 400, "Bad Request",
                     R"({"ok":false,"error":"model, workspace, prompt required"})", origin);
            closeClient();
            return;
        }
        if (!safeModelName(*model)) {
            sendJson(client, 400, "Bad Request",
                     R"({"ok":false,"error":"invalid model name"})", origin);
            closeClient();
            return;
        }
        auto canonical = canonicalWorkspace(cfg.workspaceRoot, *workspace);
        if (!canonical) {
            sendJson(client, 403, "Forbidden",
                     R"({"ok":false,"error":"workspace outside configured root or missing"})", origin);
            closeClient();
            return;
        }

        std::ostringstream h;
        h << "HTTP/1.1 200 OK\r\n"
          << "Content-Type: application/x-ndjson; charset=utf-8\r\n"
          << corsHeaders(origin)
          << "Cache-Control: no-store\r\n"
          << "Transfer-Encoding: chunked\r\n"
          << "Connection: close\r\n\r\n";
        if (!sendAll(client, h.str())) { closeClient(); return; }

        int rc = runRawrStreaming(client, cfg, requestId, mode, *model, *canonical, *prompt);
        if (rc < 0) {
            std::string line = "{\"type\":\"bridge_error\",\"requestId\":\"" + jsonEscape(requestId) +
                               "\",\"data\":\"CreateProcess/bridge failure " + std::to_string(rc) + "\"}\n";
            sendChunk(client, line);
        }
        sendAll(client, "0\r\n\r\n", 5);
        closeClient();
        return;
    }

    sendJson(client, 404, "Not Found", R"({"ok":false,"error":"route not found"})", origin);
    closeClient();
}

static Config parseArgs(int argc, wchar_t** argv) {
    Config c;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        auto need = [&](const wchar_t* name) -> std::wstring {
            if (i + 1 >= argc) {
                std::wcerr << L"Missing value for " << name << L"\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == L"--port") {
            c.port = static_cast<unsigned short>(std::stoul(need(L"--port")));
        } else if (a == L"--rawr") {
            c.rawrExe = need(L"--rawr");
        } else if (a == L"--workspace-root") {
            c.workspaceRoot = need(L"--workspace-root");
        }
    }
    c.rawrExe = fs::absolute(c.rawrExe);
    c.workspaceRoot = fs::absolute(c.workspaceRoot);
    return c;
}

int wmain(int argc, wchar_t** argv) {
    Config cfg = parseArgs(argc, argv);

    if (!fs::exists(cfg.rawrExe)) {
        std::wcerr << L"[bridge] rawr executable not found: " << cfg.rawrExe << L"\n";
        return 2;
    }
    if (!fs::exists(cfg.workspaceRoot) || !fs::is_directory(cfg.workspaceRoot)) {
        std::wcerr << L"[bridge] workspace root not found: " << cfg.workspaceRoot << L"\n";
        return 3;
    }

    try {
        g_sessionToken = randomToken();
    } catch (const std::exception& e) {
        std::cerr << "[bridge] session RNG failed: " << e.what() << "\n";
        return 4;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 5;

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        WSACleanup();
        return 6;
    }

    BOOL exclusive = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg.port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr); // hard localhost-only bind

    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[bridge] bind failed on 127.0.0.1:" << cfg.port
                  << " WSA=" << WSAGetLastError() << "\n";
        closesocket(listener);
        WSACleanup();
        return 7;
    }

    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listener);
        WSACleanup();
        return 8;
    }

    std::wcout << L"[bridge] RawrXD ScreenPilot Agent Bridge\n"
               << L"[bridge] listening: http://127.0.0.1:" << cfg.port << L"\n"
               << L"[bridge] rawr: " << cfg.rawrExe << L"\n"
               << L"[bridge] workspace root: " << cfg.workspaceRoot << L"\n";

    while (g_running.load()) {
        SOCKET client = accept(listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) break;
        std::thread(handleClient, client, cfg).detach();
    }

    closesocket(listener);
    WSACleanup();
    return 0;
}
