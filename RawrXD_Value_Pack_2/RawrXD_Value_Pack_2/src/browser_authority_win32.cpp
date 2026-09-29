#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#include "rawrxd/value/browser_authority.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string_view>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace rawrxd::value {
namespace {

struct InternetHandle {
    HINTERNET h{};
    InternetHandle() = default;
    explicit InternetHandle(HINTERNET v) : h(v) {}
    ~InternetHandle() { if (h) WinHttpCloseHandle(h); }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
    InternetHandle(InternetHandle&& o) noexcept : h(o.h) { o.h = nullptr; }
    InternetHandle& operator=(InternetHandle&& o) noexcept {
        if (this != &o) { if (h) WinHttpCloseHandle(h); h = o.h; o.h = nullptr; }
        return *this;
    }
    explicit operator bool() const noexcept { return h != nullptr; }
};

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string jsonEscape(std::string_view s) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out.push_back(hex[(c >> 4) & 0xf]);
                    out.push_back(hex[c & 0xf]);
                } else out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string jsonUnescape(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c != '\\' || i + 1 >= s.size()) { out.push_back(c); continue; }
        char e = s[++i];
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
                if (i + 4 < s.size()) {
                    int v = 0; bool ok = true;
                    for (int k = 0; k < 4; ++k) { int h = hexVal(s[i + 1 + k]); if (h < 0) { ok = false; break; } v = v * 16 + h; }
                    if (ok) {
                        i += 4;
                        if (v < 0x80) out.push_back(static_cast<char>(v));
                        else if (v < 0x800) { out.push_back(static_cast<char>(0xc0 | (v >> 6))); out.push_back(static_cast<char>(0x80 | (v & 0x3f))); }
                        else { out.push_back(static_cast<char>(0xe0 | (v >> 12))); out.push_back(static_cast<char>(0x80 | ((v >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (v & 0x3f))); }
                    }
                }
                break;
            }
            default: out.push_back(e); break;
        }
    }
    return out;
}

std::optional<std::string> jsonStringField(const std::string& json, const std::string& key, std::size_t start = 0) {
    const std::string needle = "\"" + key + "\"";
    auto p = json.find(needle, start);
    if (p == std::string::npos) return std::nullopt;
    p = json.find(':', p + needle.size());
    if (p == std::string::npos) return std::nullopt;
    ++p; while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (p >= json.size() || json[p] != '"') return std::nullopt;
    ++p;
    std::string raw;
    bool escape = false;
    for (; p < json.size(); ++p) {
        char c = json[p];
        if (!escape && c == '"') return jsonUnescape(raw);
        if (!escape && c == '\\') { escape = true; raw.push_back(c); continue; }
        escape = false; raw.push_back(c);
    }
    return std::nullopt;
}

std::optional<std::string> runtimeValue(const std::string& json) {
    auto result = json.find("\"result\"");
    if (result == std::string::npos) return std::nullopt;
    auto value = json.find("\"value\"", result);
    if (value == std::string::npos) return std::nullopt;
    auto p = json.find(':', value + 7);
    if (p == std::string::npos) return std::nullopt;
    ++p; while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (p < json.size() && json[p] == '"') return jsonStringField(json.substr(value), "value");
    std::size_t e = p;
    while (e < json.size() && json[e] != ',' && json[e] != '}' && !std::isspace(static_cast<unsigned char>(json[e]))) ++e;
    if (e > p) return json.substr(p, e - p);
    return std::nullopt;
}

std::vector<std::uint8_t> decodeBase64(std::string_view in) {
    static int table[256];
    static std::once_flag flag;
    std::call_once(flag, [] {
        std::fill(std::begin(table), std::end(table), -1);
        const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; chars[i]; ++i) table[static_cast<unsigned char>(chars[i])] = i;
    });
    std::vector<std::uint8_t> out;
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        if (table[c] < 0) continue;
        val = (val << 6) + table[c]; bits += 6;
        if (bits >= 0) { out.push_back(static_cast<std::uint8_t>((val >> bits) & 0xff)); bits -= 8; }
    }
    return out;
}

std::wstring findEdge() {
    std::vector<std::wstring> candidates;
    wchar_t buffer[32768];
    auto addEnv = [&](const wchar_t* name, const wchar_t* suffix) {
        DWORD n = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(std::size(buffer)));
        if (n > 0 && n < std::size(buffer)) candidates.emplace_back(std::wstring(buffer) + suffix);
    };
    addEnv(L"PROGRAMFILES(X86)", L"\\Microsoft\\Edge\\Application\\msedge.exe");
    addEnv(L"PROGRAMFILES", L"\\Microsoft\\Edge\\Application\\msedge.exe");
    addEnv(L"LOCALAPPDATA", L"\\Microsoft\\Edge\\Application\\msedge.exe");
    for (const auto& p : candidates) if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return p;
    return {};
}

std::string httpRequest(std::uint16_t port, const std::wstring& method, const std::wstring& path) {
    InternetHandle session(WinHttpOpen(L"RawrXD-BrowserAuthority/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) return {};
    InternetHandle connect(WinHttpConnect(session.h, L"127.0.0.1", port, 0));
    if (!connect) return {};
    InternetHandle request(WinHttpOpenRequest(connect.h, method.c_str(), path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
    if (!request) return {};
    if (!WinHttpSendRequest(request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) return {};
    if (!WinHttpReceiveResponse(request.h, nullptr)) return {};
    std::string body;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.h, &available) || available == 0) break;
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request.h, chunk.data(), available, &read)) break;
        chunk.resize(read); body += chunk;
    }
    return body;
}

bool containsId(const std::string& json, std::uint64_t id) {
    const std::string needle = "\"id\":" + std::to_string(id);
    return json.find(needle) != std::string::npos;
}

} // namespace

struct BrowserAuthority::Impl {
    PROCESS_INFORMATION process{};
    bool owns_process{false};
    std::uint16_t port{9222};
    HINTERNET ws{nullptr};
    std::atomic<std::uint64_t> next_id{1};
    std::mutex io_mutex;
    std::mutex event_mutex;
    std::vector<std::string> console_events;
    std::vector<std::string> network_failures;

    ~Impl() { shutdown(); }

    void shutdown() {
        std::lock_guard<std::mutex> lock(io_mutex);
        if (ws) { WinHttpWebSocketClose(ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0); WinHttpCloseHandle(ws); ws = nullptr; }
        if (owns_process && process.hProcess) {
            TerminateProcess(process.hProcess, 0);
            WaitForSingleObject(process.hProcess, 2000);
        }
        if (process.hThread) CloseHandle(process.hThread);
        if (process.hProcess) CloseHandle(process.hProcess);
        process = {};
        owns_process = false;
    }

    bool waitReady(std::uint32_t timeout_ms) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            const auto v = httpRequest(port, L"GET", L"/json/version");
            if (!v.empty() && v.find("webSocketDebuggerUrl") != std::string::npos) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return false;
    }

    bool openSocket() {
        auto targets = httpRequest(port, L"GET", L"/json/list");
        std::fprintf(stderr, "[BrowserAuthority] /json/list -> %zu bytes\n", targets.size());
        if (targets.empty()) {
            httpRequest(port, L"PUT", L"/json/new?about:blank");
            targets = httpRequest(port, L"GET", L"/json/list");
            std::fprintf(stderr, "[BrowserAuthority] after /json/new -> %zu bytes\n", targets.size());
        }
        auto wsurl = jsonStringField(targets, "webSocketDebuggerUrl");
        if (!wsurl) {
            std::fprintf(stderr, "[BrowserAuthority] no webSocketDebuggerUrl in targets; head=%.180s\n", targets.c_str());
            return false;
        }

        URL_COMPONENTSW uc{}; uc.dwStructSize = sizeof(uc);
        std::wstring wurl = widen(*wsurl);
        // WinHttpCrackUrl does not recognize the ws:// scheme (error 12006).
        // Translate ws->http / wss->https; the SECURE flag is decided from the
        // ORIGINAL scheme before rewriting.
        bool secure = wurl.rfind(L"wss://", 0) == 0;
        std::wstring httpUrl = wurl;
        if (secure) {
            httpUrl = L"https://" + wurl.substr(6);
        } else if (wurl.rfind(L"ws://", 0) == 0) {
            httpUrl = L"http://" + wurl.substr(5);
        }
        wchar_t host[512]{}; wchar_t path[4096]{};
        uc.lpszHostName = host; uc.dwHostNameLength = static_cast<DWORD>(std::size(host));
        uc.lpszUrlPath = path; uc.dwUrlPathLength = static_cast<DWORD>(std::size(path));
        if (!WinHttpCrackUrl(httpUrl.c_str(), static_cast<DWORD>(httpUrl.size()), 0, &uc)) {
            std::fprintf(stderr, "[BrowserAuthority] WinHttpCrackUrl failed: %lu (url=%.200ls)\n", GetLastError(), httpUrl.c_str());
            return false;
        }

        InternetHandle session(WinHttpOpen(L"RawrXD-BrowserAuthority/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        if (!session) { std::fprintf(stderr, "[BrowserAuthority] WinHttpOpen failed: %lu\n", GetLastError()); return false; }
        InternetHandle connection(WinHttpConnect(session.h, std::wstring(host, uc.dwHostNameLength).c_str(), uc.nPort, 0));
        if (!connection) { std::fprintf(stderr, "[BrowserAuthority] WinHttpConnect failed: %lu\n", GetLastError()); return false; }
        // INTERNET_SCHEME_WSS is missing from some Windows 10/11 SDK revisions;
        // its stable value is 22 (winhttp.h). Use the numeric constant with a
        // local name so the TU compiles on SDKs that lack the macro.
#if !defined(INTERNET_SCHEME_WSS)
#define INTERNET_SCHEME_WSS ((INTERNET_SCHEME)22)
#endif
        DWORD flags = (uc.nScheme == INTERNET_SCHEME_WSS) ? WINHTTP_FLAG_SECURE : 0;
        InternetHandle request(WinHttpOpenRequest(connection.h, L"GET", std::wstring(path, uc.dwUrlPathLength).c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
        if (!request) return false;
        if (!WinHttpSetOption(request.h, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) { std::fprintf(stderr, "[BrowserAuthority] UPGRADE_TO_WEB_SOCKET failed: %lu\n", GetLastError()); return false; }
        if (!WinHttpSendRequest(request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) { std::fprintf(stderr, "[BrowserAuthority] SendRequest failed: %lu\n", GetLastError()); return false; }
        if (!WinHttpReceiveResponse(request.h, nullptr)) { std::fprintf(stderr, "[BrowserAuthority] ReceiveResponse failed: %lu (status=%lu)\n", GetLastError(), 0lu); return false; }
        ws = WinHttpWebSocketCompleteUpgrade(request.h, 0);
        if (!ws) { std::fprintf(stderr, "[BrowserAuthority] WebSocketCompleteUpgrade failed: %lu\n", GetLastError()); return false; }
        return true;
    }

    void recordEvent(const std::string& msg) {
        std::lock_guard<std::mutex> lock(event_mutex);
        if (msg.find("\"method\":\"Runtime.consoleAPICalled\"") != std::string::npos) {
            console_events.push_back(msg);
            if (console_events.size() > 256) console_events.erase(console_events.begin());
        }
        if (msg.find("\"method\":\"Network.loadingFailed\"") != std::string::npos) {
            network_failures.push_back(msg);
            if (network_failures.size() > 256) network_failures.erase(network_failures.begin());
        }
    }

    BrowserResult command(const std::string& method, const std::string& params, std::uint32_t timeout_ms) {
        std::lock_guard<std::mutex> lock(io_mutex);
        if (!ws) return {false, {}, "browser websocket not attached"};
        const auto id = next_id.fetch_add(1);
        std::string msg = "{\"id\":" + std::to_string(id) + ",\"method\":\"" + jsonEscape(method) + "\"";
        if (!params.empty()) msg += ",\"params\":" + params;
        msg += "}";
        DWORD rc = WinHttpWebSocketSend(ws, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                        const_cast<char*>(msg.data()), static_cast<DWORD>(msg.size()));
        if (rc != NO_ERROR) return {false, {}, "WinHttpWebSocketSend failed: " + std::to_string(rc)};

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        std::string assembled;
        while (std::chrono::steady_clock::now() < deadline) {
            char buffer[65536]; DWORD read = 0; WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
            rc = WinHttpWebSocketReceive(ws, buffer, sizeof(buffer), &read, &type);
            if (rc != NO_ERROR) return {false, {}, "WinHttpWebSocketReceive failed: " + std::to_string(rc)};
            if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) return {false, {}, "browser websocket closed"};
            assembled.append(buffer, buffer + read);
            if (type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE) continue;

            if (containsId(assembled, id)) {
                if (assembled.find("\"error\"") != std::string::npos) return {false, {}, assembled};
                return {true, assembled, {}};
            }
            recordEvent(assembled);
            assembled.clear();
        }
        return {false, {}, "browser command timed out: " + method};
    }
};

BrowserAuthority::BrowserAuthority() : impl_(new Impl) {}
BrowserAuthority::~BrowserAuthority() { delete impl_; }

bool BrowserAuthority::launch(std::uint16_t debugging_port, bool headless) {
    close();
    const std::wstring edge = findEdge();
    if (edge.empty()) return false;
    impl_->port = debugging_port;

    wchar_t temp[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, temp)) return false;
    std::wstring profile = std::wstring(temp) + L"RawrXD-Edge-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(debugging_port);
    CreateDirectoryW(profile.c_str(), nullptr);

    std::wostringstream cmd;
    cmd << L'"' << edge << L'"'
        << L" --remote-debugging-port=" << debugging_port
        << L" --user-data-dir=\"" << profile << L"\""
        << L" --no-first-run --no-default-browser-check --disable-features=TranslateUI";
    if (headless) cmd << L" --headless=new --disable-gpu";
    cmd << L" about:blank";
    std::wstring command = cmd.str();

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(edge.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &si, &pi)) {
        std::fprintf(stderr, "[BrowserAuthority] CreateProcessW failed: %lu\n", GetLastError());
        return false;
    }
    impl_->process = pi; impl_->owns_process = true;
    if (!impl_->waitReady(15000)) {
        std::fprintf(stderr, "[BrowserAuthority] waitReady timeout (port=%u, CDP /json/version never answered)\n", impl_->port);
        close(); return false;
    }
    if (!impl_->openSocket()) {
        std::fprintf(stderr, "[BrowserAuthority] openSocket failed (targets list empty or no webSocketDebuggerUrl)\n");
        close(); return false;
    }
    impl_->command("Page.enable", "{}", 3000);
    impl_->command("Runtime.enable", "{}", 3000);
    impl_->command("Network.enable", "{}", 3000);
    return true;
}

bool BrowserAuthority::attach(std::uint16_t debugging_port) {
    close();
    impl_->port = debugging_port;
    if (!impl_->waitReady(3000)) return false;
    if (!impl_->openSocket()) return false;
    impl_->command("Page.enable", "{}", 3000);
    impl_->command("Runtime.enable", "{}", 3000);
    impl_->command("Network.enable", "{}", 3000);
    return true;
}

void BrowserAuthority::close() { impl_->shutdown(); }

BrowserResult BrowserAuthority::navigate(const std::string& url, std::uint32_t timeout_ms) {
    auto r = impl_->command("Page.navigate", "{\"url\":\"" + jsonEscape(url) + "\"}", timeout_ms);
    if (!r.ok) return r;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto ready = evaluate("document.readyState", 2000);
        if (ready.ok && (ready.value == "complete" || ready.value == "interactive")) return {true, ready.value, {}};
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return {false, {}, "navigation did not reach interactive/complete state"};
}

BrowserResult BrowserAuthority::evaluate(const std::string& javascript, std::uint32_t timeout_ms) {
    const std::string params = "{\"expression\":\"" + jsonEscape(javascript) + "\",\"returnByValue\":true,\"awaitPromise\":true}";
    auto r = impl_->command("Runtime.evaluate", params, timeout_ms);
    if (!r.ok) return r;
    auto v = runtimeValue(r.value);
    return {true, v.value_or(r.value), {}};
}

BrowserResult BrowserAuthority::queryText(const std::string& selector) {
    const std::string js = "(()=>{const e=document.querySelector(\"" + jsonEscape(selector) + "\");return e?(e.innerText??e.textContent??\"\"):null})()";
    return evaluate(js);
}

BrowserResult BrowserAuthority::click(const std::string& selector) {
    const std::string js = "(()=>{const e=document.querySelector(\"" + jsonEscape(selector) + "\");if(!e)return false;e.scrollIntoView({block:'center'});e.click();return true})()";
    return evaluate(js);
}

BrowserResult BrowserAuthority::type(const std::string& selector, const std::string& text, bool clear_first) {
    const std::string js = "(()=>{const e=document.querySelector(\"" + jsonEscape(selector) + "\");if(!e)return false;e.focus();"
                           + std::string(clear_first ? "e.value='';" : "")
                           + "e.value" + (clear_first ? "=" : "+=") + "\"" + jsonEscape(text) + "\";"
                           + "e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return true})()";
    return evaluate(js);
}

BrowserResult BrowserAuthority::screenshot(const std::string& png_path) {
    auto r = impl_->command("Page.captureScreenshot", "{\"format\":\"png\",\"captureBeyondViewport\":true}", 15000);
    if (!r.ok) return r;
    auto data = jsonStringField(r.value, "data");
    if (!data) return {false, {}, "captureScreenshot response missing data"};
    auto bytes = decodeBase64(*data);
    if (bytes.empty()) return {false, {}, "captureScreenshot produced empty PNG"};
    std::filesystem::path p(png_path);
    if (p.has_parent_path()) { std::error_code ec; std::filesystem::create_directories(p.parent_path(), ec); }
    std::ofstream out(p, std::ios::binary);
    if (!out) return {false, {}, "cannot open screenshot path"};
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out) return {false, {}, "failed writing screenshot"};
    return {true, png_path, {}};
}

std::vector<std::string> BrowserAuthority::takeConsoleEvents() {
    std::lock_guard<std::mutex> lock(impl_->event_mutex);
    auto out = std::move(impl_->console_events); impl_->console_events.clear(); return out;
}

std::vector<std::string> BrowserAuthority::takeNetworkFailures() {
    std::lock_guard<std::mutex> lock(impl_->event_mutex);
    auto out = std::move(impl_->network_failures); impl_->network_failures.clear(); return out;
}

} // namespace rawrxd::value
#endif
