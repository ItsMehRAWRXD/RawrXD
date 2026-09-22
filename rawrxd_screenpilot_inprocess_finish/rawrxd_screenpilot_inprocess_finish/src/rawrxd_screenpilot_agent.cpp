#include "rawrxd_screenpilot_agent.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace fs = std::filesystem;

namespace {

struct State {
    RawrXD_SP_ConfigV1 config{};
    RawrXD_SP_AuthorityV1 authority{};
    fs::path workspace_root;
    std::string session;
    std::atomic_bool initialized{false};
    std::mutex jobs_mutex;
    std::map<std::string, std::shared_ptr<std::atomic_bool>> jobs;
};

State g;

std::string sv(RawrXD_SP_String s) {
    if (!s.data || !s.size) return {};
    return std::string(s.data, s.size);
}

RawrXD_SP_String rs(const std::string& s) {
    return RawrXD_SP_String{s.data(), s.size()};
}

std::string lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string narrow(std::wstring_view s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string json_escape(std::string_view s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (c < 0x20) {
                    o << "\\u" << std::hex << std::setw(4)
                      << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << static_cast<char>(c);
                }
        }
    }
    return o.str();
}

std::string random_token(std::size_t bytes = 32) {
    std::vector<unsigned char> b(bytes);
    if (BCryptGenRandom(nullptr, b.data(), static_cast<ULONG>(b.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return {};
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (auto v : b) {
        out.push_back(hex[v >> 4]);
        out.push_back(hex[v & 15]);
    }
    return out;
}

bool constant_time_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

bool exact_local_host(std::string host, std::uint16_t port) {
    host = lower_ascii(trim(std::move(host)));
    const std::string p = std::to_string(port);
    return host == "127.0.0.1:" + p ||
           host == "localhost:" + p ||
           host == "[::1]:" + p;
}

bool allowed_origin(std::string origin) {
    origin = lower_ascii(trim(std::move(origin)));
    if (origin.empty()) return true; // non-browser/local harness
    if (origin == "null") return g.config.allow_null_origin != 0;

    const std::string port = std::to_string(g.config.port);
    return origin == "http://127.0.0.1:" + port ||
           origin == "http://localhost:" + port ||
           origin == "http://[::1]:" + port;
}

std::optional<std::string> json_string(std::string_view json, std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\"";
    std::size_t p = json.find(needle);
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
                if (value <= 0x7F) {
                    out.push_back(static_cast<char>(value));
                } else {
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

bool valid_mode(std::string_view m) {
    return m == "ask" || m == "plan" || m == "build" || m == "agent";
}

bool valid_model(std::string_view s) {
    if (s.empty() || s.size() > 512) return false;
    for (unsigned char c : s) {
        if (std::isalnum(c)) continue;
        switch (c) {
            case '.': case '_': case '-': case ':':
            case '/': case '\\': case '@': case '+':
                continue;
            default:
                return false;
        }
    }
    return true;
}

std::wstring lower_w(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c){ return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

bool path_is_under(const fs::path& root, const fs::path& child) {
    auto r = root.lexically_normal();
    auto c = child.lexically_normal();

    auto ri = r.begin();
    auto ci = c.begin();
    for (; ri != r.end(); ++ri, ++ci) {
        if (ci == c.end()) return false;
        if (lower_w(ri->wstring()) != lower_w(ci->wstring())) return false;
    }
    return true;
}

std::optional<fs::path> validate_workspace(std::string_view utf8) {
    try {
        const fs::path requested = fs::weakly_canonical(fs::path(widen(utf8)));
        const fs::path root = fs::weakly_canonical(g.workspace_root);
        if (!fs::exists(requested) || !fs::is_directory(requested)) return std::nullopt;
        if (!path_is_under(root, requested)) return std::nullopt;
        return requested;
    } catch (...) {
        return std::nullopt;
    }
}

int header(const RawrXD_SP_HttpSinkV1* sink, const char* k, const char* v) {
    return sink->header ? sink->header(sink->user, k, v) : 1;
}

int begin(const RawrXD_SP_HttpSinkV1* sink, int code, const char* type, int chunked) {
    if (!sink || !sink->begin || !sink->write || !sink->end) return 0;
    header(sink, "Cache-Control", "no-store");
    header(sink, "X-Content-Type-Options", "nosniff");
    header(sink, "Referrer-Policy", "no-referrer");
    return sink->begin(sink->user, code, type, chunked);
}

int write_text(const RawrXD_SP_HttpSinkV1* sink, std::string_view text) {
    return sink->write(sink->user, text.data(), text.size());
}

int json_reply(const RawrXD_SP_HttpSinkV1* sink, int code, std::string_view body) {
    if (!begin(sink, code, "application/json; charset=utf-8", 0)) return 0;
    if (!write_text(sink, body)) return 0;
    return sink->end(sink->user);
}

struct EmitCtx {
    const RawrXD_SP_HttpSinkV1* sink{};
    std::string request_id;
};

int emit_ndjson(void* p, const char* type, const char* data, std::size_t n) {
    auto* ctx = static_cast<EmitCtx*>(p);
    if (!ctx || !ctx->sink) return 0;
    std::string_view d(data ? data : "", data ? n : 0);
    const std::string line =
        "{\"type\":\"" + json_escape(type ? type : "output") +
        "\",\"requestId\":\"" + json_escape(ctx->request_id) +
        "\",\"data\":\"" + json_escape(d) + "\"}\n";
    return write_text(ctx->sink, line);
}

int is_cancelled(void* p) {
    auto* flag = static_cast<std::atomic_bool*>(p);
    return flag && flag->load(std::memory_order_acquire) ? 1 : 0;
}

std::string mode_policy(std::string_view mode) {
    if (mode == "ask")
        return "ASK: inspect and answer; do not mutate unless explicitly requested.";
    if (mode == "plan")
        return "PLAN: inspect as needed and return a concrete plan; no source mutation.";
    if (mode == "build")
        return "BUILD: edits/build/tests are allowed inside the validated workspace through Tool Authority.";
    return "AGENT: autonomous inspect/edit/build/test loop inside the validated workspace through Tool Authority.";
}

} // namespace

extern "C" {

int RawrXD_ScreenPilot_Initialize(
    const RawrXD_SP_ConfigV1* config,
    const RawrXD_SP_AuthorityV1* authority
) {
    if (!config || !authority) return 0;
    if (config->abi_version != RAWRXD_SCREENPILOT_ABI_V1) return 0;
    if (authority->abi_version != RAWRXD_SCREENPILOT_ABI_V1) return 0;
    if (!authority->run_agent) return 0;
    if (!config->port) return 0;

    const std::string root = sv(config->workspace_root);
    if (root.empty()) return 0;

    try {
        g.workspace_root = fs::weakly_canonical(fs::path(widen(root)));
        if (!fs::exists(g.workspace_root) || !fs::is_directory(g.workspace_root)) return 0;
    } catch (...) {
        return 0;
    }

    g.config = *config;
    g.authority = *authority;
    g.session = random_token();
    if (g.session.empty()) return 0;

    g.initialized.store(true, std::memory_order_release);
    return 1;
}

void RawrXD_ScreenPilot_Shutdown() {
    g.initialized.store(false, std::memory_order_release);
    std::scoped_lock lock(g.jobs_mutex);
    for (auto& [_, flag] : g.jobs) {
        if (flag) flag->store(true, std::memory_order_release);
    }
    g.jobs.clear();
    g.session.clear();
}

int RawrXD_ScreenPilot_HandleHttp(
    const RawrXD_SP_HttpRequestV1* request,
    const RawrXD_SP_HttpSinkV1* sink
) {
    if (!g.initialized.load(std::memory_order_acquire) || !request || !sink) return 0;

    const std::string method = lower_ascii(sv(request->method));
    const std::string path = sv(request->path);

    const bool ours =
        path == "/api/v1/screenpilot/health" ||
        path == "/api/v1/screenpilot/session" ||
        path == "/api/v1/screenpilot/capabilities" ||
        path == "/api/v1/screenpilot/agent/run" ||
        path == "/api/v1/screenpilot/agent/cancel";

    if (!ours) return 0;

    if (!exact_local_host(sv(request->host), g.config.port)) {
        json_reply(sink, 403, R"({"ok":false,"error":"host rejected"})");
        return 1;
    }
    if (!allowed_origin(sv(request->origin))) {
        json_reply(sink, 403, R"({"ok":false,"error":"origin rejected"})");
        return 1;
    }

    if (method == "get" && path == "/api/v1/screenpilot/health") {
        const std::string body =
            "{\"ok\":true,\"service\":\"RawrXD ScreenPilot\","
            "\"transport\":\"in-process\",\"authority\":\"canonical\","
            "\"workspaceRoot\":\"" + json_escape(narrow(g.workspace_root.wstring())) + "\"}";
        json_reply(sink, 200, body);
        return 1;
    }

    if (method == "post" && path == "/api/v1/screenpilot/session") {
        const std::string body =
            "{\"ok\":true,\"token\":\"" + g.session + "\"}";
        json_reply(sink, 200, body);
        return 1;
    }

    if (!constant_time_equal(sv(request->session_token), g.session)) {
        json_reply(sink, 401, R"({"ok":false,"error":"invalid session"})");
        return 1;
    }

    if (method == "get" && path == "/api/v1/screenpilot/capabilities") {
        json_reply(sink, 200,
            R"({"ok":true,"modes":["ask","plan","build","agent"],"streaming":true,"cancel":true,"toolAuthority":true,"transport":"in-process"})");
        return 1;
    }

    if (method == "post" && path == "/api/v1/screenpilot/agent/cancel") {
        auto id = json_string(sv(request->body), "requestId");
        if (!id || id->empty()) {
            json_reply(sink, 400, R"({"ok":false,"error":"requestId required"})");
            return 1;
        }

        bool found = false;
        {
            std::scoped_lock lock(g.jobs_mutex);
            auto it = g.jobs.find(*id);
            if (it != g.jobs.end() && it->second) {
                it->second->store(true, std::memory_order_release);
                found = true;
            }
        }
        json_reply(sink, 200, found
            ? R"({"ok":true,"cancelled":true})"
            : R"({"ok":true,"cancelled":false})");
        return 1;
    }

    if (method == "post" && path == "/api/v1/screenpilot/agent/run") {
        const std::string body = sv(request->body);
        auto id = json_string(body, "requestId");
        auto mode = json_string(body, "mode");
        auto model = json_string(body, "model");
        auto workspace = json_string(body, "workspace");
        auto prompt = json_string(body, "prompt");

        if (!id || id->empty() || id->size() > 128 ||
            !mode || !model || !workspace || !prompt || prompt->empty()) {
            json_reply(sink, 400, R"({"ok":false,"error":"requestId, mode, model, workspace, prompt required"})");
            return 1;
        }

        *mode = lower_ascii(*mode);
        if (!valid_mode(*mode)) {
            json_reply(sink, 400, R"({"ok":false,"error":"invalid mode"})");
            return 1;
        }
        if (!valid_model(*model)) {
            json_reply(sink, 400, R"({"ok":false,"error":"invalid model"})");
            return 1;
        }

        auto canonical = validate_workspace(*workspace);
        if (!canonical) {
            json_reply(sink, 403, R"({"ok":false,"error":"workspace outside configured root or missing"})");
            return 1;
        }

        auto cancel = std::make_shared<std::atomic_bool>(false);
        {
            std::scoped_lock lock(g.jobs_mutex);
            if (g.jobs.contains(*id)) {
                json_reply(sink, 409, R"({"ok":false,"error":"duplicate requestId"})");
                return 1;
            }
            g.jobs.emplace(*id, cancel);
        }

        if (!begin(sink, 200, "application/x-ndjson; charset=utf-8", 1)) {
            std::scoped_lock lock(g.jobs_mutex);
            g.jobs.erase(*id);
            return 1;
        }

        EmitCtx emit_ctx{sink, *id};
        const std::string policy = mode_policy(*mode);
        emit_ndjson(&emit_ctx, "started", policy.data(), policy.size());

        const std::string canonical_utf8 = narrow(canonical->wstring());
        RawrXD_SP_AgentRequestV1 ar{
            rs(*id), rs(*mode), rs(*model), rs(canonical_utf8), rs(*prompt)
        };

        const int rc = g.authority.run_agent(
            g.authority.user,
            &ar,
            emit_ndjson,
            &emit_ctx,
            is_cancelled,
            cancel.get()
        );

        {
            std::scoped_lock lock(g.jobs_mutex);
            g.jobs.erase(*id);
        }

        const std::string exit_data = std::to_string(rc);
        emit_ndjson(&emit_ctx, "exit", exit_data.data(), exit_data.size());
        sink->end(sink->user);
        return 1;
    }

    json_reply(sink, 405, R"({"ok":false,"error":"method not allowed"})");
    return 1;
}

} // extern "C"
