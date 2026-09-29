// Deep2 Serverless AI Gateway
// Source-only C++20, no third-party libraries.
// Provides:
//   GET  /health
//   POST /v1/chat/completions
//   POST /jobs
//   GET  /jobs/{id}
// Deep2 remains the inference engine through its local OpenAI-compatible server.
// Default upstream: 127.0.0.1:11436
// Default gateway:  127.0.0.1:11437

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socket_t = SOCKET;
  static constexpr socket_t invalid_socket_v = INVALID_SOCKET;
  static void close_socket(socket_t s) { if (s != INVALID_SOCKET) closesocket(s); }
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
  using socket_t = int;
  static constexpr socket_t invalid_socket_v = -1;
  static void close_socket(socket_t s) { if (s >= 0) ::close(s); }
#endif

namespace fs = std::filesystem;

struct Config {
    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 11437;
    std::string upstream_host = "127.0.0.1";
    uint16_t upstream_port = 11436;
    std::string api_key;
    fs::path state_dir = ".deep2_serverless";
    int workers = 2;
    size_t max_request_bytes = 2 * 1024 * 1024;
    int upstream_timeout_seconds = 780;
};

static std::string getenv_s(const char* name, const std::string& fallback = {}) {
    const char* p = std::getenv(name);
    return p ? std::string(p) : fallback;
}

static int getenv_i(const char* name, int fallback) {
    auto s = getenv_s(name);
    if (s.empty()) return fallback;
    try { return std::stoi(s); } catch (...) { return fallback; }
}

static Config load_config() {
    Config c;
    c.listen_host = getenv_s("DEEP2_SERVERLESS_HOST", c.listen_host);
    c.listen_port = static_cast<uint16_t>(getenv_i("DEEP2_SERVERLESS_PORT", c.listen_port));
    c.upstream_host = getenv_s("DEEP2_UPSTREAM_HOST", c.upstream_host);
    c.upstream_port = static_cast<uint16_t>(getenv_i("DEEP2_UPSTREAM_PORT", c.upstream_port));
    c.api_key = getenv_s("DEEP2_SERVERLESS_API_KEY");
    c.state_dir = getenv_s("DEEP2_SERVERLESS_STATE", c.state_dir.string());
    c.workers = std::max(1, getenv_i("DEEP2_SERVERLESS_WORKERS", c.workers));
    c.upstream_timeout_seconds = std::max(5, getenv_i("DEEP2_UPSTREAM_TIMEOUT", c.upstream_timeout_seconds));
    return c;
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch){ return static_cast<char>(std::tolower(ch)); });
    return s;
}

static std::string trim(std::string s) {
    auto not_space = [](unsigned char c){ return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

static std::string json_escape(const std::string& s) {
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
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << int(c) << std::dec;
                } else {
                    o << static_cast<char>(c);
                }
        }
    }
    return o.str();
}

static bool atomic_write(const fs::path& path, const std::string& data) {
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    auto tmp = path;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(data.data(), static_cast<std::streamsize>(data.size()));
        f.flush();
        if (!f) return false;
    }
    fs::rename(tmp, path, ec);
    if (!ec) return true;
    fs::remove(path, ec);
    ec.clear();
    fs::rename(tmp, path, ec);
    return !ec;
}

static std::string read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string now_iso8601() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto tt = system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static std::string make_job_id() {
    static std::mutex m;
    static std::mt19937_64 rng{std::random_device{}()};
    std::lock_guard<std::mutex> lock(m);
    uint64_t r = rng();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::ostringstream ss;
    ss << std::hex << ms << "-" << r;
    return ss.str();
}

struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    int status = 200;
    std::string reason = "OK";
    std::string content_type = "application/json";
    std::string body;
    std::map<std::string, std::string> headers;

    HttpResponse() = default;
    HttpResponse(int s, std::string r, std::string ct, std::string b)
        : status(s), reason(std::move(r)), content_type(std::move(ct)), body(std::move(b)) {}
};

static std::string serialize_response(const HttpResponse& r) {
    std::ostringstream ss;
    ss << "HTTP/1.1 " << r.status << " " << r.reason << "\r\n";
    ss << "Content-Type: " << r.content_type << "\r\n";
    ss << "Content-Length: " << r.body.size() << "\r\n";
    ss << "Connection: close\r\n";
    ss << "Cache-Control: no-store\r\n";
    for (auto& [k, v] : r.headers) ss << k << ": " << v << "\r\n";
    ss << "\r\n";
    ss << r.body;
    return ss.str();
}

static bool send_all(socket_t s, const char* data, size_t n) {
    size_t off = 0;
    while (off < n) {
#ifdef _WIN32
        int sent = ::send(s, data + off, static_cast<int>(std::min<size_t>(n - off, 1 << 20)), 0);
#else
        ssize_t sent = ::send(s, data + off, n - off, 0);
#endif
        if (sent <= 0) return false;
        off += static_cast<size_t>(sent);
    }
    return true;
}

static bool recv_until(socket_t s, std::string& data, const std::string& marker, size_t max_bytes) {
    char buf[8192];
    while (data.find(marker) == std::string::npos) {
        if (data.size() >= max_bytes) return false;
#ifdef _WIN32
        int n = ::recv(s, buf, sizeof(buf), 0);
#else
        ssize_t n = ::recv(s, buf, sizeof(buf), 0);
#endif
        if (n <= 0) return false;
        data.append(buf, static_cast<size_t>(n));
    }
    return true;
}

static bool parse_http_request(socket_t s, HttpRequest& out, size_t max_bytes) {
    std::string raw;
    if (!recv_until(s, raw, "\r\n\r\n", max_bytes)) return false;
    auto split = raw.find("\r\n\r\n");
    std::string header_blob = raw.substr(0, split);
    std::string body = raw.substr(split + 4);

    std::istringstream hs(header_blob);
    std::string line;
    if (!std::getline(hs, line)) return false;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    {
        std::istringstream rl(line);
        if (!(rl >> out.method >> out.path >> out.version)) return false;
    }

    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        out.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
    }

    size_t content_length = 0;
    auto it = out.headers.find("content-length");
    if (it != out.headers.end()) {
        try { content_length = static_cast<size_t>(std::stoull(it->second)); }
        catch (...) { return false; }
    }
    if (content_length > max_bytes) return false;

    while (body.size() < content_length) {
        char buf[8192];
#ifdef _WIN32
        int n = ::recv(s, buf, static_cast<int>(std::min<size_t>(sizeof(buf), content_length - body.size())), 0);
#else
        ssize_t n = ::recv(s, buf, std::min<size_t>(sizeof(buf), content_length - body.size()), 0);
#endif
        if (n <= 0) return false;
        body.append(buf, static_cast<size_t>(n));
    }
    if (body.size() > content_length) body.resize(content_length);
    out.body = std::move(body);
    return true;
}

static socket_t connect_tcp(const std::string& host, uint16_t port, int timeout_seconds) {
    socket_t s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == invalid_socket_v) return invalid_socket_v;

#ifdef _WIN32
    DWORD ms = static_cast<DWORD>(timeout_seconds * 1000);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
#else
    timeval tv{timeout_seconds, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close_socket(s);
        return invalid_socket_v;
    }
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(s);
        return invalid_socket_v;
    }
    return s;
}

struct UpstreamReply {
    int status = 0;
    std::string body;
    std::string error;
};

static UpstreamReply upstream_request(
    const Config& cfg,
    const std::string& method,
    const std::string& path,
    const std::string& body,
    int timeout_seconds
) {
    UpstreamReply out;
    socket_t s = connect_tcp(cfg.upstream_host, cfg.upstream_port, timeout_seconds);
    if (s == invalid_socket_v) {
        out.error = "connect_failed";
        return out;
    }

    std::ostringstream rq;
    rq << method << " " << path << " HTTP/1.1\r\n";
    rq << "Host: " << cfg.upstream_host << ":" << cfg.upstream_port << "\r\n";
    rq << "Accept: application/json\r\n";
    if (!body.empty()) rq << "Content-Type: application/json\r\n";
    rq << "Content-Length: " << body.size() << "\r\n";
    rq << "Connection: close\r\n\r\n";
    rq << body;
    auto wire = rq.str();

    if (!send_all(s, wire.data(), wire.size())) {
        close_socket(s);
        out.error = "send_failed";
        return out;
    }

    std::string raw;
    char buf[8192];
    for (;;) {
#ifdef _WIN32
        int n = ::recv(s, buf, sizeof(buf), 0);
#else
        ssize_t n = ::recv(s, buf, sizeof(buf), 0);
#endif
        if (n == 0) break;
        if (n < 0) break;
        raw.append(buf, static_cast<size_t>(n));
        if (raw.size() > 16 * 1024 * 1024) {
            out.error = "upstream_response_too_large";
            break;
        }
    }
    close_socket(s);

    auto h = raw.find("\r\n\r\n");
    if (h == std::string::npos) {
        if (out.error.empty()) out.error = "malformed_upstream_response";
        return out;
    }

    std::string head = raw.substr(0, h);
    std::istringstream hs(head);
    std::string version;
    hs >> version >> out.status;
    out.body = raw.substr(h + 4);
    return out;
}

class JobStore {
public:
    explicit JobStore(fs::path root) : root_(std::move(root)) {
        std::error_code ec;
        fs::create_directories(root_, ec);
    }

    bool create(const std::string& id, const std::string& request) {
        fs::path dir = root_ / id;
        std::error_code ec;
        fs::create_directories(dir, ec);
        if (ec) return false;
        if (!atomic_write(dir / "request.json", request)) return false;
        return set_status(id, "queued");
    }

    bool set_status(const std::string& id, const std::string& status) {
        return atomic_write(root_ / id / "status.txt", status + "\n" + now_iso8601() + "\n");
    }

    bool set_result(const std::string& id, int http_status, const std::string& body) {
        std::ostringstream meta;
        meta << http_status << "\n" << now_iso8601() << "\n";
        if (!atomic_write(root_ / id / "result.meta", meta.str())) return false;
        return atomic_write(root_ / id / "result.json", body);
    }

    bool set_error(const std::string& id, const std::string& error) {
        return atomic_write(root_ / id / "error.txt", error);
    }

    bool exists(const std::string& id) const {
        return fs::is_directory(root_ / id);
    }

    std::string request(const std::string& id) const {
        return read_file(root_ / id / "request.json");
    }

    std::string status(const std::string& id) const {
        auto x = read_file(root_ / id / "status.txt");
        auto p = x.find('\n');
        return trim(p == std::string::npos ? x : x.substr(0, p));
    }

    std::string result(const std::string& id) const {
        return read_file(root_ / id / "result.json");
    }

    std::string error(const std::string& id) const {
        return read_file(root_ / id / "error.txt");
    }

    int result_http_status(const std::string& id) const {
        auto x = read_file(root_ / id / "result.meta");
        auto p = x.find('\n');
        try { return std::stoi(p == std::string::npos ? x : x.substr(0, p)); }
        catch (...) { return 0; }
    }

    std::vector<std::string> queued_jobs() const {
        std::vector<std::string> ids;
        std::error_code ec;
        if (!fs::exists(root_, ec)) return ids;
        for (auto& e : fs::directory_iterator(root_, ec)) {
            if (!e.is_directory()) continue;
            auto id = e.path().filename().string();
            auto st = status(id);
            if (st == "queued" || st == "running") {
                ids.push_back(id);
            }
        }
        return ids;
    }

private:
    fs::path root_;
};

class JobQueue {
public:
    void push(std::string id) {
        {
            std::lock_guard<std::mutex> lock(m_);
            q_.push_back(std::move(id));
        }
        cv_.notify_one();
    }

    bool pop(std::string& id) {
        std::unique_lock<std::mutex> lock(m_);
        cv_.wait(lock, [&]{ return stop_ || !q_.empty(); });
        if (stop_ && q_.empty()) return false;
        id = std::move(q_.front());
        q_.pop_front();
        return true;
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(m_);
            stop_ = true;
        }
        cv_.notify_all();
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<std::string> q_;
    bool stop_ = false;
};

class Deep2Serverless {
public:
    explicit Deep2Serverless(Config cfg)
        : cfg_(std::move(cfg)),
          store_(cfg_.state_dir / "jobs") {}

    int run() {
#ifdef _WIN32
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "WSAStartup failed\n";
            return 2;
        }
#endif

        for (const auto& id : store_.queued_jobs()) {
            store_.set_status(id, "queued");
            queue_.push(id);
        }

        for (int i = 0; i < cfg_.workers; ++i) {
            workers_.emplace_back([this, i]{ worker_loop(i); });
        }

        socket_t listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == invalid_socket_v) {
            std::cerr << "socket() failed\n";
            return 3;
        }

        int yes = 1;
#ifdef _WIN32
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
#else
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(cfg_.listen_port);
        if (inet_pton(AF_INET, cfg_.listen_host.c_str(), &addr.sin_addr) != 1) {
            std::cerr << "listen host must be an IPv4 address\n";
            close_socket(listener);
            return 4;
        }

        if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            std::cerr << "bind failed on " << cfg_.listen_host << ":" << cfg_.listen_port << "\n";
            close_socket(listener);
            return 5;
        }
        if (::listen(listener, 64) != 0) {
            std::cerr << "listen failed\n";
            close_socket(listener);
            return 6;
        }

        std::cout
            << "GATE=DEEP2_SERVERLESS_AI_001\n"
            << "LISTEN=http://" << cfg_.listen_host << ":" << cfg_.listen_port << "\n"
            << "UPSTREAM=http://" << cfg_.upstream_host << ":" << cfg_.upstream_port << "\n"
            << "WORKERS=" << cfg_.workers << "\n"
            << "STATE=" << fs::absolute(cfg_.state_dir).string() << "\n"
            << "OLLAMA_USED=0\n"
            << "CLOUD_MODEL_USED=0\n"
            << "SERVER_READY=PASS\n"
            << std::flush;

        for (;;) {
            sockaddr_in peer{};
#ifdef _WIN32
            int plen = sizeof(peer);
#else
            socklen_t plen = sizeof(peer);
#endif
            socket_t client = ::accept(listener, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (client == invalid_socket_v) continue;
            std::thread([this, client]{
                handle_client(client);
                close_socket(client);
            }).detach();
        }

        return 0;
    }

private:
    bool auth_ok(const HttpRequest& req) const {
        if (cfg_.api_key.empty()) return true;
        auto it = req.headers.find("x-deep2-key");
        return it != req.headers.end() && it->second == cfg_.api_key;
    }

    void handle_client(socket_t s) {
        HttpRequest req;
        if (!parse_http_request(s, req, cfg_.max_request_bytes)) {
            HttpResponse r{400, "Bad Request", "application/json", R"({"error":"bad request"})"};
            auto wire = serialize_response(r);
            send_all(s, wire.data(), wire.size());
            return;
        }

        HttpResponse r = route(req);
        auto wire = serialize_response(r);
        send_all(s, wire.data(), wire.size());
    }

    HttpResponse route(const HttpRequest& req) {
        if (req.method == "GET" && req.path == "/health") {
            auto up = upstream_request(cfg_, "GET", "/health", "", 3);
            bool alive = (up.status > 0);
            std::ostringstream b;
            b << "{"
              << "\"serverless_gateway\":\"ok\","
              << "\"deep2_upstream_reachable\":" << (alive ? "true" : "false") << ","
              << "\"deep2_upstream_status\":" << up.status << ","
              << "\"ollama_used\":0,"
              << "\"cloud_model_used\":0"
              << "}";
            return {alive ? 200 : 503, alive ? "OK" : "Service Unavailable", "application/json", b.str()};
        }

        if (!auth_ok(req)) {
            return {401, "Unauthorized", "application/json", R"({"error":"unauthorized"})"};
        }

        if (req.method == "POST" && req.path == "/v1/chat/completions") {
            auto body_lower = lower(req.body);
            if (body_lower.find("\"stream\"") != std::string::npos &&
                body_lower.find("\"stream\":true") != std::string::npos) {
                return {400, "Bad Request", "application/json",
                    R"({"error":{"message":"Buffered Deep2 serverless route requires stream=false. Use POST /jobs for long generations."}})"};
            }
            auto up = upstream_request(
                cfg_, "POST", "/v1/chat/completions", req.body, cfg_.upstream_timeout_seconds);
            if (up.status == 0) {
                return {502, "Bad Gateway", "application/json",
                    std::string("{\"error\":\"") + json_escape(up.error) + "\"}"};
            }
            return {up.status, up.status >= 200 && up.status < 300 ? "OK" : "Upstream Error",
                    "application/json", up.body};
        }

        if (req.method == "POST" && req.path == "/jobs") {
            if (req.body.empty()) {
                return {400, "Bad Request", "application/json", R"({"error":"empty request"})"};
            }
            std::string id = make_job_id();
            if (!store_.create(id, req.body)) {
                return {500, "Internal Server Error", "application/json", R"({"error":"failed to persist job"})"};
            }
            queue_.push(id);
            std::ostringstream b;
            b << "{\"job_id\":\"" << json_escape(id)
              << "\",\"status\":\"queued\",\"status_url\":\"/jobs/"
              << json_escape(id) << "\"}";
            return {202, "Accepted", "application/json", b.str()};
        }

        const std::string prefix = "/jobs/";
        if (req.method == "GET" && req.path.rfind(prefix, 0) == 0) {
            std::string id = req.path.substr(prefix.size());
            if (id.empty() || id.find('/') != std::string::npos || id.find("..") != std::string::npos) {
                return {400, "Bad Request", "application/json", R"({"error":"invalid job id"})"};
            }
            if (!store_.exists(id)) {
                return {404, "Not Found", "application/json", R"({"error":"job not found"})"};
            }
            auto status = store_.status(id);
            auto result = store_.result(id);
            auto error = store_.error(id);
            std::ostringstream b;
            b << "{\"job_id\":\"" << json_escape(id)
              << "\",\"status\":\"" << json_escape(status) << "\"";
            if (!result.empty()) {
                b << ",\"upstream_http_status\":" << store_.result_http_status(id)
                  << ",\"result\":" << result;
            }
            if (!error.empty()) {
                b << ",\"error\":\"" << json_escape(error) << "\"";
            }
            b << "}";
            return {200, "OK", "application/json", b.str()};
        }

        return {404, "Not Found", "application/json", R"({"error":"route not found"})"};
    }

    void worker_loop(int worker_index) {
        std::string id;
        while (queue_.pop(id)) {
            auto request = store_.request(id);
            if (request.empty()) {
                store_.set_error(id, "missing request body");
                store_.set_status(id, "failed");
                continue;
            }

            store_.set_status(id, "running");
            auto up = upstream_request(
                cfg_, "POST", "/v1/chat/completions", request, cfg_.upstream_timeout_seconds);

            if (up.status == 0) {
                store_.set_error(id, up.error);
                store_.set_status(id, "failed");
                continue;
            }

            store_.set_result(id, up.status, up.body);
            if (up.status >= 200 && up.status < 300) {
                store_.set_status(id, "completed");
            } else {
                store_.set_error(id, "Deep2 upstream returned HTTP " + std::to_string(up.status));
                store_.set_status(id, "failed");
            }

            std::cout << "JOB_DONE id=" << id
                      << " worker=" << worker_index
                      << " upstream_status=" << up.status
                      << " status=" << store_.status(id) << "\n"
                      << std::flush;
        }
    }

    Config cfg_;
    JobStore store_;
    JobQueue queue_;
    std::vector<std::thread> workers_;
};

int main() {
    auto cfg = load_config();
    Deep2Serverless app(std::move(cfg));
    return app.run();
}
