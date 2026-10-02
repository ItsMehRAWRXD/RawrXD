// RAWRXD_BEACON_MODEL_SERVER_002
//
// Loadless model serving over HTTP. The server NEVER materialises a model: it
// holds one read-only mapping and answers byte-range requests from it, so the
// working set is the request window, not the 10.36 GB file.
//
// Beaconism: the minimum surface that makes the property observable.
//
//   GET /v1/models
//   GET /health
//   GET /models/{id}/manifest[?hash=1]
//   GET /models/{id}/blob?off=&len=
//   GET /models/{id}/verify?tensor={name}      -> FNV-1a64 of a tensor's bytes
//
// Manifest carries what a streaming client needs and should not have to derive:
// absolute offset, byte extent, element count, shape, ggml type, the type's
// block geometry, FNV-1a64 (on demand), and layer/expert/role parsed out of the
// tensor name so a MoE router never has to re-parse names at runtime.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

#include "deep2/GGUFLoader.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

static const char* VERSION = "RAWRXD_BEACON_MODEL_SERVER_002";
static const std::size_t WINDOW = 512u * 1024;   // 0.50 MiB

// ------------------------------------------------------- ggml block geometry
static bool type_geom(std::uint32_t t, std::uint32_t& blkElems, std::uint32_t& blkBytes,
                      const char*& nm) {
    switch (t) {
        case 0:  blkElems = 1;   blkBytes = 4;   nm = "F32";   return true;
        case 1:  blkElems = 1;   blkBytes = 2;   nm = "F16";   return true;
        case 2:  blkElems = 32;  blkBytes = 18;  nm = "Q4_0";  return true;
        case 3:  blkElems = 32;  blkBytes = 20;  nm = "Q4_1";  return true;
        case 6:  blkElems = 32;  blkBytes = 22;  nm = "Q5_0";  return true;
        case 7:  blkElems = 32;  blkBytes = 24;  nm = "Q5_1";  return true;
        case 8:  blkElems = 32;  blkBytes = 34;  nm = "Q8_0";  return true;
        case 9:  blkElems = 32;  blkBytes = 36;  nm = "Q8_1";  return true;
        case 10: blkElems = 256; blkBytes = 84;  nm = "Q2_K";  return true;
        case 11: blkElems = 256; blkBytes = 110; nm = "Q3_K";  return true;
        case 12: blkElems = 256; blkBytes = 144; nm = "Q4_K";  return true;
        case 13: blkElems = 256; blkBytes = 176; nm = "Q5_K";  return true;
        case 14: blkElems = 256; blkBytes = 210; nm = "Q6_K";  return true;
        case 15: blkElems = 256; blkBytes = 292; nm = "Q8_K";  return true;
        default: return false;
    }
}

// ------------------------------------------------------------------ manifest
struct Tensor {
    std::string name, shape, role;
    int layer = -1, expert = -1;
    std::uint64_t off = 0, nbytes = 0, nelem = 0;
    std::uint32_t type = 0, blkElems = 0, blkBytes = 0;
    std::uint64_t fnv = 0;
    bool hashed = false;
    const char* tname = "?";
};

// "blk.12.ffn_gate_exps.weight" -> layer 12, role moe_gate, expert 37
static void classify(Tensor& t) {
    const std::string& n = t.name;
    const std::size_t b = n.rfind("blk.");
    if (b == std::string::npos) { t.role = "other"; return; }
    std::size_t i = b + 4, layer = 0;
    while (i < n.size() && std::isdigit(static_cast<unsigned char>(n[i]))) layer = layer * 10 + (n[i++] - '0');
    t.layer = int(layer);
    std::string rest = (i < n.size()) ? n.substr(i) : std::string();
    if (!rest.empty() && rest[0] == '.') rest.erase(0, 1);
    const std::size_t ex = rest.find("_exps.weight");
    if (ex != std::string::npos) {
        std::string e = rest.substr(0, ex);
        const std::size_t u = e.rfind('_');
        if (u != std::string::npos) {
            const std::string idx = e.substr(u + 1);
            t.expert = std::atoi(idx.c_str());
        }
        if (rest.rfind("ffn_gate", 0) == 0) t.role = "moe_gate";
        else if (rest.rfind("ffn_up", 0) == 0) t.role = "moe_up";
        else if (rest.rfind("ffn_down", 0) == 0) t.role = "moe_down";
        else t.role = "moe";
    } else if (rest.rfind("ffn_gate_shexp", 0) == 0) t.role = "ffn_gate_dense";
    else if (rest.rfind("ffn_", 0) == 0) t.role = "ffn_dense";
    else if (rest.rfind("attn_q", 0) == 0) t.role = "attn_q";
    else if (rest.rfind("attn_k", 0) == 0) t.role = "attn_k";
    else if (rest.rfind("attn_v", 0) == 0) t.role = "attn_v";
    else if (rest.rfind("attn_", 0) == 0) t.role = "attn_other";
    else t.role = "other";
}

static std::uint64_t fnv1a64(const std::uint8_t* p, std::size_t n) {
    std::uint64_t h = 1469598103934665603ull;
    for (std::size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

struct Cfg { std::string modelPath, modelId; std::uint16_t port = 8080; };
static Cfg g_cfg;
static std::vector<Tensor> g_tensors;
static std::uint64_t g_dataStart = 0, g_fileSize = 0, g_mapSize = 0;
static std::uint8_t* g_map = nullptr;

// ------------------------------------------------------------------- plumbing
static void send_all(SOCKET s, const void* pv, std::size_t n) {
    const char* p = static_cast<const char*>(pv);
    while (n) { const int k = ::send(s, p, int(n), 0); if (k <= 0) return; p += k; n -= std::size_t(k); }
}
static void respond(SOCKET s, int code, const char* status, const char* ctype,
                    const std::string& body, const char* extra = nullptr) {
    char h[640];
    int n = std::snprintf(h, sizeof h,
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n%sConnection: close\r\n\r\n",
        code, status, ctype, body.size(), extra ? extra : "");
    send_all(s, h, std::size_t(n));
    send_all(s, body.data(), body.size());
}
static std::string qget(const std::string& q, const char* key, std::string dflt = "") {
    std::string pat = std::string("&") + key + "=";
    std::size_t p = q.find(pat);
    if (p == std::string::npos) { pat = std::string("?") + key + "="; p = q.find(pat); }
    if (p == std::string::npos) return dflt;
    p += pat.size();
    const std::size_t e = q.find('&', p);
    return q.substr(p, (e == std::string::npos) ? std::string::npos : e - p);
}
static std::uint64_t qnum(const std::string& q, const char* key, std::uint64_t d) {
    const std::string v = qget(q, key);
    return v.empty() ? d : std::strtoull(v.c_str(), nullptr, 10);
}

// --------------------------------------------------------------------- routes
static std::string json_models() {
    std::string j = "{\"object\":\"list\",\"version\":\"";
    j += VERSION;
    j += "\",\"data\":[{\"id\":\"" + g_cfg.modelId;
    j += "\",\"object\":\"model\",\"owned_by\":\"local\",\"size\":" + std::to_string(g_fileSize);
    j += ",\"tensor_count\":" + std::to_string(g_tensors.size());
    j += ",\"window_bytes\":" + std::to_string(WINDOW);
    j += ",\"loadless\":true}]}";
    return j;
}

static std::string json_manifest(bool hash) {
    if (hash) {
        for (auto& t : g_tensors) {
            if (t.hashed) continue;
            t.fnv = fnv1a64(g_map + g_dataStart + t.off, std::size_t(t.nbytes));
            t.hashed = true;
        }
    }
    std::string j = "{\"id\":\"" + g_cfg.modelId + "\",\"version\":" + VERSION;
    j += ",\"size\":" + std::to_string(g_fileSize);
    j += ",\"data_offset\":" + std::to_string(g_dataStart);
    j += ",\"window_bytes\":" + std::to_string(WINDOW);
    j += ",\"tensor_count\":" + std::to_string(g_tensors.size());
    j += ",\"tensors\":[";
    for (std::size_t i = 0; i < g_tensors.size(); ++i) {
        const Tensor& t = g_tensors[i];
        if (i) j += ",";
        j += "{\"name\":\"" + t.name + "\"";
        j += ",\"offset\":" + std::to_string(g_dataStart + t.off);
        j += ",\"nbytes\":" + std::to_string(t.nbytes);
        j += ",\"elements\":" + std::to_string(t.nelem);
        j += ",\"shape\":\"" + t.shape + "\"";
        j += ",\"ggml_type\":" + std::to_string(t.type);
        j += ",\"type_name\":\"" + std::string(t.tname) + "\"";
        j += ",\"block_elems\":" + std::to_string(t.blkElems);
        j += ",\"block_bytes\":" + std::to_string(t.blkBytes);
        j += ",\"layer\":" + std::to_string(t.layer);
        j += ",\"expert\":" + std::to_string(t.expert);
        j += ",\"role\":\"" + t.role + "\"";
        if (t.hashed) j += ",\"fnv1a64\":" + std::to_string(t.fnv);
        j += "}";
    }
    j += "]}";
    return j;
}

static void handle(SOCKET s) {
    std::string req; char buf[8192];
    for (;;) {
        const int k = ::recv(s, buf, sizeof buf, 0);
        if (k <= 0) return;
        req.append(buf, std::size_t(k));
        if (req.find("\r\n\r\n") != std::string::npos) break;
        if (req.size() > (1u << 20)) return;
    }
    const std::size_t sp = req.find(' ');
    if (sp == std::string::npos) { respond(s, 400, "Bad Request", "text/plain", "bad\n"); return; }
    std::string path = req.substr(sp + 1);
    const std::size_t sp2 = path.find(' ');
    if (sp2 != std::string::npos) path = path.substr(0, sp2);
    const std::size_t qq = path.find('?');
    const std::string query = (qq == std::string::npos) ? "" : path.substr(qq);
    const std::string clean = (qq == std::string::npos) ? path : path.substr(0, qq);

    if (clean == "/health") {
        respond(s, 200, "OK", "application/json",
                "{\"status\":\"ok\",\"version\":\"" + std::string(VERSION) +
                "\",\"tensors\":" + std::to_string(g_tensors.size()) +
                ",\"mapped\":" + (g_map ? "true" : "false") +
                ",\"size\":" + std::to_string(g_fileSize) +
                ",\"window_bytes\":" + std::to_string(WINDOW) + "}");
        return;
    }
    if (clean == "/v1/models") { respond(s, 200, "OK", "application/json", json_models()); return; }
    if (clean.size() > 9 && clean.compare(clean.size() - 9, 9, "/manifest") == 0) {
        respond(s, 200, "OK", "application/json", json_manifest(qget(query, "hash") == "1"));
        return;
    }
    if (clean.size() > 10 && clean.compare(clean.size() - 10, 10, "/verify") == 0) {
        const std::string want = qget(query, "tensor");
        for (const auto& t : g_tensors) {
            if (t.name != want) continue;
            const std::uint64_t h = fnv1a64(g_map + g_dataStart + t.off, std::size_t(t.nbytes));
            respond(s, 200, "OK", "application/json",
                    "{\"name\":\"" + t.name + "\",\"nbytes\":" + std::to_string(t.nbytes) +
                    ",\"fnv1a64\":" + std::to_string(h) + "}");
            return;
        }
        respond(s, 404, "Not Found", "application/json", "{\"error\":\"no such tensor\"}");
        return;
    }
    if (clean.size() > 5 && clean.compare(clean.size() - 5, 5, "/blob") == 0) {
        const std::uint64_t off = qnum(query, "off", 0);
        std::uint64_t len = qnum(query, "len", WINDOW);
        if (!len || len > WINDOW) len = WINDOW;          // hard server-side ceiling
        if (off >= g_mapSize) { respond(s, 416, "Range Not Satisfiable", "text/plain", "past EOF\n"); return; }
        if (off + len > g_mapSize) len = g_mapSize - off;
        char h[400];
        const int hn = std::snprintf(h, sizeof h,
            "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\n"
            "Content-Range: bytes %llu-%llu/%llu\r\nContent-Length: %llu\r\n"
            "X-Loadless: 1\r\nX-Window: %zu\r\nConnection: close\r\n\r\n",
            (unsigned long long)off, (unsigned long long)(off + len - 1),
            (unsigned long long)g_mapSize, (unsigned long long)len, WINDOW);
        send_all(s, h, std::size_t(hn));
        send_all(s, g_map + off, std::size_t(len));
        return;
    }
    respond(s, 404, "Not Found", "text/plain", "no such endpoint\n");
}

// ---------------------------------------------------------------------- main
int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: %s <model.gguf> [port] [id]\n", argv[0]); return 1; }
    g_cfg.modelPath = argv[1];
    g_cfg.port = (argc > 2) ? std::uint16_t(std::atoi(argv[2])) : 8080;
    g_cfg.modelId = (argc > 3) ? argv[3] : "model";

    // parse the GGUF header
    std::FILE* f = std::fopen(g_cfg.modelPath.c_str(), "rb");
    if (!f) { std::printf("OPEN_FAILED\n"); return 1; }
    char magic[4] = {};
    std::uint32_t ver = 0; std::uint64_t ntensor = 0, nkv = 0;
    if (std::fread(magic, 1, 4, f) != 4 || std::memcmp(magic, "GGUF", 4)) {
        std::printf("NOT_GGUF\n"); std::fclose(f); return 1;
    }
    std::fread(&ver, 4, 1, f);
    std::fread(&ntensor, 8, 1, f);
    std::fread(&nkv, 8, 1, f);
    auto rdstr = [&](std::string& s) -> bool {
        std::uint64_t n = 0; if (std::fread(&n, 8, 1, f) != 1) return false;
        s.resize(n); return !n || std::fread(&s[0], 1, n, f) == n; };
    std::function<bool(std::uint32_t)> skipval = [&](std::uint32_t t) -> bool {
        switch (t) {
            case 0: case 1: case 7: return std::fseek(f, 1, SEEK_CUR) == 0;
            case 2: case 3: return std::fseek(f, 2, SEEK_CUR) == 0;
            case 4: case 5: case 6: return std::fseek(f, 4, SEEK_CUR) == 0;
            case 10: case 11: case 12: return std::fseek(f, 8, SEEK_CUR) == 0;
            case 8: { std::string s; return rdstr(s); }
            case 9: {
                std::uint32_t et = 0; std::uint64_t cnt = 0;
                if (std::fread(&et, 4, 1, f) != 1 || std::fread(&cnt, 8, 1, f) != 1) return false;
                for (std::uint64_t i = 0; i < cnt; ++i) if (!skipval(et)) return false;
                return true; }
            default: return false; } };
    for (std::uint64_t i = 0; i < nkv; ++i) {
        std::string k; std::uint32_t t = 0;
        if (!rdstr(k) || std::fread(&t, 4, 1, f) != 1 || !skipval(t)) {
            std::printf("KV_PARSE_FAILED at %llu\n", (unsigned long long)i); std::fclose(f); return 1; }
    }
    // _ftelli64: MSVC `long` is 32-bit even on x64, so ftell wraps on >2 GB files.
    // Record the table position but keep the handle OPEN -- the tensor table
    // still has to be read from it.
    const long long tableEnd = _ftelli64(f);

    g_dataStart = std::uint64_t(((tableEnd + 31) / 32) * 32);
    for (std::uint64_t i = 0; i < ntensor; ++i) {
        Tensor t; std::uint32_t nd = 0;
        if (!rdstr(t.name) || std::fread(&nd, 4, 1, f) != 1) { std::printf("TABLE_FAILED\n"); return 1; }
        std::string sh;
        for (std::uint32_t d = 0; d < nd; ++d) {
            std::uint64_t dim = 0; if (std::fread(&dim, 8, 1, f) != 1) return 1;
            if (!sh.empty()) sh += "x";
            sh += std::to_string(dim); t.nelem *= dim; }
        if (std::fread(&t.type, 4, 1, f) != 1 || std::fread(&t.off, 8, 1, f) != 1) return 1;
        t.shape = sh.empty() ? "scalar" : sh;
        const char* nm = "?";
        type_geom(t.type, t.blkElems, t.blkBytes, nm);
        t.tname = nm;
        classify(t);
        g_tensors.push_back(t);
    }
    std::fseek(f, 0, SEEK_END);
    g_fileSize = std::uint64_t(_ftelli64(f));
    std::fclose(f);

    for (std::size_t i = 0; i + 1 < g_tensors.size(); ++i)
        g_tensors[i].nbytes = g_tensors[i + 1].off - g_tensors[i].off;
    if (!g_tensors.empty())
        g_tensors.back().nbytes = g_fileSize - g_dataStart - g_tensors.back().off;

    HANDLE h = CreateFileA(g_cfg.modelPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { std::printf("OPEN_FAILED\n"); return 1; }
    // Size 0 on BOTH calls: an explicit 10 GB mapping size reserves that much
    // commit charge and fails with ERROR_NOT_ENOUGH_MEMORY (8). A read-only
    // file-backed section is demand-paged, so nothing is committed.
    HANDLE hm = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hm) { std::printf("MAPPING_FAILED err=%lu\n", GetLastError()); return 1; }
    g_map = static_cast<std::uint8_t*>(MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0));
    CloseHandle(hm); CloseHandle(h);
    if (!g_map) { std::printf("MAP_FAILED\n"); return 1; }
    g_mapSize = g_fileSize;

    WSADATA wa; WSAStartup(MAKEWORD(2, 2), &wa);
    SOCKET srv = ::socket(AF_INET, SOCK_STREAM, 0);
    BOOL one = TRUE;
    ::setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(g_cfg.port);
    if (::bind(srv, (sockaddr*)&a, sizeof a) == SOCKET_ERROR) { std::printf("BIND_FAILED\n"); return 1; }
    ::listen(srv, 16);

    PROCESS_MEMORY_COUNTERS_EX pmc{}; GetProcessMemoryInfo(GetCurrentProcess(),
        (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
    std::printf("%s\nmodel   %s\nsize    %llu\ntensors %zu\ndata_at %llu\n",
                VERSION, g_cfg.modelPath.c_str(), (unsigned long long)g_fileSize,
                g_tensors.size(), (unsigned long long)g_dataStart);
    std::printf("window  %zu bytes (%.2f MiB) hard ceiling per request\n",
                WINDOW, WINDOW / 1048576.0);
    std::printf("private %llu bytes (%.2f MB) at startup, zero model residency\n",
                (unsigned long long)pmc.PrivateUsage, pmc.PrivateUsage / 1e6);
    std::printf("listen  http://127.0.0.1:%u/v1/models\n\n", g_cfg.port);
    std::fflush(stdout);

    for (;;) { SOCKET c = ::accept(srv, nullptr, nullptr);
                if (c == INVALID_SOCKET) continue; handle(c); ::closesocket(c); }
}
