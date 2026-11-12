// MasmLspSession.cpp — embedded MASM LSP protocol session (sync, no fake PASS).
#include "lsp/MasmLspSession.hpp"
#include "lsp/RawrXD_LSPServer.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <sstream>

using json = nlohmann::json;

namespace RawrXD {
namespace LSPServer {
namespace {

std::string NormalizePath(std::string p) {
    for (char& c : p) {
        if (c == '/') c = '\\';
    }
    return p;
}

std::string PathToUri(std::string path) {
    for (char& c : path) {
        if (c == '\\') c = '/';
    }
    if (!path.empty() && path[0] != '/') path = "/" + path;
    return "file://" + path;
}

std::string ExtractProcName(const std::string& asmText) {
    // First "name PROC" token — probe uses probe_entry PROC.
    std::istringstream iss(asmText);
    std::string line;
    while (std::getline(iss, line)) {
        std::string up = line;
        std::transform(up.begin(), up.end(), up.begin(),
                       [](unsigned char c) { return (char)std::toupper(c); });
        auto pos = up.find(" PROC");
        if (pos == std::string::npos) continue;
        std::string name;
        for (size_t i = 0; i < line.size() && i < pos; ++i) {
            char c = line[i];
            if (std::isalnum((unsigned char)c) || c == '_' || c == '$' || c == '?' || c == '@')
                name.push_back(c);
            else if (!name.empty())
                break;
        }
        if (!name.empty()) return name;
    }
    return {};
}

json PollResult(RawrXDLSPServer& srv, int id) {
    for (int i = 0; i < 64; ++i) {
        std::string out = srv.pollOutgoing();
        if (out.empty()) continue;
        try {
            json msg = json::parse(out);
            if (msg.contains("id") && msg["id"] == id) return msg;
        } catch (...) {
        }
    }
    return json::object();
}

}  // namespace

MasmLspProbeResult RunMasmLspProtocolSession(const std::string& rootPath,
                                             const std::string& asmPath,
                                             const std::string& asmText) {
    MasmLspProbeResult r;
    if (asmPath.empty() || asmText.empty()) {
        r.detail = "empty_asm";
        return r;
    }

    const std::string proc = ExtractProcName(asmText);
    if (proc.empty()) {
        r.detail = "no_proc_in_source";
        return r;
    }

    RawrXDLSPServer srv;
    ServerConfig cfg;
    cfg.useStdio = false;
    // Empty root skips workspace walk; didOpen indexes the open .asm.
    cfg.rootPath = rootPath.empty() ? std::string() : NormalizePath(rootPath);
    cfg.rootUri = PathToUri(cfg.rootPath.empty() ? NormalizePath(asmPath) : cfg.rootPath);
    // Ensure initialize cannot re-derive a walkable root from rootUri alone.
    cfg.enableHover = true;
    cfg.enableCompletion = true;
    cfg.enableDiagnostics = true;
    cfg.enableDefinition = true;
    cfg.enableDocumentSymbol = true;
    cfg.maxCompletionItems = 100;
    srv.configure(cfg);

    const std::string uri = PathToUri(NormalizePath(asmPath));
    int nextId = 1;

    {
        json params;
        params["processId"] = nullptr;
        params["rootUri"] = cfg.rootUri;
        params["capabilities"]["textDocument"]["hover"] = json::object();
        params["capabilities"]["textDocument"]["completion"] = json::object();
        params["clientInfo"] = {{"name", "RawrXD-MasmLspProbe"}, {"version", "1.0.0"}};
        json req = {{"jsonrpc", "2.0"}, {"id", nextId}, {"method", "initialize"}, {"params", params}};
        srv.processMessageSync(req.dump());
        json resp = PollResult(srv, nextId++);
        r.initOk = resp.contains("result") && resp["result"].contains("capabilities") &&
                   resp["result"]["capabilities"].value("hoverProvider", false);
        if (!r.initOk) {
            r.detail = "initialize_failed";
            return r;
        }
    }

    {
        json n = {{"jsonrpc", "2.0"},
                  {"method", "initialized"},
                  {"params", json::object()}};
        srv.processMessageSync(n.dump());
    }

    {
        json td;
        td["uri"] = uri;
        td["languageId"] = "asm";
        td["version"] = 1;
        td["text"] = asmText;
        json n = {{"jsonrpc", "2.0"},
                  {"method", "textDocument/didOpen"},
                  {"params", {{"textDocument", td}}}};
        srv.processMessageSync(n.dump());
        r.didOpenOk = true;
        r.symbolsIndexed = (int)srv.getIndexedSymbolCount();
        if (r.symbolsIndexed <= 0) {
            r.detail = "didOpen_no_symbols";
            return r;
        }
    }

    // Hover on PROC name (line with PROC — typically line 1 in probe.asm).
    int hoverLine = 1;
    int hoverChar = 0;
    {
        std::istringstream iss(asmText);
        std::string line;
        int ln = 0;
        while (std::getline(iss, line)) {
            if (line.find(proc) != std::string::npos &&
                (line.find("PROC") != std::string::npos || line.find("proc") != std::string::npos)) {
                hoverLine = ln;
                hoverChar = (int)line.find(proc) + 1;
                break;
            }
            ++ln;
        }
    }

    bool hoverHit = false;
    {
        json params;
        params["textDocument"]["uri"] = uri;
        params["position"]["line"] = hoverLine;
        params["position"]["character"] = hoverChar;
        json req = {{"jsonrpc", "2.0"},
                    {"id", nextId},
                    {"method", "textDocument/hover"},
                    {"params", params}};
        srv.processMessageSync(req.dump());
        json resp = PollResult(srv, nextId++);
        if (resp.contains("result") && !resp["result"].is_null()) {
            std::string dump = resp["result"].dump();
            hoverHit = dump.find(proc) != std::string::npos;
        }
    }

    bool completionHit = false;
    {
        json params;
        params["textDocument"]["uri"] = uri;
        params["position"]["line"] = hoverLine;
        params["position"]["character"] = hoverChar;
        json req = {{"jsonrpc", "2.0"},
                    {"id", nextId},
                    {"method", "textDocument/completion"},
                    {"params", params}};
        srv.processMessageSync(req.dump());
        json resp = PollResult(srv, nextId++);
        if (resp.contains("result")) {
            std::string dump = resp["result"].dump();
            completionHit = dump.find(proc) != std::string::npos;
        }
    }

    r.featureOk = hoverHit || completionHit;
    r.ok = r.initOk && r.didOpenOk && r.featureOk;
    r.detail = r.ok ? ("protocol_ok hover=" + std::to_string((int)hoverHit) +
                       " completion=" + std::to_string((int)completionHit) +
                       " symbols=" + std::to_string(r.symbolsIndexed) + " proc=" + proc)
                    : ("feature_miss hover=" + std::to_string((int)hoverHit) +
                       " completion=" + std::to_string((int)completionHit) +
                       " symbols=" + std::to_string(r.symbolsIndexed));
    return r;
}

}  // namespace LSPServer
}  // namespace RawrXD
