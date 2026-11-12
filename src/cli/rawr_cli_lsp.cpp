#include "cli/rawr_cli_lsp.hpp"
#include "lsp/RawrXD_LSPServer.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;
using RawrXD::LSPServer::RawrXDLSPServer;
using RawrXD::LSPServer::ServerConfig;

static std::string drain(RawrXDLSPServer& s) {
    std::string last;
    for (;;) {
        std::string m = s.pollOutgoing();
        if (m.empty()) break;
        last = std::move(m);
    }
    return last;
}

static json parseResult(const std::string& raw) {
    if (raw.empty()) return json();
    try {
        json j = json::parse(raw);
        if (j.contains("result")) return j["result"];
        return j;
    } catch (...) {
        return json();
    }
}

int rawrCliLspCommand(const std::vector<std::string>& args,
                      const std::string& workspaceRoot, bool jsonOut) {
    if (!args.empty() && args[0] != "probe") {
        std::cout << "usage: rawr lsp probe\n";
        return 1;
    }
    fs::path probeDir = fs::path(workspaceRoot) / "evidence" / "_lsp_cli_probe";
    std::error_code ec;
    fs::create_directories(probeDir, ec);
    fs::path file = probeDir / "probe_lsp.cpp";
    const std::string body =
        "class AlphaWidget {\npublic:\n  void tick() {}\n};\n"
        "int alpha_helper() { return 42; } // TODO: wire\n"
        "void use_alpha() { AlphaWidget w; w.tick(); }\n";
    {
        std::ofstream ofs(file, std::ios::binary | std::ios::trunc);
        ofs << body;
    }
    std::string path = file.string();
    for (char& c : path)
        if (c == '\\') c = '/';
    std::string uri = "file:///" + path;

    ServerConfig cfg;
    cfg.rootPath = probeDir.string();
    cfg.rootUri = "file:///" + probeDir.string();
    cfg.useStdio = false;
    cfg.maxCompletionItems = 50;

    RawrXDLSPServer server;
    server.configure(cfg);
    server.processMessageSync(
        json({{"jsonrpc", "2.0"},
              {"id", 1},
              {"method", "initialize"},
              {"params", {{"processId", nullptr}, {"rootUri", cfg.rootUri}}}})
            .dump());
    json init = parseResult(drain(server));
    server.processMessageSync(
        json({{"jsonrpc", "2.0"}, {"method", "initialized"}, {"params", json::object()}})
            .dump());
    drain(server);
    server.indexSingleFile(file.string());
    server.processMessageSync(
        json({{"jsonrpc", "2.0"},
              {"method", "textDocument/didOpen"},
              {"params",
               {{"textDocument",
                 {{"uri", uri}, {"languageId", "cpp"}, {"version", 1}, {"text", body}}}}}})
            .dump());
    drain(server);

    server.processMessageSync(
        json({{"jsonrpc", "2.0"},
              {"id", 2},
              {"method", "textDocument/completion"},
              {"params",
               {{"textDocument", {{"uri", uri}}},
                {"position", {{"line", 5}, {"character", 10}}}}}})
            .dump());
    json comp = parseResult(drain(server));
    int completions = 0;
    if (comp.contains("items") && comp["items"].is_array())
        completions = (int)comp["items"].size();

    // AlphaWidget at class line 0
    server.processMessageSync(
        json({{"jsonrpc", "2.0"},
              {"id", 3},
              {"method", "textDocument/hover"},
              {"params",
               {{"textDocument", {{"uri", uri}}},
                {"position", {{"line", 0}, {"character", 8}}}}}})
            .dump());
    json hover = parseResult(drain(server));
    int hoverOk = (hover.is_object() && hover.contains("contents")) ? 1 : 0;

    server.processMessageSync(
        json({{"jsonrpc", "2.0"},
              {"id", 4},
              {"method", "textDocument/definition"},
              {"params",
               {{"textDocument", {{"uri", uri}}},
                {"position", {{"line", 0}, {"character", 8}}}}}})
            .dump());
    json def = parseResult(drain(server));
    int definitions = def.is_array() ? (int)def.size() : (def.is_object() ? 1 : 0);

    server.processMessageSync(
        json({{"jsonrpc", "2.0"},
              {"method", "textDocument/didSave"},
              {"params", {{"textDocument", {{"uri", uri}}}, {"text", body}}}})
            .dump());
    int diagnostics = 0;
    for (;;) {
        std::string m = server.pollOutgoing();
        if (m.empty()) break;
        try {
            json n = json::parse(m);
            if (n.value("method", "") == "textDocument/publishDiagnostics") {
                diagnostics = (int)n["params"].value("diagnostics", json::array()).size();
            }
        } catch (...) {
        }
    }

    server.processMessageSync(
        json({{"jsonrpc", "2.0"},
              {"id", 5},
              {"method", "textDocument/rename"},
              {"params",
               {{"textDocument", {{"uri", uri}}},
                {"position", {{"line", 0}, {"character", 8}}},
                {"newName", "BetaWidget"}}}})
            .dump());
    json ren = parseResult(drain(server));
    int renameEdits = 0;
    if (ren.contains("changes") && ren["changes"].is_object()) {
        for (auto it = ren["changes"].begin(); it != ren["changes"].end(); ++it)
            if (it.value().is_array()) renameEdits += (int)it.value().size();
    }

    json diag = {{"message", "TODO marker found"},
                 {"range",
                  {{"start", {{"line", 3}, {"character", 24}}},
                   {"end", {{"line", 3}, {"character", 28}}}}}};
    json caParams = {
        {"textDocument", {{"uri", uri}}},
        {"range",
         {{"start", {{"line", 3}, {"character", 0}}},
          {"end", {{"line", 3}, {"character", 20}}}}},
        {"context", {{"diagnostics", json::array({diag})}}}};
    server.processMessageSync(
        json({{"jsonrpc", "2.0"},
              {"id", 6},
              {"method", "textDocument/codeAction"},
              {"params", caParams}})
            .dump());
    json acts = parseResult(drain(server));
    int codeActions = acts.is_array() ? (int)acts.size() : 0;

    int symbols = (int)server.getIndexedSymbolCount();
    int caps = (init.contains("capabilities") &&
                init["capabilities"].value("completionProvider", json()).is_object() &&
                init["capabilities"].value("hoverProvider", false) &&
                init["capabilities"].value("definitionProvider", false) &&
                init["capabilities"].value("renameProvider", false))
                   ? 1
                   : 0;
    int sessionOk = (caps && completions > 0 && hoverOk && definitions > 0 &&
                     diagnostics > 0 && renameEdits > 0 && codeActions > 0 && symbols > 0)
                        ? 1
                        : 0;

    if (jsonOut) {
        std::cout << json({{"caps", caps},
                           {"completions", completions},
                           {"hover", hoverOk},
                           {"definitions", definitions},
                           {"diagnostics", diagnostics},
                           {"rename_edits", renameEdits},
                           {"code_actions", codeActions},
                           {"symbols", symbols},
                           {"SESSION_REAL", sessionOk}})
                         .dump()
                  << "\n";
    } else {
        std::cout << "BACKEND=RawrXDLSPServer caps=" << caps
                  << " completions=" << completions << " hover=" << hoverOk
                  << " definitions=" << definitions << " diagnostics=" << diagnostics
                  << " rename_edits=" << renameEdits << " code_actions=" << codeActions
                  << " symbols=" << symbols << " SESSION_REAL=" << sessionOk << "\n";
    }
    return sessionOk ? 0 : 1;
}
