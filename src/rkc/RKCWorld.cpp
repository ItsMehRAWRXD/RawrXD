// RKCWorld.cpp — REAL observers (fs, LIVE_PATH, hardware, negative)
#include "RKCWorld.hpp"
#include "RKCValidator.hpp"
#include "RKCCodeWorld.hpp"
#include "RKCNegativeKnowledge.hpp"
#include "RKCModelInventory.hpp"
#include "deep2/Deep2LivePath.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif

namespace fs = std::filesystem;

namespace RawrXD {
namespace RKC {

void World::clearSession() {
    atoms_.clear();
    graph_.clearSession();
}

void World::putAtom(const KnowledgeAtom& a) { atoms_[a.key] = a; }

const KnowledgeAtom* World::get(const std::string& key) const {
    auto it = atoms_.find(key);
    return it == atoms_.end() ? nullptr : &it->second;
}

void World::putReal(const std::string& key, const std::string& value,
                    const std::string& source) {
    KnowledgeAtom a;
    a.key = key;
    a.value = value;
    a.state = EpistemicState::Real;
    a.source = source;
    a.kind = AtomKind::Fact;
    atoms_[key] = a;

    W0::KnowledgeNode n;
    n.kind = W0::NodeKind::Fact;
    n.name = key;
    n.content = value;
    n.provenance = {source, 0, W0::VerificationLevel::SourceCode};
    graph_.addNode(std::move(n), W0::KnowledgeScope::Session);
}

void World::putNeg(const std::string& key, EpistemicState neg,
                   const std::string& value, const std::string& source) {
    KnowledgeAtom a;
    a.key = key;
    a.value = value;
    a.state = neg;
    a.source = source;
    a.kind = AtomKind::Negative;
    atoms_[key] = a;
}

void World::observeFilesystem(const WorldObserveConfig& cfg) {
    if (cfg.modelPath.empty()) {
        putNeg("model_exists", EpistemicState::NotPresent, "0", "fs");
        putNeg("all_required_shards_exist", EpistemicState::NotObserved,
               "unknown", "fs");
        return;
    }
    std::error_code ec;
    const fs::path p(cfg.modelPath);
    const bool exists = fs::exists(p, ec);
    putReal("model_exists", exists ? "1" : "0", "fs");
    if (!exists) {
        putNeg("all_required_shards_exist", EpistemicState::NotPresent, "0", "fs");
        return;
    }

    bool isDir = fs::is_directory(p, ec);
    putReal("model_path", cfg.modelPath, "fs");
    if (isDir) {
        size_t gguf = 0;
        for (auto& e : fs::directory_iterator(p, ec)) {
            if (e.is_regular_file() && e.path().extension() == ".gguf") ++gguf;
        }
        putReal("shard_present_count", std::to_string(gguf), "fs");
        putReal("all_required_shards_exist", gguf > 0 ? "1" : "0", "fs");
        putReal("model_format_supported", gguf > 0 ? "1" : "0", "fs");
    } else {
        putReal("shard_present_count", "1", "fs");
        putReal("all_required_shards_exist", "1", "fs");
        const auto ext = p.extension().string();
        putReal("model_format_supported",
                (ext == ".gguf" || ext == ".GGUF") ? "1" : "0", "fs");
        putReal("model_bytes",
                std::to_string(static_cast<uint64_t>(fs::file_size(p, ec))), "fs");
    }
}

void World::observeLivePath() {
    const auto& c = Deep2::LivePath_Counters();
    putReal("live_generation_path_exists", "1", "live_path_abi");
    putReal("live_path_vacuum", std::to_string(c.vacuumArmed), "live_path");
    putReal("live_path_trampoline", std::to_string(c.trampolineInstalled),
            "live_path");
    putReal("live_path_cyclone", std::to_string(c.cycloneArmed), "live_path");
    putReal("live_path_trampoline_hits", std::to_string(c.trampolineHits),
            "live_path");
    putReal("engine_loaded",
            (c.trampolineInstalled || c.cycloneArmed || Deep2::LivePath_Active())
                ? "1"
                : "0",
            "live_path");
    putReal("forward_live", c.cycloneLayerStarts > 0 ? "1" : "0", "live_path");
    putReal("decode_live", c.trailbrakeReports > 0 ? "1" : "0", "live_path");
    putReal("sample_live", c.pinballSamples > 0 ? "1" : "0", "live_path");
}

void World::observeHardware(const WorldObserveConfig& cfg) {
    putReal("gpu.memory", std::to_string(cfg.availableVram), "hw");
    putReal("weights_window", std::to_string(cfg.weightsBytes), "hw");
    putReal("kv_budget", std::to_string(cfg.kvBudget), "hw");
    putReal("forward_arena", std::to_string(cfg.forwardArena), "hw");
    putReal("safety_margin", std::to_string(cfg.safetyMargin), "hw");
    putReal("compute_backend_exists", "1", "hw"); // Deep2 local stack present
}

void World::observeNegative(const WorldObserveConfig& cfg) {
    putReal("no_remote_dependency", "1", "policy");
    putReal("remote_calls", "0", "policy");

    if (!cfg.probeOllama11434) return;
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    bool reachable = false;
    if (s != INVALID_SOCKET) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(11434);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        u_long nonblock = 1;
        ioctlsocket(s, FIONBIO, &nonblock);
        connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(s, &wset);
        timeval tv{0, 200000};
        if (select(0, nullptr, &wset, nullptr, &tv) > 0) reachable = true;
        closesocket(s);
    }
    WSACleanup();
    if (reachable) {
        putReal("ollama_11434_reachable", "1", "net");
    } else {
        putNeg("ollama_11434_reachable", EpistemicState::NotReachable, "0", "net");
        putReal("generation_path_requires_ollama", "0", "net");
    }
#endif
}

void World::observeCodeWorld(const std::string& repoRoot) {
    (void)ObserveCodeWorld(*this, repoRoot);
}

void World::observeAbsence(const WorldObserveConfig& cfg,
                           const std::string& repoRoot) {
    (void)ObserveAbsenceCatalog(*this, cfg, repoRoot);
}

void World::observeModelInventory(const std::string& modelRoot) {
    (void)ObserveModelInventory(*this, modelRoot);
}

void World::seedAll(const WorldObserveConfig& cfg) {
    clearSession();
    observeFilesystem(cfg);
    observeLivePath();
    observeHardware(cfg);
    observeNegative(cfg);
    // tokenizer: derive placeholder from format support
    if (const auto* fmt = get("model_format_supported")) {
        KnowledgeAtom t;
        t.key = "tokenizer_supported";
        t.value = fmt->value;
        t.state = EpistemicState::Derived;
        t.parents = {"model_format_supported"};
        t.source = "derive:format";
        atoms_[t.key] = t;
    }
}

} // namespace RKC
} // namespace RawrXD
