// rawr_terminal_supervisor.hpp
#pragma once
#include "rawr_terminal_session.hpp"
#include "rawr_terminal_safety.hpp"
#include <memory>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace rawr::term {

struct TerminalSupervisor {
    std::mutex mu;
    std::unordered_map<std::string, std::unique_ptr<TermSession>> map;
    TermSafety safety;

    static TerminalSupervisor& instance() {
        static TerminalSupervisor g;
        return g;
    }

    int start(const std::string& name, const std::string& cmd) {
        if (name.empty() || cmd.empty()) return 1;
        int g = GuardCommand(safety, cmd);
        if (g) return g;
        std::lock_guard<std::mutex> lk(mu);
        if (map.count(name)) return 2;
        auto s = std::make_unique<TermSession>();
        if (!SessionStart(*s, name, cmd)) return 3;
        map[name] = std::move(s);
        return 0;
    }

    bool stop(const std::string& name) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = map.find(name);
        if (it == map.end()) return false;
        bool ok = SessionStop(*it->second);
        map.erase(it);
        return ok;
    }

    int killall() {
        std::lock_guard<std::mutex> lk(mu);
        int n = 0;
        for (auto& kv : map) {
            SessionStop(*kv.second);
            ++n;
        }
        map.clear();
        return n;
    }

    bool send(const std::string& name, const std::string& in) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = map.find(name);
        if (it == map.end()) return false;
        return SessionSend(*it->second, in);
    }

    std::string tail(const std::string& name, size_t maxBytes) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = map.find(name);
        if (it == map.end()) return ReadTermLogTail(name, maxBytes);
        SessionPoll(*it->second);
        return it->second->tail(maxBytes);
    }

    std::string status(const std::string& name) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = map.find(name);
        if (it == map.end()) return "missing=1";
        SessionPoll(*it->second);
        auto& s = *it->second;
        std::ostringstream os;
        os << "name=" << s.name << " pid=" << s.proc.pid
           << " alive=" << (s.alive.load() ? 1 : 0) << " exit=" << s.exitCode
           << " out=" << s.outBytes << " err=" << s.errBytes;
        return os.str();
    }

    std::string list() {
        std::lock_guard<std::mutex> lk(mu);
        std::ostringstream os;
        for (auto& kv : map) {
            SessionPoll(*kv.second);
            os << kv.first << " pid=" << kv.second->proc.pid
               << " alive=" << (kv.second->alive.load() ? 1 : 0)
               << " exit=" << kv.second->exitCode << "\n";
        }
        return os.str();
    }

    TermSession* get(const std::string& name) {
        auto it = map.find(name);
        return it == map.end() ? nullptr : it->second.get();
    }
};

} // namespace rawr::term
