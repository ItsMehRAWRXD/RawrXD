// rawr_transcript_log.hpp
#pragma once
#include "rawr_session_store.hpp"
#include <fstream>
#include <string>
namespace rawr {
inline bool AppendTranscript(const SessionState& s, const ChatTurn& t) {
    std::string path = DefaultSessionRoot() + "\\" + s.id + ".transcript";
    std::ofstream out(path, std::ios::app | std::ios::binary);
    if (!out) return false;
    out << t.role << "\t" << t.content << "\n";
    return true;
}
} // namespace rawr
