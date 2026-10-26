#pragma once
#include <cstdint>
#include <string>

struct AgentSessionNote {
    uint64_t sessionId = 0;
    uint64_t taskId = 0;
    int filesChanged = 0;
    int terminals = 0;
    int cancelled = 0;
};

bool AgentSessionBegin(const std::string& dir, uint64_t* sessionId, uint64_t* taskId);
void AgentSessionCancel();
bool AgentSessionCancelled();
bool AgentSessionNoteWrite(const std::string& path, const std::string& before,
                           const std::string& after);
void AgentSessionNoteTerminal(uint64_t pid, int live);
int AgentSessionFilesChanged();
int AgentSessionTerminals();
std::string AgentSessionCountersJson();
std::string AgentSessionReviewFirst();
void AgentSessionKillTree(void* process);
int AgentSessionProductProof();
int AgentSessionAdmit(const std::string& body, std::string* json);
bool AgentSessionRestore(const std::string& dir, AgentSessionNote* out);
void AgentSessionAbandonLive();
void AgentSessionLoadIds(uint64_t session, uint64_t task, int cancelled);
void AgentSessionLoadRow(const std::string& path, uint64_t first, uint64_t last);
void AgentSessionMarkCancelled();
uint64_t AgentSessionTaskId();
