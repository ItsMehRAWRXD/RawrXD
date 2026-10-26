#pragma once
#include <string>
#include <vector>

struct BatchGate {
    int id = 0;
    const char* name = "";
    const char* status = "NOT_RUN";
    std::string detail;
};

inline void addGate(std::vector<BatchGate>& out, int id, const char* name, const char* status, const std::string& detail) {
    out.push_back({id, name, status, detail});
}
inline const char* passFail(bool ok) { return ok ? "PASS" : "FAIL"; }

void fillBatchWorld(std::vector<BatchGate>& out);
void fillBatchClimate(std::vector<BatchGate>& out);
void fillBatchLive(std::vector<BatchGate>& out);
void fillBatchSim(std::vector<BatchGate>& out);
void fillBatchPlay(std::vector<BatchGate>& out);
void fillBatchAudio(std::vector<BatchGate>& out);
void fillBatchTools(std::vector<BatchGate>& out, const std::string& dir);
void fillBatchShip(std::vector<BatchGate>& out, const std::string& dir);
int runFinishBatches(const std::string& evidenceDir);
