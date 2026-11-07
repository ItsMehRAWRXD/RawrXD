#include "finish_batches.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>

void fillBatchSim(std::vector<BatchGate>& out);
void fillBatchAudio(std::vector<BatchGate>& out);

int runFinishBatches(const std::string& evidenceDir) {
    std::filesystem::create_directories(evidenceDir);
    std::vector<BatchGate> gates;
    auto start = std::chrono::steady_clock::now();
    fillBatchWorld(gates);
    fillBatchClimate(gates);
    fillBatchLive(gates);
    fillBatchSim(gates);
    fillBatchPlay(gates);
    fillBatchAudio(gates);
    fillBatchTools(gates, evidenceDir);
    fillBatchShip(gates, evidenceDir);
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    for (BatchGate& gate : gates) if (gate.id == 20) gate.detail += " suite_ms=" + std::to_string(ms);
    int pass = 0, fail = 0, partial = 0, notrun = 0;
    std::ofstream json(evidenceDir + "/kartgib_batches_25.json");
    json << "{\n  \"gate\":\"KARTGIB_BATCHES_25\",\n  \"promote\":0,\n  \"tip_climb\":\"HOLD\",\n  \"suite_ms\":" << ms << ",\n  \"batches\":[\n";
    for (size_t i = 0; i < gates.size(); ++i) {
        const BatchGate& gate = gates[i];
        if (std::string(gate.status) == "PASS") ++pass;
        else if (std::string(gate.status) == "FAIL") ++fail;
        else if (std::string(gate.status) == "PARTIAL") ++partial;
        else ++notrun;
        json << "    {\"id\":" << gate.id << ",\"name\":\"" << gate.name << "\",\"status\":\"" << gate.status
             << "\",\"detail\":\"" << gate.detail << "\"}" << (i + 1 == gates.size() ? "\n" : ",\n");
        std::cout << "[B" << gate.id << "] " << gate.status << " " << gate.detail << std::endl;
    }
    json << "  ],\n  \"pass\":" << pass << ",\"fail\":" << fail << ",\"partial\":" << partial << ",\"not_run\":" << notrun << "\n}\n";
    std::cout << "[BATCHES] pass=" << pass << " fail=" << fail << " partial=" << partial << " not_run=" << notrun << std::endl;
    return fail == 0 ? 0 : 1;
}
