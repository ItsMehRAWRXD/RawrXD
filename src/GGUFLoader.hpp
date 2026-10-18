#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>

struct ModelConfig {
    uint32_t magic = 0;
    uint32_t version = 0;
    size_t tensorCount = 0;
    size_t kvCount = 0;
    size_t hiddenDim = 0;
    size_t numLayers = 0;
    size_t intermediateDim = 0;
    size_t numHeads = 0;
    size_t numKVHeads = 0;
    size_t vocabSize = 0;
    size_t maxSeqLen = 4096;
    double ropeThetaGlobal = 10000.0;
    double ropeScaleFactor = 1.0;
};

struct GGUFTensorMeta {
    std::string name;
    uint32_t type = 0;
    std::vector<uint64_t> dims;
    uint64_t offset = 0;
    void* dataData = nullptr;
};

struct EngineContext {
    ModelConfig cfg;
    std::unordered_map<std::string, GGUFTensorMeta> tensors;
    std::vector<uint8_t> tensorWeightsPool;
};

// Core parsing functions
std::string ReadGGUFStr(std::ifstream& f);
void SkipGGUFValue(uint32_t type, std::ifstream& f);
float SafeFp16ToFloat32(uint16_t fp16);
float ConvertFp16ToFloat32(uint16_t fp16);

// Universal metadata parsing
void ParseUniversalGGUFMetadata(const std::string& keyStr, uint32_t kvType, std::ifstream& file, EngineContext* ctx);

// Ollama manifest parsing
bool ParseOllamaManifest(const std::string& manifestPath, EngineContext* ctx);

// Main loading function
bool LoadUniversalBlob(const std::string& path, EngineContext* ctx);