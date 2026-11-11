#include "IntegrityEngine.h"
#include "../lora/LoRAAdapterManager.h"
#include "../lora/AdapterSerializer.h"
#include <iostream>
#include <cstring>
#include <random>

namespace RawrXD::E2E {

bool IntegrityEngine::ValidateSerializationRoundTrip(const LoRAAdapter& adapter) {
    // Create temporary file
    std::string temp_path = std::filesystem::temp_directory_path().string() + 
                            "/e2e_roundtrip_test.lora";
    
    // Serialize
    if (!AdapterSerializer::Save(temp_path, adapter)) {
        std::cerr << "[IntegrityEngine] Serialization failed\n";
        return false;
    }
    
    // Deserialize
    auto loaded = AdapterSerializer::Load(temp_path);
    if (!loaded) {
        std::cerr << "[IntegrityEngine] Deserialization failed\n";
        return false;
    }
    
    // Compare dimensions
    if (loaded->rank != adapter.rank ||
        loaded->input_dim != adapter.input_dim ||
        loaded->output_dim != adapter.output_dim) {
        std::cerr << "[IntegrityEngine] Dimension mismatch\n";
        return false;
    }
    
    // Compare matrix A
    size_t a_size = adapter.rank * adapter.input_dim;
    if (std::memcmp(loaded->matrix_A.get(), adapter.matrix_A.get(), a_size * sizeof(float)) != 0) {
        std::cerr << "[IntegrityEngine] Matrix A mismatch\n";
        return false;
    }
    
    // Compare matrix B
    size_t b_size = adapter.output_dim * adapter.rank;
    if (std::memcmp(loaded->matrix_B.get(), adapter.matrix_B.get(), b_size * sizeof(float)) != 0) {
        std::cerr << "[IntegrityEngine] Matrix B mismatch\n";
        return false;
    }
    
    // Cleanup
    std::filesystem::remove(temp_path);
    
    return true;
}

bool IntegrityEngine::DetectCorruption(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return false; // File doesn't exist, not corrupted
    }
    
    // Read file
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return true; // Can't read - treat as corrupted
    }
    
    // Read header
    LoRAFileHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    if (!file || file.gcount() != sizeof(header)) {
        return true; // Header read failed
    }
    
    // Validate header
    if (!AdapterSerializer::ValidateHeader(header)) {
        return true; // Invalid header
    }
    
    // Read data
    std::vector<uint8_t> data(header.data_size);
    file.read(reinterpret_cast<char*>(data.data()), header.data_size);
    
    if (!file || static_cast<size_t>(file.gcount()) != header.data_size) {
        return true; // Data read failed
    }
    
    // Calculate checksum
    uint32_t calculated_crc = AdapterSerializer::CalculateCRC32(data.data(), data.size());
    
    // Compare
    if (calculated_crc != header.checksum) {
        std::cerr << "[IntegrityEngine] Checksum mismatch: expected " 
                  << header.checksum << ", got " << calculated_crc << "\n";
        return true; // Checksum mismatch - corruption detected
    }
    
    return false; // No corruption
}

bool IntegrityEngine::SimulateCorruption(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return false;
    }
    
    // Read entire file
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (size <= sizeof(LoRAFileHeader)) {
        return false;
    }
    
    // Read data after header
    std::vector<uint8_t> data(size - sizeof(LoRAFileHeader));
    file.seekg(sizeof(LoRAFileHeader));
    file.read(reinterpret_cast<char*>(data.data()), data.size());
    
    // Corrupt random byte in data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, data.size() - 1);
    size_t corrupt_idx = dist(gen);
    
    data[corrupt_idx] ^= 0xFF; // Flip all bits
    
    // Write back
    file.seekp(sizeof(LoRAFileHeader));
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    
    return file.good();
}

} // namespace RawrXD::E2E
