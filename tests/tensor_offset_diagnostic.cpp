/**
 * @file tensor_offset_diagnostic.cpp
 * @brief Diagnose tensor data location
 * 
 * Reads raw bytes from various offsets to find actual tensor data.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstdint>

using namespace std;

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔍 Tensor Offset Diagnostic\n";
    cout << "============================\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open file\n";
        return 1;
    }
    
    // Get file size
    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    cout << "File size: " << file_size << " bytes (" << (file_size / 1024 / 1024) << " MB)\n\n";
    
    // Try reading from various offsets
    vector<size_t> test_offsets = {
        726725,      // Known metadata end
        726728,      // Aligned to 8 bytes
        727000,      // Slightly past
        728000,      // Further past
        730000,      // Even further
        740000,      // Much further
    };
    
    for (size_t offset : test_offsets) {
        if (offset >= file_size) continue;
        
        file.seekg(offset, ios::beg);
        
        // Read first 32 bytes
        uint8_t buffer[32];
        file.read(reinterpret_cast<char*>(buffer), 32);
        
        cout << "Offset " << offset << ":\n";
        cout << "  Hex: ";
        for (int i = 0; i < 32; i++) {
            cout << hex << setw(2) << setfill('0') << (int)buffer[i];
            if ((i + 1) % 4 == 0) cout << " ";
        }
        cout << dec << "\n";
        
        // Check if this looks like Q4_0 data
        // First 2 bytes should be FP16 scale
        uint16_t scale_bits = buffer[0] | (buffer[1] << 8);
        
        // Simple FP16 check: if exponent bits (10-14) are not all 0 or all 1
        uint16_t exponent = (scale_bits >> 10) & 0x1F;
        bool looks_like_fp16 = (exponent != 0 && exponent != 31);
        
        cout << "  Scale bits: 0x" << hex << scale_bits << dec;
        if (looks_like_fp16) {
            cout << " (looks like valid FP16)";
        }
        cout << "\n\n";
    }
    
    // Also check what tensor_validation found
    cout << "Expected tensor data start: 726725\n";
    cout << "This should be where token_embd.weight data begins\n\n";
    
    // Read from 726725 and interpret as Q4_0 blocks
    file.seekg(726725, ios::beg);
    
    cout << "Reading Q4_0 blocks from offset 726725:\n";
    for (int block = 0; block < 3; block++) {
        uint8_t block_data[18];
        file.read(reinterpret_cast<char*>(block_data), 18);
        
        uint16_t scale = block_data[0] | (block_data[1] << 8);
        
        cout << "  Block " << block << ":\n";
        cout << "    Scale: 0x" << hex << scale << dec;
        
        // Check if scale looks reasonable
        uint16_t exp = (scale >> 10) & 0x1F;
        if (exp == 0) cout << " (subnormal)";
        else if (exp == 31) cout << " (inf/nan)";
        else cout << " (normal)";
        cout << "\n";
        
        // Show first few weight bytes
        cout << "    Weights: ";
        for (int i = 2; i < 6; i++) {
            cout << hex << setw(2) << (int)block_data[i] << " ";
        }
        cout << dec << "...\n";
    }
    
    return 0;
}
