/**
 * @file tensor_raw_inspection.cpp
 * @brief Inspect raw tensor bytes without decoding
 * 
 * Validates we can read the correct data from the file.
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
    
    cout << "🔍 Raw Tensor Data Inspection\n";
    cout << "==============================\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open file\n";
        return 1;
    }
    
    // Read first 256 bytes of tensor data (at offset 0)
    vector<uint8_t> buffer(256);
    file.read(reinterpret_cast<char*>(buffer.data()), 256);
    
    cout << "First 256 bytes of token_embd.weight:\n\n";
    
    // Display as hex dump
    for (int row = 0; row < 16; row++) {
        cout << hex << setw(4) << setfill('0') << (row * 16) << ": ";
        
        // Hex values
        for (int col = 0; col < 16; col++) {
            cout << setw(2) << setfill('0') << (int)buffer[row * 16 + col] << " ";
        }
        
        cout << " |";
        
        // ASCII representation
        for (int col = 0; col < 16; col++) {
            uint8_t c = buffer[row * 16 + col];
            if (c >= 32 && c < 127) {
                cout << (char)c;
            } else {
                cout << ".";
            }
        }
        
        cout << "|\n";
    }
    
    // Interpret first few bytes as different types
    cout << "\n\nInterpretation:\n";
    cout << dec;
    
    // First 2 bytes as uint16 (little endian)
    uint16_t first_u16 = buffer[0] | (buffer[1] << 8);
    cout << "  Bytes 0-1 as uint16: " << first_u16 << "\n";
    
    // First 4 bytes as uint32
    uint32_t first_u32 = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
    cout << "  Bytes 0-3 as uint32: " << first_u32 << "\n";
    
    // First 2 bytes as FP16 (just show raw bits)
    cout << "  Bytes 0-1 as FP16 bits: 0x" << hex << first_u16 << dec << "\n";
    
    // Check if this looks like Q4_0 (18 bytes per block)
    // First 2 bytes should be scale, next 16 bytes weights
    cout << "\n  Q4_0 Block 0 analysis:\n";
    cout << "    Scale (bytes 0-1): 0x" << hex << first_u16 << dec << "\n";
    cout << "    Weights (bytes 2-17): ";
    for (int i = 2; i < 18; i++) {
        cout << hex << setw(2) << setfill('0') << (int)buffer[i];
    }
    cout << dec << "\n";
    
    // Check file size
    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    cout << "\n  File size: " << (file_size / 1024 / 1024) << " MB\n";
    
    // Check if file is actually Q8_0 based on size
    // token_embd.weight: [3072, 32064] = 98,500,608 elements
    // Q4_0: ~52 MB, Q8_0: ~98 MB, F16: ~197 MB
    size_t expected_q4_0 = (3072ULL * 32064 / 32) * 18;  // ~52 MB
    size_t expected_q8_0 = (3072ULL * 32064 / 32) * 34;  // ~98 MB
    size_t expected_f16 = 3072ULL * 32064 * 2;  // ~197 MB
    
    cout << "\n  Expected sizes:\n";
    cout << "    Q4_0: " << (expected_q4_0 / 1024 / 1024) << " MB\n";
    cout << "    Q8_0: " << (expected_q8_0 / 1024 / 1024) << " MB\n";
    cout << "    F16:  " << (expected_f16 / 1024 / 1024) << " MB\n";
    
    // The file is 2075 MB total, tensor data starts at ~726KB
    // So tensor data is ~2074 MB, which is way larger than expected
    // This suggests the file might actually be Q8_0 or the tensor is different
    
    cout << "\n  Note: File name says 'q8_0' but tensor info says Q4_0\n";
    cout << "  This mismatch needs investigation.\n";
    
    return 0;
}
