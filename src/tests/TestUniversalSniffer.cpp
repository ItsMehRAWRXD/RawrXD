// ============================================================================
// TestUniversalSniffer - Demonstration of Extension-Agnostic Binary Ingestion
// ============================================================================
// Build: cl TestUniversalSniffer.cpp ..\runtime\UniversalHeaderSniffer.cpp /EHsc /O2
// Run: TestUniversalSniffer.exe <path_to_any_file>
// ============================================================================

#include <iostream>
#include <iomanip>
#include <cstring>
#include "../runtime/UniversalHeaderSniffer.hpp"

using namespace RawrXD;

void PrintHexDump(const void* data, size_t len) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    std::cout << "First 32 bytes: ";
    for (size_t i = 0; i < std::min(len, size_t(32)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(bytes[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    
    // Print as ASCII
    std::cout << "As ASCII:       ";
    for (size_t i = 0; i < std::min(len, size_t(32)); ++i) {
        char c = static_cast<char>(bytes[i]);
        if (c >= 32 && c < 127) {
            std::cout << c;
        } else {
            std::cout << ".";
        }
    }
    std::cout << std::endl;
}

void TestSniffer(const std::string& path) {
    std::cout << "========================================" << std::endl;
    std::cout << "Testing: " << path << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Method 1: Fast file sniff (reads first 64 bytes)
    UniversalHeaderSniffer sniffer;
    FileFormat fmt = sniffer.SniffFile(path);
    
    std::cout << "\n[Fast Sniff Result]" << std::endl;
    std::cout << "  Format: " << sniffer.GetFormatName(fmt) << std::endl;
    std::cout << "  Enum:   " << static_cast<uint32_t>(fmt) << std::endl;
    std::cout << "  Is Tensor: " << (sniffer.IsTensorFormat(fmt) ? "YES" : "NO") << std::endl;
    std::cout << "  Is Binary: " << (sniffer.IsNativeBinary(fmt) ? "YES" : "NO") << std::endl;
    
    // Method 2: Full memory-mapped stream
    MemoryMappedStream stream(path);
    if (!stream.IsValid()) {
        std::cout << "\n[ERROR] Failed to map file" << std::endl;
        return;
    }
    
    std::cout << "\n[Memory-Mapped Stream]" << std::endl;
    std::cout << "  Size: " << stream.Size() << " bytes" << std::endl;
    std::cout << "  Data: " << stream.Data() << std::endl;
    
    // Show hex dump
    std::cout << std::endl;
    PrintHexDump(stream.Data(), stream.Size());
    
    // Re-sniff from mapped memory
    FileFormat fmt2 = sniffer.Sniff(stream.Data(), std::min(stream.Size(), size_t(64)));
    std::cout << "\n[Mapped Sniff Result]" << std::endl;
    std::cout << "  Format: " << sniffer.GetFormatName(fmt2) << std::endl;
    
    // Check for importer
    auto* importer = ImporterRegistry::Instance().FindImporter(fmt2);
    if (importer) {
        std::cout << "  Importer: " << importer->GetName() << std::endl;
    } else {
        std::cout << "  Importer: (none registered)" << std::endl;
    }
    
    // UniversalLoader high-level API
    UniversalLoader loader(path);
    if (loader.IsLoaded()) {
        std::cout << "\n[UniversalLoader]" << std::endl;
        std::cout << "  Detected: " << sniffer.GetFormatName(loader.GetDetectedFormat()) << std::endl;
        std::cout << "  Stream valid: YES" << std::endl;
    }
    
    std::cout << std::endl;
}

void TestSyntheticMagics() {
    std::cout << "========================================" << std::endl;
    std::cout << "Testing Synthetic Magic Numbers" << std::endl;
    std::cout << "========================================" << std::endl;
    
    UniversalHeaderSniffer sniffer;
    
    // Test various magic numbers
    struct TestCase {
        const char* name;
        uint8_t data[8];
        size_t len;
        FileFormat expected;
    };
    
    TestCase tests[] = {
        {"GGUF", {'G','G','U','F',0,0,0,0}, 8, FileFormat::GGUF},
        {"GGML", {'G','G','M','L',0,0,0,0}, 8, FileFormat::GGML},
        {"PE (MZ)", {'M','Z',0,0,0,0,0,0}, 8, FileFormat::PE32},
        {"ELF", {0x7F,'E','L','F',0,0,0,0}, 8, FileFormat::ELF},
        {"ZIP", {'P','K',0x03,0x04,0,0,0,0}, 8, FileFormat::ZIP},
        {"GZIP", {0x1F,0x8B,0,0,0,0,0,0}, 8, FileFormat::GZIP},
        {"Raw Float32", {'R','A','W','F',0,0,0,0}, 8, FileFormat::RawFloat32},
        {"Raw Float16", {'R','A','W','H',0,0,0,0}, 8, FileFormat::RawFloat16},
        {"Raw Int8", {'R','A','W','B',0,0,0,0}, 8, FileFormat::RawInt8},
        {"Encrypted", {'R','A','D','E',0,0,0,0}, 8, FileFormat::Encrypted},
        {"VM Bytecode", {'R','A','V','M',0,0,0,0}, 8, FileFormat::CustomVM},
        {"Unknown", {0,0,0,0,0,0,0,0}, 8, FileFormat::Unknown},
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test : tests) {
        FileFormat detected = sniffer.Sniff(test.data, test.len);
        bool ok = (detected == test.expected);
        
        std::cout << "  " << (ok ? "[PASS]" : "[FAIL]") 
                  << " " << std::left << std::setw(15) << test.name
                  << " -> " << sniffer.GetFormatName(detected) << std::endl;
        
        if (ok) passed++; else failed++;
    }
    
    std::cout << "\nResults: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << std::endl;
}

void PrintUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <file1> [file2] ..." << std::endl;
    std::cout << "       " << prog << " --test (run synthetic magic tests)" << std::endl;
    std::cout << std::endl;
    std::cout << "Universal Header Sniffer - detects file types by magic numbers," << std::endl;
    std::cout << "completely ignoring file extensions." << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::cout << "RawrXD Universal Header Sniffer" << std::endl;
    std::cout << "Extension is dead. Long live the byte stream." << std::endl;
    std::cout << std::endl;
    
    if (std::strcmp(argv[1], "--test") == 0) {
        TestSyntheticMagics();
        return 0;
    }
    
    // Test each file
    for (int i = 1; i < argc; ++i) {
        TestSniffer(argv[i]);
    }
    
    // Show registered importers
    std::cout << "========================================" << std::endl;
    std::cout << "Registered Importers" << std::endl;
    std::cout << "========================================" << std::endl;
    auto importers = ImporterRegistry::Instance().ListImporters();
    if (importers.empty()) {
        std::cout << "  (none - implement IModelImporter and register)" << std::endl;
    } else {
        for (const auto& name : importers) {
            std::cout << "  - " << name << std::endl;
        }
    }
    std::cout << std::endl;
    
    return 0;
}
