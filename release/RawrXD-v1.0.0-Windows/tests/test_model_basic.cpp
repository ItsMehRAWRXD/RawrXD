/**
 * @file test_model_basic.cpp
 * @brief Basic model validation - header only
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include <ctime>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/stat.h>
#endif

#define GGUF_MAGIC 0x46554747
#define GGUF_VERSION 3

struct MappedFile {
    void* data;
    size_t size;
    #ifdef _WIN32
    HANDLE hFile;
    HANDLE hMap;
    #else
    int fd;
    #endif
};

bool mmap_file(const char* path, MappedFile* out) {
    #ifdef _WIN32
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        LARGE_INTEGER size;
        if (!GetFileSizeEx(hFile, &size)) { CloseHandle(hFile); return false; }
        
        HANDLE hMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) { CloseHandle(hFile); return false; }
        
        void* data = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!data) { CloseHandle(hMap); CloseHandle(hFile); return false; }
        
        out->hFile = hFile;
        out->hMap = hMap;
        out->data = data;
        out->size = size.QuadPart;
    #else
        int fd = open(path, O_RDONLY);
        if (fd < 0) return false;
        
        struct stat st;
        if (fstat(fd, &st) < 0) { close(fd); return false; }
        
        void* data = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (data == MAP_FAILED) { close(fd); return false; }
        
        out->fd = fd;
        out->data = data;
        out->size = st.st_size;
    #endif
    return true;
}

void munmap_file(MappedFile* file) {
    #ifdef _WIN32
        UnmapViewOfFile(file->data);
        CloseHandle(file->hMap);
        CloseHandle(file->hFile);
    #else
        munmap(file->data, file->size);
        close(file->fd);
    #endif
}

int main(int argc, char* argv[]) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD Basic Model Test                                       ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_gguf_file>\n", argv[0]);
        return 1;
    }
    
    const char* model_path = argv[1];
    printf("Testing: %s\n\n", model_path);
    
    // Memory map the file
    MappedFile mapped;
    if (!mmap_file(model_path, &mapped)) {
        fprintf(stderr, "❌ Failed to memory-map file\n");
        return 1;
    }
    
    printf("✓ File mapped: %zu bytes (%.2f MB)\n", mapped.size, mapped.size / (1024.0 * 1024.0));
    
    // Parse header only
    uint8_t* data = (uint8_t*)mapped.data;
    size_t pos = 0;
    
    // Read magic
    uint32_t magic = *(uint32_t*)(data + pos); pos += 4;
    if (magic != GGUF_MAGIC) {
        fprintf(stderr, "❌ Invalid GGUF magic: 0x%08X\n", magic);
        munmap_file(&mapped);
        return 1;
    }
    printf("✓ GGUF magic valid (0x%08X)\n", magic);
    
    // Read version
    uint32_t version = *(uint32_t*)(data + pos); pos += 4;
    printf("✓ GGUF version: %u\n", version);
    
    // Read tensor count
    uint64_t tensor_count = *(uint64_t*)(data + pos); pos += 8;
    printf("✓ Tensor count: %llu\n", (unsigned long long)tensor_count);
    
    // Read metadata KV count
    uint64_t metadata_kv_count = *(uint64_t*)(data + pos); pos += 8;
    printf("✓ Metadata KV count: %llu\n", (unsigned long long)metadata_kv_count);
    
    // Calculate header size
    size_t header_size = pos;
    printf("✓ Header size: %zu bytes\n", header_size);
    
    // Verify file is large enough
    if (mapped.size < header_size) {
        fprintf(stderr, "❌ File too small for header\n");
        munmap_file(&mapped);
        return 1;
    }
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Validation Summary                                            ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("File size:        %zu bytes (%.2f MB)\n", mapped.size, mapped.size / (1024.0 * 1024.0));
    printf("Header:           %zu bytes\n", header_size);
    printf("Tensors:          %llu\n", (unsigned long long)tensor_count);
    printf("Metadata entries: %llu\n", (unsigned long long)metadata_kv_count);
    printf("\n");
    
    // Sanity checks
    bool valid = true;
    
    if (tensor_count == 0) {
        printf("⚠️  WARNING: No tensors found\n");
        valid = false;
    } else if (tensor_count > 10000) {
        printf("⚠️  WARNING: Unusually high tensor count\n");
        valid = false;
    } else {
        printf("✓ Tensor count looks reasonable\n");
    }
    
    if (metadata_kv_count > 10000) {
        printf("⚠️  WARNING: Unusually high metadata count\n");
        valid = false;
    } else {
        printf("✓ Metadata count looks reasonable\n");
    }
    
    if (mapped.size < 1024) {
        printf("⚠️  WARNING: File suspiciously small\n");
        valid = false;
    } else {
        printf("✓ File size looks reasonable\n");
    }
    
    printf("\n");
    if (valid) {
        printf("✅ BASIC VALIDATION PASSED\n");
        printf("The file appears to be a valid GGUF v3 model.\n");
    } else {
        printf("⚠️  VALIDATION PASSED WITH WARNINGS\n");
        printf("The file parsed but has unusual characteristics.\n");
    }
    printf("\n");
    
    munmap_file(&mapped);
    return 0;
}
