// GGUF Link Stubs - Minimal implementations for test linking
// This file provides stub implementations for GGUF loader tests

#include <cstddef>
#include <cstdint>

// Stub for GGUF loader initialization
extern "C" int GGUFLoader_Initialize() {
    return 0; // Success
}

// Stub for GGUF loader cleanup
extern "C" void GGUFLoader_Cleanup() {
}

// Stub for model loading
extern "C" int GGUFLoader_LoadModel(const char* path) {
    (void)path;
    return -1; // Not implemented in stubs
}

// Stub for model unloading
extern "C" void GGUFLoader_UnloadModel() {
}

// Stub for getting tensor count
extern "C" size_t GGUFLoader_GetTensorCount() {
    return 0;
}

// Stub for getting metadata string
extern "C" const char* GGUFLoader_GetMetadataString(const char* key) {
    (void)key;
    return nullptr;
}

// Stub for getting metadata int
extern "C" int64_t GGUFLoader_GetMetadataInt(const char* key) {
    (void)key;
    return 0;
}

// Stub for tensor info
extern "C" int GGUFLoader_GetTensorInfo(size_t index, char* name, size_t nameSize,
                                         int* type, uint64_t* offset, uint64_t* size) {
    (void)index;
    (void)name;
    (void)nameSize;
    (void)type;
    (void)offset;
    (void)size;
    return -1;
}
