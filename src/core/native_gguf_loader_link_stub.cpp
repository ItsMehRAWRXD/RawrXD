// Native GGUF Loader Link Stub
// Provides stub implementations for GGUF loader functions

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {

// GGUF Loader initialization
int NativeGGUFLoader_Initialize() {
    return 0; // Success
}

// GGUF Loader cleanup
void NativeGGUFLoader_Cleanup() {
}

// Load GGUF model
int NativeGGUFLoader_Load(const char* path) {
    (void)path;
    return -1; // Not implemented
}

// Unload GGUF model
void NativeGGUFLoader_Unload() {
}

// Get tensor count
size_t NativeGGUFLoader_GetTensorCount() {
    return 0;
}

// Get metadata string
const char* NativeGGUFLoader_GetMetadataString(const char* key) {
    (void)key;
    return nullptr;
}

// Get metadata int
int64_t NativeGGUFLoader_GetMetadataInt(const char* key) {
    (void)key;
    return 0;
}

// Get tensor info
int NativeGGUFLoader_GetTensorInfo(size_t index, char* name, size_t nameSize,
                                     int* type, uint64_t* offset, uint64_t* size) {
    (void)index;
    (void)name;
    (void)nameSize;
    (void)type;
    (void)offset;
    (void)size;
    return -1;
}

// Read tensor data
int NativeGGUFLoader_ReadTensor(const char* name, void* data, size_t size) {
    (void)name;
    (void)data;
    (void)size;
    return -1;
}

} // extern "C"
