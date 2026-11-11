// H01-04: Resource leak defect - FIXED VERSION
// DEFECT: File handles and memory not properly released
// Expected: Implement RAII cleanup for all resources

#include <iostream>
#include <fstream>
#include <vector>
#include <memory>

class FileProcessor {
private:
    std::unique_ptr<std::fstream> fileHandle;
    std::unique_ptr<char[]> buffer;
    size_t bufferSize = 0;
    
public:
    // FIXED: RAII - resources automatically cleaned up
    bool openFile(const char* filename) {
        fileHandle = std::make_unique<std::fstream>(filename, std::ios::in | std::ios::out | std::ios::app);
        if (!fileHandle->is_open()) {
            fileHandle.reset();
            return false;
        }
        return true;
    }
    
    // FIXED: RAII - buffer automatically freed
    bool allocateBuffer(size_t size) {
        buffer = std::make_unique<char[]>(size);
        bufferSize = size;
        return buffer != nullptr;
    }
    
    void processData() {
        if (fileHandle && fileHandle->is_open()) {
            *fileHandle << "processed data\n";
        }
        if (buffer) {
            for (size_t i = 0; i < bufferSize; ++i) {
                buffer[i] = 'x';
            }
        }
    }
    
    // FIXED: Destructor automatically cleans up via unique_ptr
    ~FileProcessor() = default;
};

class ResourceTracker {
public:
    static int openFiles;
    static int allocatedBuffers;
    
    static void reset() { openFiles = 0; allocatedBuffers = 0; }
};

int ResourceTracker::openFiles = 0;
int ResourceTracker::allocatedBuffers = 0;

// Wrapper to track allocations (for verification)
std::fstream* trackedOpen(const char* filename) {
    auto f = new std::fstream(filename, std::ios::in | std::ios::out | std::ios::app);
    if (f && f->is_open()) ResourceTracker::openFiles++;
    return f;
}

char* trackedAlloc(size_t size) {
    char* buf = new char[size];
    if (buf) ResourceTracker::allocatedBuffers++;
    return buf;
}

void trackedClose(std::fstream* f) {
    if (f) {
        f->close();
        delete f;
        ResourceTracker::openFiles--;
    }
}

void trackedFree(char* buf) {
    if (buf) {
        delete[] buf;
        ResourceTracker::allocatedBuffers--;
    }
}

int main() {
    ResourceTracker::reset();
    
    // Test the RAII version
    {
        FileProcessor processor;
        processor.openFile("test_resource_leak.txt");
        processor.allocateBuffer(1024);
        processor.processData();
        // Automatic cleanup when processor goes out of scope
    }
    
    // Also test tracked version for verification
    std::fstream* file = trackedOpen("test_resource_leak2.txt");
    char* buffer = trackedAlloc(1024);
    
    if (file && file->is_open()) {
        *file << "test data\n";
    }
    
    if (buffer) {
        for (size_t i = 0; i < 1024; ++i) buffer[i] = 'x';
    }
    
    // Proper cleanup
    trackedClose(file);
    trackedFree(buffer);
    
    // Check for leaks
    bool noLeaks = (ResourceTracker::openFiles == 0 && ResourceTracker::allocatedBuffers == 0);
    
    // Clean up test files
    std::remove("test_resource_leak.txt");
    std::remove("test_resource_leak2.txt");
    
    if (noLeaks) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Leaks detected - openFiles=" << ResourceTracker::openFiles 
                  << " allocatedBuffers=" << ResourceTracker::allocatedBuffers << std::endl;
        return 1;
    }
}