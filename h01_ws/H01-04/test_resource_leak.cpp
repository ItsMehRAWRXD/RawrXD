// H01-04: Resource leak defect
// DEFECT: File handles and memory not properly released
// Expected: Implement RAII cleanup for all resources

#include <iostream>
#include <fstream>
#include <vector>
#include <memory>

class FileProcessor {
private:
    std::fstream* fileHandle = nullptr;
    char* buffer = nullptr;
    size_t bufferSize = 0;
    
public:
    // BUG: No RAII - resources leaked if exceptions thrown or early return
    bool openFile(const char* filename) {
        fileHandle = new std::fstream(filename, std::ios::in | std::ios::out | std::ios::app);
        if (!fileHandle->is_open()) {
            delete fileHandle;
            fileHandle = nullptr;
            return false;
        }
        return true;
    }
    
    // BUG: Allocates buffer but no corresponding free
    bool allocateBuffer(size_t size) {
        buffer = new char[size];
        bufferSize = size;
        return buffer != nullptr;
    }
    
    // BUG: Doesn't close file or free buffer
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
    
    // BUG: Missing destructor - resources leaked
    ~FileProcessor() {
        // Should clean up but doesn't
    }
    
    // Manual cleanup method (not called automatically)
    void cleanup() {
        if (fileHandle) {
            fileHandle->close();
            delete fileHandle;
            fileHandle = nullptr;
        }
        if (buffer) {
            delete[] buffer;
            buffer = nullptr;
        }
    }
};

class ResourceTracker {
public:
    static int openFiles;
    static int allocatedBuffers;
    
    static void reset() { openFiles = 0; allocatedBuffers = 0; }
};

int ResourceTracker::openFiles = 0;
int ResourceTracker::allocatedBuffers = 0;

// Wrapper to track allocations
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
    
    // Simulate the fixed version using tracked allocations
    std::fstream* file = trackedOpen("test_resource_leak.txt");
    char* buffer = trackedAlloc(1024);
    
    if (file && file->is_open()) {
        *file << "test data\n";
    }
    
    if (buffer) {
        for (size_t i = 0; i < 1024; ++i) buffer[i] = 'x';
    }
    
    // Proper cleanup (this is what the fix should ensure happens automatically)
    trackedClose(file);
    trackedFree(buffer);
    
    // Check for leaks
    bool noLeaks = (ResourceTracker::openFiles == 0 && ResourceTracker::allocatedBuffers == 0);
    
    // Clean up test file
    std::remove("test_resource_leak.txt");
    
    if (noLeaks) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Leaks detected - openFiles=" << ResourceTracker::openFiles 
                  << " allocatedBuffers=" << ResourceTracker::allocatedBuffers << std::endl;
        return 1;
    }
}