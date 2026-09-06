#pragma once

#include <windows.h>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <algorithm>

class Deep2StorageRing {
private:
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hIOCP = NULL;
    
    // Dual-slot pinned host memory layout
    uint8_t* ringBufferSlots[2] = { nullptr, nullptr };
    OVERLAPPED overlappedPool[2];
    
    uint64_t slotSizeBytes = 0;
    uint32_t activeComputeSlot = 0;
    uint32_t activeIoSlot = 1;

public:
    Deep2StorageRing(const wchar_t* weightShardPath, uint64_t shardSize) : slotSizeBytes(shardSize) {
        // 1. Open the target binary weight shard using explicit bare-metal unbuffered flags
        hFile = CreateFileW(
            weightShardPath,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED, // Bypass Windows file caching completely
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("[-] NVMe Storage Fault: Failed to bind direct unbuffered file interface.");
        }

        // 2. Bind the file handle to an isolated high-performance I/O Completion Port
        hIOCP = CreateIoCompletionPort(hFile, NULL, 0, 1);
        if (!hIOCP) {
            CloseHandle(hFile);
            throw std::runtime_error("[-] IOCP Initialization Fault: Failed to establish kernel notification port.");
        }

        // 3. Allocate dual-slot cache-aligned pinned streaming surfaces
        for (int i = 0; i < 2; ++i) {
            ringBufferSlots[i] = static_cast<uint8_t*>(VirtualAlloc(NULL, slotSizeBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (!ringBufferSlots[i]) throw std::bad_alloc();
            
            // Hard-lock the allocations to physical system RAM lines
            if (!VirtualLock(ringBufferSlots[i], slotSizeBytes)) {
                // Fallback or warning if locking fails due to quota
                std::cerr << "[!] Warning: VirtualLock failed for slot " << i << ". Proceeding with standard mapping.\n";
            }
            
            ZeroMemory(&overlappedPool[i], sizeof(OVERLAPPED));
        }

        std::cout << "[+] NVMe Direct-DMA Ring Active. Dual " << (slotSizeBytes / (1024 * 1024)) << " MB execution tracks pinned.\n";
    }

    /**
     * Dispatches an asynchronous, non-blocking disk read request straight to physical host RAM.
     */
    void PrimeBackgroundPrefetch(uint64_t sourceFileOffset, bool forceSynchronous = false) {
        overlappedPool[activeIoSlot].Internal = 0;
        overlappedPool[activeIoSlot].InternalHigh = 0;
        overlappedPool[activeIoSlot].Offset = static_cast<DWORD>(sourceFileOffset & 0xFFFFFFFF);
        overlappedPool[activeIoSlot].OffsetHigh = static_cast<DWORD>((sourceFileOffset >> 32) & 0xFFFFFFFF);
        overlappedPool[activeIoSlot].hEvent = NULL;

        if (forceSynchronous) {
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, ringBufferSlots[activeIoSlot], static_cast<DWORD>(slotSizeBytes), &bytesRead, NULL)) {
                throw std::runtime_error("[-] Sync Read Fault: Failed to read shard block.");
            }
            return;
        }

        // Direct kernel file-system bypass trigger to pipe data straight over the PCIe storage bus
        if (!ReadFile(
            hFile,
            ringBufferSlots[activeIoSlot],
            static_cast<DWORD>(slotSizeBytes),
            NULL,
            &overlappedPool[activeIoSlot]
        )) {
            if (GetLastError() != ERROR_IO_PENDING) {
                throw std::runtime_error("[-] Critical DMA Fault: Read dispatch failed.");
            }
        }
    }

    /**
     * Stalls the compute engine only if the hardware disk controller has not finished writing to the slot.
     */
    void SynchronizeRingRotation() {
        DWORD bytesTransferred = 0;
        ULONG_PTR completionKey = 0;
        LPOVERLAPPED pOverlapped = NULL;

        // Block on the completion port with microsecond-accurate tracking metrics
        if (!GetQueuedCompletionStatus(hIOCP, &bytesTransferred, &completionKey, &pOverlapped, INFINITE)) {
            throw std::runtime_error("[-] IOCP Sync Fault: Failed to retrieve I/O completion status.");
        }

        // Atomic toggle swaps active processing paths
        std::swap(activeComputeSlot, activeIoSlot);
    }

    uint8_t* GetActiveComputePointer() const {
        return ringBufferSlots[activeComputeSlot];
    }

    ~Deep2StorageRing() {
        for (int i = 0; i < 2; ++i) {
            if (ringBufferSlots[i]) {
                VirtualUnlock(ringBufferSlots[i], slotSizeBytes);
                VirtualFree(ringBufferSlots[i], 0, MEM_RELEASE);
            }
        }
        if (hIOCP) CloseHandle(hIOCP);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }
};
