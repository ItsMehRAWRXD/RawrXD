#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <cstdint>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include "Deep2TrafficAccounting.hpp"

class Deep2StorageRing {
private:
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hIOCP = NULL;
    
    // Dual-slot pinned host memory layout
    struct RingSlot {
        uint8_t* buffer;
        uint64_t bytesReady;
        std::atomic<bool> ready;
        OVERLAPPED overlapped;
    };

    RingSlot slots[2];
    uint64_t slotSizeBytes = 0;
    uint32_t activeComputeSlot = 0;
    uint32_t activeIoSlot = 1;

    // Traffic Accounting
    rawrxd::deep2::SovereignTrafficAccounting* traffic_ = nullptr;

public:
    Deep2StorageRing(const wchar_t* weightShardPath, uint64_t shardSize) 
        : slotSizeBytes(shardSize) {
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
            slots[i].buffer = static_cast<uint8_t*>(VirtualAlloc(NULL, slotSizeBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (!slots[i].buffer) throw std::bad_alloc();
            
            // Hard-lock the allocations to physical system RAM lines
            if (!VirtualLock(slots[i].buffer, slotSizeBytes)) {
                std::cerr << "[!] Warning: VirtualLock failed for slot " << i << ". Proceeding with standard mapping.\n";
            }
            
            slots[i].ready.store(true, std::memory_order_release);
            ZeroMemory(&slots[i].overlapped, sizeof(OVERLAPPED));
        }

        std::cout << "[+] NVMe Direct-DMA Ring Active. Dual " << (slotSizeBytes / (1024 * 1024)) << " MB execution tracks pinned.\n";
    }

    void SetTrafficAccounting(rawrxd::deep2::SovereignTrafficAccounting* accounting) noexcept
    {
        traffic_ = accounting;
    }

    /**
     * Dispatches an asynchronous, non-blocking disk read request straight to physical host RAM.
     */
    void PrimeBackgroundPrefetch(uint64_t sourceFileOffset) {
        RingSlot& slot = slots[activeIoSlot];
        slot.ready.store(false, std::memory_order_release);
        
        ZeroMemory(&slot.overlapped, sizeof(OVERLAPPED));
        slot.overlapped.Offset = static_cast<DWORD>(sourceFileOffset & 0xFFFFFFFF);
        slot.overlapped.OffsetHigh = static_cast<DWORD>((sourceFileOffset >> 32) & 0xFFFFFFFF);

        // Direct kernel file-system bypass trigger to pipe data straight over the PCIe storage bus
        if (!ReadFile(
            hFile,
            slot.buffer,
            static_cast<DWORD>(slotSizeBytes),
            NULL,
            &slot.overlapped
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
        RingSlot& slot = slots[activeIoSlot];

        if (!slot.ready.load(std::memory_order_acquire))
        {
            if (traffic_ != nullptr)
                traffic_->RecordRingStarvation();

            DWORD transferred = 0;
            ULONG_PTR completionKey = 0;
            OVERLAPPED* completedOverlapped = nullptr;

            if (!GetQueuedCompletionStatus(hIOCP, &transferred, &completionKey, &completedOverlapped, INFINITE)) {
                throw std::runtime_error("[-] IOCP Sync Fault: Failed to retrieve I/O completion status.");
            }

            if (completedOverlapped != nullptr && traffic_ != nullptr)
            {
                traffic_->RecordNvmeReadCompletion(static_cast<uint64_t>(transferred));
            }
            
            slot.ready.store(true, std::memory_order_release);
        }

        // Atomic toggle swaps active processing paths
        std::swap(activeComputeSlot, activeIoSlot);
    }

    uint8_t* GetActiveComputePointer() const {
        return slots[activeComputeSlot].buffer;
    }

    ~Deep2StorageRing() {
        for (int i = 0; i < 2; ++i) {
            if (slots[i].buffer) {
                VirtualUnlock(slots[i].buffer, slotSizeBytes);
                VirtualFree(slots[i].buffer, 0, MEM_RELEASE);
            }
        }
        if (hIOCP) CloseHandle(hIOCP);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }
};
