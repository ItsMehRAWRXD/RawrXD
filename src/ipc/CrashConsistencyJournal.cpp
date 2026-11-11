/*===========================================================================
 * CrashConsistencyJournal.cpp
 * VAL-028.5: Crash Consistency Gate - Implementation
 * 
 * Write-ahead journaling for spill recovery.
 *===========================================================================*/

#include "CrashConsistencyJournal.h"
#include <stdio.h>
#include <string.h>

/*===========================================================================
 * CRC32 HELPER
 *===========================================================================*/
static uint32_t CRC32(const void* data, size_t size) {
    // Simple CRC32 implementation
    static const uint32_t crcTable[256] = {
        // Table would be initialized here
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
        // ... (full table omitted for brevity)
    };
    
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t* bytes = (const uint8_t*)data;
    
    for (size_t i = 0; i < size; i++) {
        crc = (crc >> 8) ^ crcTable[(crc ^ bytes[i]) & 0xFF];
    }
    
    return ~crc;
}

/*===========================================================================
 * LIFECYCLE
 *===========================================================================*/

BOOL CCJ_Initialize(CrashConsistencyJournal* journal, const WCHAR* journalPath) {
    if (!journal || !journalPath) {
        return FALSE;
    }
    
    ZeroMemory(journal, sizeof(CrashConsistencyJournal));
    wcsncpy_s(journal->journalPath, MAX_PATH, journalPath, MAX_PATH - 1);
    
    // Try to open existing journal
    journal->hJournalFile = CreateFileW(
        journalPath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
        nullptr
    );
    
    if (journal->hJournalFile == INVALID_HANDLE_VALUE) {
        // Create new journal
        journal->hJournalFile = CreateFileW(
            journalPath,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
            nullptr
        );
        
        if (journal->hJournalFile == INVALID_HANDLE_VALUE) {
            return FALSE;
        }
        
        // Pre-allocate file
        size_t fileSize = sizeof(JournalHeader) + (CCJ_MAX_ENTRIES * CCJ_ENTRY_SIZE);
        fileSize = (fileSize + CCJ_SECTOR_SIZE - 1) & ~(CCJ_SECTOR_SIZE - 1);
        
        LARGE_INTEGER liSize;
        liSize.QuadPart = fileSize;
        SetFilePointerEx(journal->hJournalFile, liSize, nullptr, FILE_BEGIN);
        SetEndOfFile(journal->hJournalFile);
        
        // Initialize header
        JournalHeader header = {};
        header.magic = CCJ_MAGIC;
        header.version = CCJ_VERSION;
        header.entryCount = 0;
        header.lastSequence = 0;
        header.lastTimestamp = 0;
        header.checksum = CRC32(&header, sizeof(header) - sizeof(header.checksum));
        
        DWORD written;
        SetFilePointerEx(journal->hJournalFile, {0}, nullptr, FILE_BEGIN);
        WriteFile(journal->hJournalFile, &header, sizeof(header), &written, nullptr);
        FlushFileBuffers(journal->hJournalFile);
        
        journal->needsRecovery = false;
    } else {
        // Check if recovery needed
        JournalHeader header;
        DWORD read;
        ReadFile(journal->hJournalFile, &header, sizeof(header), &read, nullptr);
        
        if (header.magic == CCJ_MAGIC && header.version == CCJ_VERSION) {
            // Check for uncommitted entries
            journal->needsRecovery = (header.entryCount > 0);
        } else {
            // Corrupted header, start fresh
            journal->needsRecovery = false;
        }
    }
    
    // Memory-map the journal
    HANDLE hMapping = CreateFileMapping(
        journal->hJournalFile,
        nullptr,
        PAGE_READWRITE,
        0, 0,
        nullptr
    );
    
    if (!hMapping) {
        CloseHandle(journal->hJournalFile);
        return FALSE;
    }
    
    void* base = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    CloseHandle(hMapping);
    
    if (!base) {
        CloseHandle(journal->hJournalFile);
        return FALSE;
    }
    
    journal->header = (JournalHeader*)base;
    journal->entries = (JournalEntry*)((uint8_t*)base + sizeof(JournalHeader));
    journal->nextEntry.store(journal->header->entryCount, std::memory_order_relaxed);
    
    return TRUE;
}

void CCJ_Shutdown(CrashConsistencyJournal* journal) {
    if (!journal) return;
    
    // Flush header
    if (journal->header) {
        FlushViewOfFile(journal->header, sizeof(JournalHeader));
        UnmapViewOfFile(journal->header);
    }
    
    if (journal->hJournalFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(journal->hJournalFile);
        CloseHandle(journal->hJournalFile);
    }
    
    ZeroMemory(journal, sizeof(CrashConsistencyJournal));
}

BOOL CCJ_NeedsRecovery(const CrashConsistencyJournal* journal) {
    if (!journal) return FALSE;
    return journal->needsRecovery;
}

/*===========================================================================
 * JOURNAL OPERATIONS
 *===========================================================================*/

int CCJ_AppendEntry(
    CrashConsistencyJournal* journal,
    uint64_t sequence,
    uint64_t spillOffset,
    uint32_t dataSize,
    uint32_t checksum
) {
    if (!journal || !journal->entries) return -1;
    
    uint32_t index = journal->nextEntry.fetch_add(1, std::memory_order_acq_rel);
    if (index >= CCJ_MAX_ENTRIES) {
        journal->nextEntry.fetch_sub(1, std::memory_order_relaxed);
        return -1; // Journal full
    }
    
    JournalEntry* entry = &journal->entries[index];
    entry->sequence = sequence;
    entry->timestamp = GetTickCount64() * 1000; // Approximate microseconds
    entry->spillOffset = spillOffset;
    entry->dataSize = dataSize;
    entry->checksum = checksum;
    entry->flags = 0;
    entry->reserved = 0;
    
    // Update header
    journal->header->entryCount = index + 1;
    journal->header->lastSequence = sequence;
    journal->header->lastTimestamp = entry->timestamp;
    
    // Flush entry (write-ahead)
    FlushViewOfFile(entry, sizeof(JournalEntry));
    
    InterlockedIncrement64((LONG64*)&journal->stats.entriesWritten);
    
    return (int)index;
}

void CCJ_CommitEntry(CrashConsistencyJournal* journal, int entryIndex) {
    if (!journal || !journal->entries || entryIndex < 0 || entryIndex >= CCJ_MAX_ENTRIES) {
        return;
    }
    
    JournalEntry* entry = &journal->entries[entryIndex];
    entry->flags |= JournalEntry::FLAG_COMMITTED;
    FlushViewOfFile(&entry->flags, sizeof(entry->flags));
}

void CCJ_MarkRecovered(CrashConsistencyJournal* journal, int entryIndex) {
    if (!journal || !journal->entries || entryIndex < 0 || entryIndex >= CCJ_MAX_ENTRIES) {
        return;
    }
    
    JournalEntry* entry = &journal->entries[entryIndex];
    entry->flags |= JournalEntry::FLAG_RECOVERED;
    FlushViewOfFile(&entry->flags, sizeof(entry->flags));
}

/*===========================================================================
 * RECOVERY
 *===========================================================================*/

uint32_t CCJ_RecoverAll(
    CrashConsistencyJournal* journal,
    const WCHAR* spillFilePath,
    void (*recoveredCallback)(const JournalEntry* entry, const void* data, uint32_t size)
) {
    if (!journal || !journal->entries || !recoveredCallback) return 0;
    
    uint32_t recoveredCount = 0;
    
    // Open spill file
    HANDLE hSpill = CreateFileW(
        spillFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
        nullptr
    );
    
    if (hSpill == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    for (uint32_t i = 0; i < journal->header->entryCount; i++) {
        JournalEntry* entry = &journal->entries[i];
        
        // Skip already recovered or corrupted
        if (entry->flags & JournalEntry::FLAG_RECOVERED) continue;
        if (entry->flags & JournalEntry::FLAG_CORRUPTED) continue;
        
        // Read data from spill file
        uint8_t buffer[CCJ_SECTOR_SIZE];
        OVERLAPPED overlapped = {};
        overlapped.Offset = (DWORD)(entry->spillOffset & 0xFFFFFFFF);
        overlapped.OffsetHigh = (DWORD)(entry->spillOffset >> 32);
        
        DWORD read;
        BOOL result = ReadFile(hSpill, buffer, CCJ_SECTOR_SIZE, &read, &overlapped);
        
        if (!result || read < entry->dataSize) {
            entry->flags |= JournalEntry::FLAG_CORRUPTED;
            InterlockedIncrement64((LONG64*)&journal->stats.entriesCorrupted);
            continue;
        }
        
        // Validate checksum
        uint32_t actualChecksum = CRC32(buffer, entry->dataSize);
        if (actualChecksum != entry->checksum) {
            entry->flags |= JournalEntry::FLAG_CORRUPTED;
            InterlockedIncrement64((LONG64*)&journal->stats.entriesCorrupted);
            continue;
        }
        
        // Recovery successful
        recoveredCallback(entry, buffer, entry->dataSize);
        CCJ_MarkRecovered(journal, i);
        
        recoveredCount++;
        InterlockedIncrement64((LONG64*)&journal->stats.entriesRecovered);
        InterlockedAdd64((LONG64*)&journal->stats.bytesRecovered, entry->dataSize);
    }
    
    CloseHandle(hSpill);
    
    // Clear recovery flag
    journal->needsRecovery = false;
    
    return recoveredCount;
}

BOOL CCJ_ValidateEntry(
    const CrashConsistencyJournal* journal,
    int entryIndex,
    const WCHAR* spillFilePath
) {
    if (!journal || !journal->entries || entryIndex < 0 || entryIndex >= CCJ_MAX_ENTRIES) {
        return FALSE;
    }
    
    const JournalEntry* entry = &journal->entries[entryIndex];
    
    // Open spill file
    HANDLE hSpill = CreateFileW(
        spillFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (hSpill == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    // Read and validate
    uint8_t buffer[CCJ_SECTOR_SIZE];
    OVERLAPPED overlapped = {};
    overlapped.Offset = (DWORD)(entry->spillOffset & 0xFFFFFFFF);
    overlapped.OffsetHigh = (DWORD)(entry->spillOffset >> 32);
    
    DWORD read;
    BOOL result = ReadFile(hSpill, buffer, CCJ_SECTOR_SIZE, &read, &overlapped);
    CloseHandle(hSpill);
    
    if (!result || read < entry->dataSize) {
        return FALSE;
    }
    
    uint32_t actualChecksum = CRC32(buffer, entry->dataSize);
    return (actualChecksum == entry->checksum);
}

const JournalEntry* CCJ_GetEntry(const CrashConsistencyJournal* journal, int index) {
    if (!journal || !journal->entries || index < 0 || index >= CCJ_MAX_ENTRIES) {
        return nullptr;
    }
    return &journal->entries[index];
}

/*===========================================================================
 * STATISTICS
 *===========================================================================*/

void CCJ_GetStats(const CrashConsistencyJournal* journal, void* outStats) {
    if (!journal || !outStats) return;
    memcpy(outStats, &journal->stats, sizeof(journal->stats));
}

void CCJ_GetStatusString(const CrashConsistencyJournal* journal, WCHAR* outBuffer, size_t bufferSize) {
    if (!journal || !outBuffer || bufferSize == 0) return;
    
    swprintf_s(outBuffer, bufferSize,
        L"Journal: %llu written, %llu recovered, %llu corrupted",
        journal->stats.entriesWritten,
        journal->stats.entriesRecovered,
        journal->stats.entriesCorrupted
    );
}
