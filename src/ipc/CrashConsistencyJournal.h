/*===========================================================================
 * CrashConsistencyJournal.h
 * VAL-028.5: Crash Consistency Gate
 * 
 * Write-ahead journaling for spill recovery across process restarts.
 * Ensures committed blocks survive crashes.
 *
 * Journal Format:
 *   [Header] [Entry 1] [Entry 2] ... [Entry N] [Checksum]
 * 
 * Each entry records a spill operation with sequence number,
 * allowing recovery of in-flight data after restart.
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define CCJ_VERSION                     1
#define CCJ_MAGIC                       0x52415752434A4E4CULL  // "RAWRCJNL"
#define CCJ_MAX_ENTRIES                 1024    // Entries per journal file
#define CCJ_SECTOR_SIZE                 4096    // Alignment
#define CCJ_ENTRY_SIZE                  64      // Bytes per entry

/*===========================================================================
 * JOURNAL ENTRY
 * Records a single spill operation
 *===========================================================================*/
struct alignas(64) JournalEntry {
    uint64_t sequence;          // ControlBlock sequence number
    uint64_t timestamp;         // UTC microseconds
    uint64_t spillOffset;       // Offset in spill file
    uint32_t dataSize;          // Actual data bytes
    uint32_t checksum;          // CRC32 of data
    uint16_t flags;             // State flags
    uint16_t reserved;          // Padding
    
    // Flags
    static constexpr uint16_t FLAG_COMMITTED = 0x0001;
    static constexpr uint16_t FLAG_RECOVERED = 0x0002;
    static constexpr uint16_t FLAG_CORRUPTED = 0x0004;
};

static_assert(sizeof(JournalEntry) == 32, "JournalEntry must be 32 bytes");

/*===========================================================================
 * JOURNAL HEADER
 *===========================================================================*/
struct alignas(4096) JournalHeader {
    uint64_t magic;             // CCJ_MAGIC
    uint32_t version;           // CCJ_VERSION
    uint32_t entryCount;        // Number of valid entries
    uint64_t lastSequence;      // Highest sequence number
    uint64_t lastTimestamp;     // Last write time
    uint32_t checksum;          // Header checksum
    uint8_t reserved[4076];     // Padding to sector
};

static_assert(sizeof(JournalHeader) == 4096, "JournalHeader must be sector-aligned");

/*===========================================================================
 * CRASH CONSISTENCY JOURNAL
 *===========================================================================*/
typedef struct CrashConsistencyJournal {
    // File handle
    HANDLE hJournalFile;
    WCHAR journalPath[MAX_PATH];
    
    // Memory-mapped view
    JournalHeader* header;
    JournalEntry* entries;
    
    // State
    std::atomic<uint32_t> nextEntry;
    std::atomic<bool> needsRecovery;
    
    // Statistics
    struct {
        uint64_t entriesWritten;
        uint64_t entriesRecovered;
        uint64_t entriesCorrupted;
        uint64_t bytesRecovered;
    } stats;
    
} CrashConsistencyJournal;

/*===========================================================================
 * LIFECYCLE
 *===========================================================================*/

/* Initialize journal (creates or recovers existing)
 * journalPath: Path to journal file
 * Returns: TRUE on success */
BOOL CCJ_Initialize(CrashConsistencyJournal* journal, const WCHAR* journalPath);

/* Shutdown and flush */
void CCJ_Shutdown(CrashConsistencyJournal* journal);

/* Check if recovery is needed (unclean shutdown detected) */
BOOL CCJ_NeedsRecovery(const CrashConsistencyJournal* journal);

/*===========================================================================
 * JOURNAL OPERATIONS
 *===========================================================================*/

/* Append entry to journal (write-ahead)
 * Must be called BEFORE actual spill operation
 * Returns: entry index, or -1 on failure */
int CCJ_AppendEntry(
    CrashConsistencyJournal* journal,
    uint64_t sequence,
    uint64_t spillOffset,
    uint32_t dataSize,
    uint32_t checksum
);

/* Mark entry as committed (after spill completes) */
void CCJ_CommitEntry(CrashConsistencyJournal* journal, int entryIndex);

/* Mark entry as recovered (after successful recovery) */
void CCJ_MarkRecovered(CrashConsistencyJournal* journal, int entryIndex);

/*===========================================================================
 * RECOVERY
 *===========================================================================*/

/* Recover all uncommitted entries
 * spillFilePath: Path to spill file for validation
 * recoveredCallback: Called for each recovered entry
 * Returns: Number of entries recovered */
uint32_t CCJ_RecoverAll(
    CrashConsistencyJournal* journal,
    const WCHAR* spillFilePath,
    void (*recoveredCallback)(const JournalEntry* entry, const void* data, uint32_t size)
);

/* Validate single entry against spill file */
BOOL CCJ_ValidateEntry(
    const CrashConsistencyJournal* journal,
    int entryIndex,
    const WCHAR* spillFilePath
);

/* Get entry by index */
const JournalEntry* CCJ_GetEntry(const CrashConsistencyJournal* journal, int index);

/*===========================================================================
 * STATISTICS
 *===========================================================================*/

/* Get recovery statistics */
void CCJ_GetStats(const CrashConsistencyJournal* journal, void* outStats);

/* Get human-readable status */
void CCJ_GetStatusString(const CrashConsistencyJournal* journal, WCHAR* outBuffer, size_t bufferSize);

#ifdef __cplusplus
}
#endif
