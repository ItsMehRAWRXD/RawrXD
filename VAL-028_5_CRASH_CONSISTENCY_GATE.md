# VAL-028.5: Crash Consistency Gate

**Status**: ✅ COMPLETE  
**Date**: 2026-07-19  
**Component**: Storage Engine Reliability  
**Priority**: CRITICAL

---

## Overview

VAL-028.5 implements write-ahead journaling for the spill manager, ensuring committed data survives process crashes. This transforms RawrXD from a volatile inference engine into a **resilient storage engine**.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  WRITE PATH (Before Spill)                                      │
│  1. Append journal entry (write-ahead)                         │
│  2. Execute spill to disk                                       │
│  3. Mark entry committed                                        │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼ (Crash can occur here)
┌─────────────────────────────────────────────────────────────────┐
│  RECOVERY PATH (After Restart)                                  │
│  1. Detect uncommitted entries                                  │
│  2. Validate checksums                                          │
│  3. Replay recovered data                                       │
│  4. Mark entries recovered                                        │
└─────────────────────────────────────────────────────────────────┘
```

## Journal Format

```
┌─────────────────────────────────────────────────────────────────┐
│  SECTOR 0: Journal Header (4096 bytes)                          │
│  ├── magic: 0x52415752434A4E4C ("RAWRCJNL")                   │
│  ├── version: 1                                                 │
│  ├── entryCount: Number of valid entries                       │
│  ├── lastSequence: Highest sequence number                     │
│  └── checksum: Header integrity                                │
├─────────────────────────────────────────────────────────────────┤
│  SECTOR 1-N: Journal Entries (64 bytes each)                  │
│  ├── sequence: ControlBlock sequence number                      │
│  ├── timestamp: UTC microseconds                                │
│  ├── spillOffset: Location in spill file                       │
│  ├── dataSize: Actual data bytes                               │
│  ├── checksum: CRC32 of data                                   │
│  └── flags: COMMITTED | RECOVERED | CORRUPTED                  │
└─────────────────────────────────────────────────────────────────┘
```

## Write-Ahead Protocol

```
Producer:
  1. CCJ_AppendEntry()     // Write journal entry
  2. FlushViewOfFile()     // Ensure entry is durable
  3. IOCP_SpillBuffer()    // Execute spill
  4. CCJ_CommitEntry()     // Mark committed

Crash Detection:
  - Entries with FLAG_COMMITTED = 0 need recovery
  - Entries with FLAG_RECOVERED = 1 already processed
```

## Recovery Process

```cpp
// On restart
if (CCJ_NeedsRecovery(journal)) {
    // Scan uncommitted entries
    CCJ_RecoverAll(journal, spillFile, [](entry, data, size) {
        // Validate checksum
        // Replay to application
        // Mark recovered
    });
}
```

## Test Scenarios

### Scenario 1: Clean Shutdown
- Write data with full commit
- Graceful shutdown
- **Verify**: No recovery needed on restart

### Scenario 2: Crash During Spill
- Write data (journal entry appended)
- Simulate crash before commit
- **Verify**: Recovery detects and replays data

### Scenario 3: Corruption Detection
- Corrupt spill file data
- **Verify**: Checksum mismatch detected, entry flagged

## Files Added

| File | Purpose |
|------|---------|
| `CrashConsistencyJournal.h` | Journal API and structures |
| `CrashConsistencyJournal.cpp` | Write-ahead logging implementation |
| `test_crash_consistency.cpp` | Recovery test harness |
| `VAL-028_5_CRASH_CONSISTENCY_GATE.md` | This documentation |

## Integration with IOCP Spill Manager

```cpp
// Modified spill flow
int CCJ_AppendEntry(journal, sequence, offset, size, checksum);
BOOL result = IOCP_SpillBuffer(mgr, data, size, sequence);
if (result) {
    CCJ_CommitEntry(journal, entryIndex);
}
```

## Success Metrics

| Metric | Target |
|--------|--------|
| Recovery rate | 100% of committed data |
| False positives | 0% |
| Corruption detection | 100% |
| Recovery time | < 5 seconds |

## Next: VAL-029 Memory Fabric

With local storage engine proven, extend to distributed:

```
Node A                    Node B
   |                        |
Journal                 Journal
   |                        |
Spill File              Spill File
   |                        |
   +--------Network---------+
            |
     Shared Tensor Address Space
```

**Repository**: Ready for commit  
**Next**: VAL-029 Distributed Memory Fabric
