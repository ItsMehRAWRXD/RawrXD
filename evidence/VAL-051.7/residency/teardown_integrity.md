# VAL-051.7 — Extra G: Teardown Integrity

## Document Identity
- **Extra:** G
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Requirements

1. **All leases released:** `activeLeaseCount == 0`
2. **All resident mappings released:** `mapCount == unmapCount`
3. **All windows unmapped:** No dangling mappings
4. **Resident bytes = 0:** `currentResidentBytes == 0`
5. **Active leases = 0:** No outstanding borrows
6. **Mapping count balanced:** Every map has matching unmap
7. **Handles closed:** OS file handles closed
8. **Manager destroyed cleanly:** No crashes in destructor
9. **Second teardown does not crash:** Idempotent shutdown
10. **Reinitialize after teardown works:** Can start new session

## Tests

- [ ] Shutdown after successful generation
- [ ] Shutdown after B3 failure
- [ ] Shutdown after residency error
- [ ] Double shutdown (idempotent)
- [ ] Reinitialize after shutdown
- [ ] Leak check: `mapCount == unmapCount`
