// Regression Test: Bug #0001 - Property Deletion IC Invalidation
// Issue: IC was not invalidated when property deleted, causing
//        access to stale memory location
// Fixed: 2026-07-03
// Test: Delete property then access should return undefined

var obj = { x: 1 };
print(obj.x);  // IC caches offset for x
delete obj.x;   // Property deleted
print(obj.x);  // Should be undefined, was returning garbage

// Expected output:
// 1
// undefined
