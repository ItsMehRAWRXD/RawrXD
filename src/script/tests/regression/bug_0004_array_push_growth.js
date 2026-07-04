// Regression Test: Bug #0004 - Array Push Growth
// Issue: Array push beyond capacity caused memory corruption
// Fixed: 2026-07-03
// Test: Multiple pushes should grow array correctly

var arr = [];
for (var i = 0; i < 100; i++) {
    arr.push(i);
}
print(arr.length);
print(arr[0]);
print(arr[99]);

// Expected output:
// 100
// 0
// 99
