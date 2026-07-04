// Regression Test: Bug #0002 - Negative Zero Division
// Issue: 1 / -0 was returning Infinity instead of -Infinity
// Fixed: 2026-07-03
// Test: Division by negative zero should preserve sign

print(1 / -0);
print(-1 / 0);
print(-1 / -0);

// Expected output:
// -Infinity
// -Infinity
// Infinity
