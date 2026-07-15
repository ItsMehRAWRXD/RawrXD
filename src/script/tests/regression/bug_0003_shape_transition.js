// Regression Test: Bug #0003 - Shape Transition Chain
// Issue: Multiple shape transitions caused IC to point to wrong offset
// Fixed: 2026-07-03
// Test: Multiple property additions should maintain correct offsets

var obj = {};
obj.a = 1;
obj.b = 2;
obj.c = 3;

print(obj.a);
print(obj.b);
print(obj.c);

// Expected output:
// 1
// 2
// 3
