// Differential Test: Objects - Prototype Chain
// Tests: Property lookup through prototype

var parent = { x: 1 };
var child = Object.create(parent);
child.y = 2;
print(child.x);
print(child.y);
print(child.z);
