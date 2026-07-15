// Differential Test: Objects - Property Deletion
// Tests: delete operator and IC invalidation

var obj = { x: 1, y: 2 };
print(obj.x);
delete obj.x;
print(obj.x);
print(obj.y);
obj.x = 3;
print(obj.x);
