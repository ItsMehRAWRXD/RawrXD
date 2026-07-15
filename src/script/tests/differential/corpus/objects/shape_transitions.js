// Differential Test: Objects - Shape Transitions
// Tests: IC invalidation on shape change

var obj = { a: 1 };
print(obj.a);
obj.b = 2;
print(obj.a);
print(obj.b);
obj.c = 3;
print(obj.a);
print(obj.b);
print(obj.c);
