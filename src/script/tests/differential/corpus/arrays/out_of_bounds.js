// Differential Test: Arrays - Out of Bounds
// Tests: Access beyond array length

var arr = [1, 2, 3];
print(arr[100]);
print(arr[-1]);
arr[10] = 10;
print(arr.length);
print(arr[10]);
