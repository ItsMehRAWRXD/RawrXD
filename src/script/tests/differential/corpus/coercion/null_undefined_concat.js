// Differential Test: Coercion - String Concatenation Edge Cases
// Tests: null, undefined, and empty string coercion

print("" + null);
print("" + undefined);
print(null + "hello");
print(undefined + "world");
print("" + "");
print("test" + null + undefined);
