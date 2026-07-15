// Differential Test: Coercion - Abstract Equality (==)
// Tests: Type coercion in equality comparison
// These are notorious JavaScript edge cases

print([] == []);
print([] == ![]);
print([] + []);
print([] + {});
print({} + []);
print({} + {});

print("" == false);
print("" == 0);
print(0 == false);
print("1" == 1);
print(true == 1);

print(null == undefined);
print(null === undefined);
print(null == 0);
print(undefined == 0);

print(true + true);
print(false == 0);
print(false === 0);
