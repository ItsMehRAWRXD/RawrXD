// Differential Test: Functions - Arguments Object
// Tests: Function arguments handling

function sumAll() {
    var sum = 0;
    for (var i = 0; i < arguments.length; i++) {
        sum = sum + arguments[i];
    }
    return sum;
}

print(sumAll());
print(sumAll(1));
print(sumAll(1, 2, 3));
print(sumAll(10, 20, 30, 40));
