// RawrXD-Script Sample: Objects and Arrays
// Tests object literals, array literals, and member access

// Object literal
var person = {
    name: "John",
    age: 30,
    isStudent: false,
    address: {
        street: "123 Main St",
        city: "Anytown"
    }
};

// Array literal
var numbers = [1, 2, 3, 4, 5];
var mixed = [1, "two", true, null, { x: 1 }];
var empty = [];

// Member access
var personName = person.name;
var personAge = person["age"];
var street = person.address.street;

// Array access
var first = numbers[0];
var last = numbers[numbers.length - 1];

// Array methods (simulated with functions)
function arrayPush(arr, item) {
    arr[arr.length] = item;
    return arr.length;
}

function arrayPop(arr) {
    if (arr.length === 0) return undefined;
    var item = arr[arr.length - 1];
    arr.length = arr.length - 1;
    return item;
}

// Object methods
var calculator = {
    value: 0,
    add: function(n) {
        this.value = this.value + n;
        return this;
    },
    subtract: function(n) {
        this.value = this.value - n;
        return this;
    },
    getValue: function() {
        return this.value;
    }
};

// Constructor function
function Point(x, y) {
    this.x = x;
    this.y = y;
}

Point.prototype.distance = function(other) {
    var dx = this.x - other.x;
    var dy = this.y - other.y;
    return Math.sqrt(dx * dx + dy * dy);
};

// Using constructor
var p1 = new Point(0, 0);
var p2 = new Point(3, 4);
var dist = p1.distance(p2);

// Array iteration
function sumArray(arr) {
    var sum = 0;
    for (var i = 0; i < arr.length; i++) {
        sum = sum + arr[i];
    }
    return sum;
}

// Object iteration
function getKeys(obj) {
    var keys = [];
    for (var key in obj) {
        if (obj.hasOwnProperty(key)) {
            keys.push(key);
        }
    }
    return keys;
}

// Test operations
arrayPush(numbers, 6);
var popped = arrayPop(numbers);
calculator.add(5).subtract(2).add(10);
var calcResult = calculator.getValue();

console.log("Objects and arrays tests complete");
console.log("Person:", personName, personAge);
console.log("Sum:", sumArray(numbers));
console.log("Distance:", dist);
