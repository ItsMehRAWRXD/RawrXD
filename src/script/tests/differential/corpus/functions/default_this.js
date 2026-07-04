// Differential Test: Functions - Default This Binding
// Tests: 'this' value in different contexts

function showThis() {
    return this;
}

print(typeof showThis());

var obj = {
    method: function() {
        return this;
    }
};
print(obj.method() === obj);
