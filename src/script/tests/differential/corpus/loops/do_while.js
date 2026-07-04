// Differential Test: Loops - Do While Loop
// Tests: Do-while loop execution (always runs at least once)

var i = 0;
var sum = 0;
do {
    sum = sum + i;
    i = i + 1;
} while (i < 10);
print(sum);

var count = 0;
do {
    count = count + 1;
} while (count < 1);
print(count);
