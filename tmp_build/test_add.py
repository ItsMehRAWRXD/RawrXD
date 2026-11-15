def add_numbers(a, b):
    return a + b

def test_add():
    assert add_numbers(2, 3) == 5
    assert add_numbers(-1, 1) == 0
    print("All tests passed!")

if __name__ == "__main__":
    test_add()
