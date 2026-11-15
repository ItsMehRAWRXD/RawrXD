def add_numbers(a, b):
    return a - b  # BUG: should be +

def test_add():
    assert add_numbers(2, 3) == 5
    print("All tests passed!")
