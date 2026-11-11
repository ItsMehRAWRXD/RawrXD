def calculate_factorial(n):
    """Calculate factorial of n."""
    if n < 0:
        return None
    if n == 0:
        return 1
    result = 1
    for i in range(1, n + 1):
        result *= i
    return result

def main():
    print("Testing factorial function:")
    print(f"5! = {calculate_factorial(5)}")
    print(f"0! = {calculate_factorial(0)}")
    print(f"-1! = {calculate_factorial(-1)}")

if __name__ == "__main__":
    main()