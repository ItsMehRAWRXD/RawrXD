"""RawrZ Python math module"""
pi = 3.141592653589793
e = 2.718281828459045

def sqrt(x):
    return x ** 0.5

def pow(x, y):
    return x ** y

def abs(x):
    return x if x >= 0 else -x

def ceil(x):
    return int(x) + (1 if x > int(x) else 0)

def floor(x):
    return int(x)
