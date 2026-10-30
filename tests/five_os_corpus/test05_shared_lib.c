// Test 05: Shared library linking - library source
#ifdef _WIN32
#define SHARED_API __declspec(dllexport)
#else
#define SHARED_API __attribute__((visibility("default")))
#endif

SHARED_API int shared_add(int a, int b) {
    return a + b;
}
