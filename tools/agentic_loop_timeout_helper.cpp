#include <windows.h>

int main()
{
    // Deliberately exceeds the one-second bridge budget.  The recovery smoke
    // test verifies that the parent terminates this real child process and
    // remains reusable afterward.
    Sleep(5000);
    return 1;
}
