#include <stdio.h>

void shared_function() {
    // Use libc++ mutex
    printf("Hello from C++ shared library!\n");

    static bool is_initialized = []() {
        printf("Static initialization guard executed.\n");
        return true;
    }();
 
    printf("is_initialized: %d\n", is_initialized);
}
