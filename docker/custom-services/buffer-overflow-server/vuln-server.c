/*
 * Vulnerable Server - Buffer Overflow Practice
 * FOR EDUCATIONAL PURPOSES ONLY
 *
 * Vulnerabilities:
 * 1. Stack-based buffer overflow in vulnerable_function()
 * 2. No bounds checking on user input
 * 3. Compiled without stack protection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 64

// This function is the target for ret2win attacks
void secret_function() {
    printf("\n========================================\n");
    printf("  CONGRATULATIONS! You called secret_function!\n");
    printf("  FLAG{buff3r_0v3rfl0w_m4st3r}\n");
    printf("========================================\n\n");
    fflush(stdout);

    // Give a shell for post-exploitation practice
    system("/bin/sh");
}

// Vulnerable function with stack buffer overflow
void vulnerable_function(char *input) {
    char buffer[BUFFER_SIZE];

    // VULNERABLE: strcpy doesn't check bounds!
    // If input > 64 bytes, it will overflow the buffer
    strcpy(buffer, input);

    printf("You entered: %s\n", buffer);
    fflush(stdout);
}

void print_banner() {
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║     VULNERABLE SERVER v1.0                   ║\n");
    printf("║     Buffer Overflow Practice                 ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Target: Overflow the buffer to call         ║\n");
    printf("║          secret_function()                   ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Hints:                                      ║\n");
    printf("║  - Buffer size: %d bytes                     ║\n", BUFFER_SIZE);
    printf("║  - secret_function: %p             ║\n", secret_function);
    printf("║  - Find the offset to overwrite RIP          ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    printf("\nEnter your input: ");
    fflush(stdout);
}

int main() {
    char input[256];

    // Disable buffering for cleaner I/O
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    print_banner();

    // Read user input
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Error reading input\n");
        return 1;
    }

    // Remove newline
    input[strcspn(input, "\n")] = 0;

    // Call vulnerable function
    vulnerable_function(input);

    printf("\nGoodbye!\n");

    return 0;
}
