/*
 * Stack Overflow Challenge - Level 2
 * Requires overwriting a local variable to change program flow
 *
 * Vulnerability: Buffer overflow to modify local variable
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 32

void print_flag() {
    printf("\n[+] ACCESS GRANTED!\n");
    printf("[+] FLAG{st4ck_sm4sh1ng_succ3ss}\n\n");
    fflush(stdout);
}

int main() {
    int authenticated = 0;  // Target variable to overflow
    char password[BUFFER_SIZE];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║     AUTHENTICATION BYPASS CHALLENGE          ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Objective: Bypass authentication without    ║\n");
    printf("║             knowing the password             ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Hints:                                      ║\n");
    printf("║  - Buffer size: %d bytes                     ║\n", BUFFER_SIZE);
    printf("║  - authenticated var is AFTER buffer        ║\n");
    printf("║  - Overflow to set authenticated != 0        ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    printf("\nPassword: ");
    fflush(stdout);

    // VULNERABLE: gets() has no bounds checking
    // This allows overflowing into 'authenticated' variable
    gets(password);  // Never use gets() in real code!

    // Debug info
    printf("\n[DEBUG] authenticated = 0x%08x\n", authenticated);

    if (authenticated) {
        print_flag();
    } else {
        printf("\n[-] ACCESS DENIED\n");
        printf("[-] Wrong password!\n\n");
    }

    return 0;
}
