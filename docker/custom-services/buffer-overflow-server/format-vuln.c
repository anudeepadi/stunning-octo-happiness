/*
 * Format String Vulnerability Challenge
 * Practice format string attacks
 *
 * Vulnerability: printf(user_input) without format specifier
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Secret value to leak/modify
int secret_value = 0xDEADBEEF;
char flag[] = "FLAG{f0rm4t_str1ng_m4st3r}";

void print_banner() {
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║     FORMAT STRING VULNERABILITY LAB          ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Objectives:                                 ║\n");
    printf("║  1. Leak the secret_value from memory        ║\n");
    printf("║  2. Read the flag from memory                ║\n");
    printf("║  3. Modify secret_value to 0x41414141        ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Hints:                                      ║\n");
    printf("║  - Try %%x, %%p, %%s, %%n format specifiers     ║\n");
    printf("║  - secret_value @ %p                ║\n", &secret_value);
    printf("║  - flag @ %p                        ║\n", flag);
    printf("╚══════════════════════════════════════════════╝\n\n");
    fflush(stdout);
}

void check_secret() {
    if (secret_value == 0x41414141) {
        printf("\n[+] SECRET VALUE MODIFIED!\n");
        printf("[+] %s\n", flag);
        printf("[+] BONUS FLAG: FLAG{f0rm4t_wr1t3_pr1m1t1v3}\n\n");
    }
    fflush(stdout);
}

int main() {
    char buffer[256];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    print_banner();

    while (1) {
        printf("Enter string (or 'quit'): ");
        fflush(stdout);

        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break;
        }

        buffer[strcspn(buffer, "\n")] = 0;

        if (strcmp(buffer, "quit") == 0) {
            break;
        }

        printf("You entered: ");

        // VULNERABLE: printf without format specifier
        // This allows format string attacks!
        printf(buffer);

        printf("\n");
        printf("[DEBUG] secret_value = 0x%08x\n\n", secret_value);

        check_secret();
    }

    printf("Goodbye!\n");
    return 0;
}
