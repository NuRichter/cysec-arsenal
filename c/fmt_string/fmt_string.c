/*
 * fmt_string.c — Format String Vulnerability Demo
 * NuRichter · CySec Arsenal
 *
 * INTENTIONALLY VULNERABLE — educational/CTF training only.
 * Demonstrates: stack leak via %p, arbitrary read via %s, 
 * arbitrary write via %n (classic GOT overwrite technique).
 *
 * Build:
 *   gcc -o fmt_string fmt_string.c -no-pie -fno-stack-protector
 *
 * Challenges:
 *   1. Leak a stack address using format specifiers
 *   2. Read the secret string from the stack
 *   3. Overwrite target_var using %n
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* ─── Globals ────────────────────────────────────────────────────────────── */
int  target_var   = 0xdeadbeef;   /* Overwrite this to 0x1337 to win */
char secret_flag[] = "FLAG{fmt_str_leak_2026}";

/* ─── Level helpers ──────────────────────────────────────────────────────── */
static void win_check(void) {
    if (target_var == 0x1337) {
        puts("\n  [!] target_var overwritten to 0x1337!");
        puts("  [!] YOU WIN: " "FLAG{fmt_write_success_2026}");
        exit(0);
    }
}

/* ─── Level 1: Leak stack values ─────────────────────────────────────────── */
static void level1(void) {
    char buf[256];
    int  canary_like = 0xc0ffee42;    /* canary simulation on stack */
    int  local_key   = 0xfeedface;

    printf("[?] Enter format string: ");
    fflush(stdout);
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    printf("\n[*] Stack layout (64-bit x86):\n");
    printf("    &canary_like = %p  (val: 0x%x)\n", &canary_like, canary_like);
    printf("    &local_key   = %p  (val: 0x%x)\n", &local_key,   local_key);
    printf("    secret_flag  = %p\n", (void*)secret_flag);
    printf("    target_var   = %p  (val: 0x%x)\n", &target_var,  target_var);
    printf("\n[*] Output: ");

    /* VULNERABLE: user-controlled format string */
    printf(buf);
    putchar('\n');

    printf("\n[*] Hint: Try %%p.%%p.%%p.%%p to leak stack addresses\n");
    printf("[*] Hint: Use %%<n>$p to access specific stack offset\n");
}

/* ─── Level 2: Arbitrary read ────────────────────────────────────────────── */
static void level2(void) {
    char buf[256];
    char local_secret[32] = "hidden_stack_value_4321";

    printf("[?] Enter format string (read challenge): ");
    fflush(stdout);
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    printf("\n[*] local_secret is at: %p\n", (void*)local_secret);
    printf("[*] Output: ");

    /* VULNERABLE */
    printf(buf);
    putchar('\n');

    /* Did they read the secret? */
    if (strstr(buf, "%s") || strstr(buf, "$s")) {
        printf("[*] You used %%s — well done! Look for '%s' in output\n", local_secret);
    }
}

/* ─── Level 3: Arbitrary write via %n ────────────────────────────────────── */
static void level3(void) {
    char buf[256];

    printf("[*] target_var is at : %p\n", (void*)&target_var);
    printf("[*] target_var value : 0x%08x  (need 0x00001337 = %d)\n",
           target_var, 0x1337);

    printf("[?] Enter format string (write challenge): ");
    fflush(stdout);
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    /* VULNERABLE */
    printf(buf);
    putchar('\n');

    win_check();
    printf("[-] target_var is still 0x%08x — try harder!\n", target_var);
    printf("[*] Hint: Craft payload that writes 0x1337 chars then uses %%n\n");
    printf("[*] Hint: pwntools fmt_str module can automate this\n");
}

/* ─── Main ───────────────────────────────────────────────────────────────── */
static void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════════════╗\n");
    printf("  ║   Format String Demo — NuRichter CySec Arsenal  ║\n");
    printf("  ║   INTENTIONALLY VULNERABLE — CTF Training       ║\n");
    printf("  ╚══════════════════════════════════════════════════╝\n\n");
    printf("  secret_flag addr : %p\n", (void*)secret_flag);
    printf("  target_var  addr : %p\n", (void*)&target_var);
    printf("  secret_flag val  : (hidden — leak it!)\n\n");
    printf("  Levels:\n");
    printf("    1 — Stack leak   (%%p chains)\n");
    printf("    2 — Arb. read    (%%s with address)\n");
    printf("    3 — Arb. write   (%%n to overwrite target_var)\n\n");
}

int main(int argc, char *argv[]) {
    int level = 1;
    if (argc > 1) level = atoi(argv[1]);

    /* Disable buffering for piped input */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    print_banner();
    printf("  [*] Level %d\n\n", level);

    switch (level) {
        case 1: level1(); break;
        case 2: level2(); break;
        case 3: level3(); break;
        default:
            fprintf(stderr, "Usage: %s [1|2|3]\n", argv[0]);
            return 1;
    }

    return 0;
}
