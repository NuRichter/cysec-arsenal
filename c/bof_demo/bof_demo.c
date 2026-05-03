/*
 * bof_demo.c — Intentionally Vulnerable Buffer Overflow Demo
 * NuRichter · CySec Arsenal
 *
 * INTENTIONALLY VULNERABLE — educational/CTF training only.
 * Demonstrates: stack BOF, ret addr overwrite, NX bypass concept.
 *
 * Build (with protections disabled for learning):
 *   gcc -o bof_demo bof_demo.c -fno-stack-protector -no-pie -z execstack
 *   # Enable to study defeat:
 *   gcc -o bof_demo_protected bof_demo.c -fstack-protector-all -pie -z noexecstack
 *
 * Challenge:
 *   1. Find the buffer overflow
 *   2. Overwrite the return address
 *   3. Redirect execution to win()
 *   4. (Advanced) Use ROP chain to call system("/bin/sh")
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ─── Secret function — CTF target ──────────────────────────────────────── */
void win(void) {
    puts("\n[!] ===================================");
    puts("[!]  YOU WIN! Buffer overflow success!");
    puts("[!] ===================================\n");
    /* In a real CTF this would be: system("/bin/sh"); */
    puts("[*] Simulating shell access...");
    puts("[*] FLAG{buffer_overflow_pwned_2026}\n");
    exit(0);
}

/* ─── Vulnerable helper (DO NOT USE IN PRODUCTION) ───────────────────────── */
static void vulnerable_read(void) {
    char buf[64];   /* deliberately small buffer */

    printf("[?] Enter your username: ");
    fflush(stdout);

    /* BUG: gets() has no bounds checking — classic BOF */
    gets(buf);      /* VULNERABLE: overflow this to reach win() */

    printf("[*] Hello, %s!\n", buf);
    printf("[*] Try harder... You need to call win() at: %p\n", (void*)win);
}

/* ─── Level 2: fgets with format string leak ─────────────────────────────── */
static void level2(void) {
    char buf[128];
    char secret[16] = "S3cr3tK3y!";

    printf("[?] Enter a message: ");
    fflush(stdout);
    fgets(buf, sizeof(buf), stdin);

    /* BUG: format string vulnerability */
    printf(buf);    /* VULNERABLE: user controls format string */
    printf("[*] Secret is at stack offset (find it with %%p's)\n");
}

/* ─── Level 3: Integer overflow leading to heap BOF ─────────────────────── */
static void level3(void) {
    unsigned int size;
    printf("[?] Enter allocation size: ");
    scanf("%u", &size);

    /* BUG: integer overflow if size is close to UINT_MAX */
    char *heap_buf = (char *)malloc(size + 1);
    if (!heap_buf) { puts("[-] malloc failed"); return; }

    printf("[?] Enter data: ");
    /* BUG: using size that may have overflowed */
    fread(heap_buf, 1, size, stdin);
    heap_buf[size] = '\0';

    printf("[*] Data: %s\n", heap_buf);
    free(heap_buf);
}

/* ─── Challenge info ─────────────────────────────────────────────────────── */
static void print_info(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════════╗\n");
    printf("  ║    BOF Demo — NuRichter CySec Arsenal        ║\n");
    printf("  ║    INTENTIONALLY VULNERABLE — CTF Training   ║\n");
    printf("  ╚══════════════════════════════════════════════╝\n\n");
    printf("  Addresses (ASLR disabled for demo):\n");
    printf("    win()      : %p\n", (void*)win);
    printf("    main()     : %p\n", (void*)main);
    printf("    level2()   : %p\n", (void*)level2);
    printf("\n  Hints:\n");
    printf("    Level 1: Overflow a 64-byte buffer to overwrite RIP\n");
    printf("             Pattern: python3 -c \"print('A'*72 + '\\xXX\\xXX...')\"\n");
    printf("    Level 2: Format string — try %%p.%%p.%%p.%%p\n");
    printf("    Level 3: Integer overflow on malloc size\n\n");
}

/* ─── Main ───────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    int level = 1;
    if (argc > 1) level = atoi(argv[1]);

    print_info();

    printf("  [*] Running Level %d challenge...\n\n", level);

    switch (level) {
        case 1: vulnerable_read(); break;
        case 2: level2();          break;
        case 3: level3();          break;
        default:
            fprintf(stderr, "Usage: %s [1|2|3]\n", argv[0]);
            return 1;
    }

    puts("\n[-] Returned normally — try again!\n");
    return 0;
}
