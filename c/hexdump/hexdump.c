/*
 * hexdump.c — Portable hex dump utility for binary analysis
 * NuRichter · CySec Arsenal
 *
 * Build:
 *   gcc -O2 -o hexdump hexdump.c
 *
 * Usage:
 *   ./hexdump file.bin
 *   ./hexdump file.bin --offset 0x100 --len 256
 *   ./hexdump file.bin --strings          # extract printable strings
 *   cat file.bin | ./hexdump -             # stdin mode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>

#define COLS       16
#define CHUNK_SIZE 4096

static void print_hex_line(uint64_t offset, const uint8_t *row, size_t len) {
    /* Offset */
    printf("  \033[2m%08llx\033[0m  ", (unsigned long long)offset);

    /* Hex bytes — two groups of 8 */
    for (size_t i = 0; i < COLS; i++) {
        if (i == 8) printf(" ");
        if (i < len) {
            uint8_t b = row[i];
            /* Color code: null=dim, printable=white, high=red */
            if (b == 0x00)
                printf("\033[2m%02x\033[0m ", b);
            else if (b >= 0x20 && b < 0x7f)
                printf("\033[97m%02x\033[0m ", b);
            else if (b >= 0x80)
                printf("\033[91m%02x\033[0m ", b);
            else
                printf("\033[93m%02x\033[0m ", b);
        } else {
            printf("   ");
        }
    }

    /* ASCII panel */
    printf(" \033[2m│\033[0m ");
    for (size_t i = 0; i < len; i++) {
        uint8_t b = row[i];
        if (b >= 0x20 && b < 0x7f)
            printf("\033[97m%c\033[0m", b);
        else
            printf("\033[2m.\033[0m");
    }
    /* Pad */
    for (size_t i = len; i < COLS; i++) printf(" ");
    printf(" \033[2m│\033[0m\n");
}

static void hexdump(FILE *f, uint64_t start_off, int64_t max_len) {
    uint8_t  buf[COLS];
    uint64_t offset = start_off;
    int64_t  remaining = max_len < 0 ? INT64_MAX : max_len;

    printf("\n  \033[36m%8s  %-48s  %-16s\033[0m\n", "Offset", "Hex", "ASCII");
    printf("  %s\n", "\033[2m" "────────  "
           "────────────────────────────────────────────────  "
           "────────────────" "\033[0m");

    while (remaining > 0) {
        size_t to_read = (remaining < COLS) ? (size_t)remaining : COLS;
        size_t n = fread(buf, 1, to_read, f);
        if (n == 0) break;
        print_hex_line(offset, buf, n);
        offset    += n;
        remaining -= (int64_t)n;
    }
    printf("\n  \033[32m[+]\033[0m %llu bytes displayed.\n\n",
           (unsigned long long)(offset - start_off));
}

static void extract_strings(FILE *f, size_t min_len) {
    uint8_t buf[CHUNK_SIZE];
    char    current[1024];
    size_t  cur_len  = 0;
    uint64_t offset  = 0;
    uint64_t str_off = 0;

    printf("\n  \033[36mStrings (min-len=%zu):\033[0m\n\n", min_len);

    while (!feof(f)) {
        size_t n = fread(buf, 1, sizeof(buf), f);
        for (size_t i = 0; i < n; i++, offset++) {
            uint8_t b = buf[i];
            if (b >= 0x20 && b < 0x7f && cur_len < sizeof(current) - 1) {
                if (cur_len == 0) str_off = offset;
                current[cur_len++] = (char)b;
            } else {
                if (cur_len >= min_len) {
                    current[cur_len] = '\0';
                    /* Highlight interesting strings */
                    const char *kws[] = {
                        "flag","FLAG","ctf","CTF","password","passwd",
                        "secret","key","token","http://","https://",
                        "/bin/sh","/bin/bash","admin","root",NULL
                    };
                    int interesting = 0;
                    for (int k = 0; kws[k]; k++) {
                        if (strstr(current, kws[k])) { interesting = 1; break; }
                    }
                    if (interesting)
                        printf("  \033[35m[>]\033[0m 0x%08llx  \033[1;97m%s\033[0m\n",
                               (unsigned long long)str_off, current);
                    else
                        printf("  \033[2m    0x%08llx  %s\033[0m\n",
                               (unsigned long long)str_off, current);
                }
                cur_len = 0;
            }
        }
    }
    printf("\n");
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <file|-> [OPTIONS]\n\n"
        "Options:\n"
        "  --offset, -o <hex>   Start offset (default: 0)\n"
        "  --len,    -n <dec>   Number of bytes (default: all)\n"
        "  --strings,-s         Extract printable strings\n"
        "  --min-len,-m <n>     Minimum string length (default: 6)\n"
        "  --help,   -h         Show this help\n\n"
        "Examples:\n"
        "  %s binary.elf\n"
        "  %s binary.elf -o 0x100 -n 64\n"
        "  %s binary.elf --strings\n"
        "  cat data.bin | %s -\n\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    uint64_t start_off = 0;
    int64_t  max_len   = -1;
    int      do_strings = 0;
    size_t   min_str_len = 6;

    const char *filepath = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]); return 0;
        } else if (!strcmp(argv[i], "--strings") || !strcmp(argv[i], "-s")) {
            do_strings = 1;
        } else if ((!strcmp(argv[i], "--offset") || !strcmp(argv[i], "-o")) && i+1 < argc) {
            start_off = strtoull(argv[++i], NULL, 0);
        } else if ((!strcmp(argv[i], "--len") || !strcmp(argv[i], "-n")) && i+1 < argc) {
            max_len = (int64_t)strtoull(argv[++i], NULL, 0);
        } else if ((!strcmp(argv[i], "--min-len") || !strcmp(argv[i], "-m")) && i+1 < argc) {
            min_str_len = (size_t)strtoull(argv[++i], NULL, 0);
        } else if (argv[i][0] != '-') {
            filepath = argv[i];
        }
    }

    if (!filepath) { usage(argv[0]); return 1; }

    FILE *f;
    if (!strcmp(filepath, "-")) {
        f = stdin;
    } else {
        f = fopen(filepath, "rb");
        if (!f) { perror("fopen"); return 1; }
    }

    printf("\n  \033[1;31m[hexdump]\033[0m  NuRichter · CySec Arsenal");
    printf("  \033[2mfile: %s\033[0m\n", filepath);

    if (start_off > 0 && f != stdin) {
        if (fseek(f, (long)start_off, SEEK_SET) != 0) {
            perror("fseek"); fclose(f); return 1;
        }
    }

    if (do_strings)
        extract_strings(f, min_str_len);
    else
        hexdump(f, start_off, max_len);

    if (f != stdin) fclose(f);
    return 0;
}
