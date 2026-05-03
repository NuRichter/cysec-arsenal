/*
 * heap_demo.c — Heap Exploit Primitives Demo
 * NuRichter · CySec Arsenal
 *
 * INTENTIONALLY VULNERABLE — educational/CTF training only.
 * Demonstrates: Use-After-Free (UAF), double-free, heap overflow.
 *
 * Build:
 *   gcc -o heap_demo heap_demo.c -no-pie -fno-stack-protector
 *   # ASAN build (to see errors clearly):
 *   gcc -o heap_demo_asan heap_demo.c -fsanitize=address -g
 *
 * Levels:
 *   1 — Use-After-Free: read/write freed chunk
 *   2 — Double-Free: free same pointer twice → heap corruption
 *   3 — Heap overflow: overflow one chunk into another
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ─── Object model (simulated vtable — common CTF pattern) ──────────────── */
typedef void (*action_fn)(void);

typedef struct {
    char       name[32];
    int        id;
    action_fn  do_action;   /* function pointer — overwrite target */
} Object;

static void normal_action(void) {
    puts("  [*] Normal action executed.");
}

static void win_action(void) {
    puts("\n  [!] ======================================");
    puts("  [!]  UAF exploit success! win() called!");
    puts("  [!]  FLAG{heap_uaf_pwned_2026}");
    puts("  [!] ======================================\n");
}

/* ─── Level 1: Use-After-Free ────────────────────────────────────────────── */
static void level1_uaf(void) {
    puts("  [*] Level 1: Use-After-Free\n");

    /* Allocate object */
    Object *obj = (Object *)malloc(sizeof(Object));
    strncpy(obj->name, "Player1", sizeof(obj->name)-1);
    obj->id        = 0x41;
    obj->do_action = normal_action;

    printf("  [*] Allocated at : %p\n", (void*)obj);
    printf("  [*] do_action    : %p  (normal_action)\n", (void*)normal_action);
    printf("  [*] win_action   : %p  (target)\n",  (void*)win_action);

    /* Free the object — but keep the pointer! */
    free(obj);
    puts("  [*] Object freed.\n");

    /* Allocate same-size chunk — will get the same address (tcache/fastbin) */
    char *overlap = (char *)malloc(sizeof(Object));
    printf("  [*] New chunk at : %p (same as freed obj? %s)\n",
           (void*)overlap, (overlap == (char*)obj) ? "YES ← UAF!" : "different");

    /* Write win_action's address at the do_action offset */
    uintptr_t win_addr = (uintptr_t)win_action;
    memcpy(overlap + offsetof(Object, do_action), &win_addr, sizeof(uintptr_t));

    /* Invoke do_action via the dangling pointer — UAF */
    puts("  [*] Calling obj->do_action() via dangling pointer...");
    obj->do_action();   /* VULNERABLE: use-after-free */

    free(overlap);
}

/* ─── Level 2: Double-Free ───────────────────────────────────────────────── */
static void level2_doublefree(void) {
    puts("  [*] Level 2: Double-Free\n");

    char *a = (char *)malloc(64);
    char *b = (char *)malloc(64);
    snprintf(a, 64, "chunk_A");
    snprintf(b, 64, "chunk_B");

    printf("  [*] a = %p  (chunk_A)\n", (void*)a);
    printf("  [*] b = %p  (chunk_B)\n", (void*)b);

    free(a);
    puts("  [*] free(a) — ok");
    free(b);
    puts("  [*] free(b) — ok");
    free(a);  /* BUG: double-free */
    puts("  [*] free(a) again — DOUBLE FREE!");
    puts("  [*] Heap metadata is now corrupted.");
    puts("  [*] With tcache double-free, next malloc may return overlapping chunks.");

    /* Demonstrate overlap */
    char *c = (char *)malloc(64);
    char *d = (char *)malloc(64);
    printf("  [*] c = %p\n", (void*)c);
    printf("  [*] d = %p\n", (void*)d);
    if (c == a || d == a) {
        puts("  [!] Overlapping chunk obtained via double-free!");
        puts("  [!] FLAG{heap_doublefree_2026}");
    } else {
        puts("  [*] (ASAN/tcache hardening may prevent direct overlap)");
        puts("  [*] Run without ASAN and with glibc < 2.34 to see raw overlap.");
    }

    free(c);
    free(d);
}

/* ─── Level 3: Heap Overflow ─────────────────────────────────────────────── */
typedef struct {
    char   data[32];
    int    is_admin;      /* overflow target */
    int    user_id;
} UserRecord;

static void level3_overflow(void) {
    puts("  [*] Level 3: Heap Overflow\n");

    UserRecord *victim = (UserRecord *)malloc(sizeof(UserRecord));
    victim->is_admin   = 0;
    victim->user_id    = 1001;
    strncpy(victim->data, "regular_user", 31);

    /* Adjacent allocation for overflow buffer */
    char *buf = (char *)malloc(32);
    printf("  [*] buf    = %p\n", (void*)buf);
    printf("  [*] victim = %p\n", (void*)victim);
    printf("  [*] victim->is_admin = %d  (need 1 to win)\n", victim->is_admin);

    puts("  [?] Enter data for buf (overflow to reach victim->is_admin): ");
    fflush(stdout);

    /* BUG: reads up to 64 bytes into a 32-byte buf on heap */
    fgets(buf, 64, stdin);   /* VULNERABLE: heap overflow */

    printf("  [*] victim->is_admin now = %d\n", victim->is_admin);
    if (victim->is_admin != 0) {
        puts("  [!] is_admin overwritten!");
        puts("  [!] FLAG{heap_overflow_2026}");
    } else {
        puts("  [-] is_admin unchanged. Try longer input or target offset differently.");
    }

    free(buf);
    free(victim);
}

/* ─── Main ───────────────────────────────────────────────────────────────── */
static void print_banner(void) {
    puts("\n  ╔════════════════════════════════════════════════════╗");
    puts("  ║   Heap Exploit Demo — NuRichter CySec Arsenal     ║");
    puts("  ║   INTENTIONALLY VULNERABLE — CTF Training         ║");
    puts("  ╚════════════════════════════════════════════════════╝\n");
    printf("  win_action    : %p\n", (void*)win_action);
    printf("  normal_action : %p\n", (void*)normal_action);
    puts("  Levels: 1=UAF  2=DoubleFree  3=HeapOverflow\n");
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    int level = 1;
    if (argc > 1) level = atoi(argv[1]);

    print_banner();

    switch (level) {
        case 1: level1_uaf();       break;
        case 2: level2_doublefree();break;
        case 3: level3_overflow();  break;
        default:
            fprintf(stderr, "Usage: %s [1|2|3]\n", argv[0]);
            return 1;
    }

    return 0;
}
