# Makefile — Build all C tools
# NuRichter · CySec Arsenal
#
# Usage:
#   make all             — build all tools (hardened defaults)
#   make vuln            — build intentionally-vulnerable lab targets
#   make clean
#   make install PREFIX=/usr/local/bin

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDFLAGS =

# Hardened build flags (production-safe tools like hexdump)
HARDENED_FLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE

# Vulnerable lab target flags (intentionally disabled for training)
VULN_FLAGS = -fno-stack-protector -no-pie -z execstack -g

# Output directory
OUT = bin

TARGETS_HARD  = $(OUT)/hexdump
TARGETS_VULN  = $(OUT)/bof_demo $(OUT)/fmt_string $(OUT)/heap_demo $(OUT)/shellcode_runner

.PHONY: all vuln clean install dirs

all: dirs $(TARGETS_HARD)
	@echo ""
	@echo "  ✓ Hardened tools built in $(OUT)/"
	@echo "  Run 'make vuln' to also build intentionally-vulnerable lab targets."
	@echo ""

vuln: dirs $(TARGETS_VULN)
	@echo ""
	@echo "  ⚠ Vulnerable lab targets built in $(OUT)/"
	@echo "  These are INTENTIONALLY INSECURE — use only in isolated lab VMs!"
	@echo ""

dirs:
	@mkdir -p $(OUT)

# ─── Hardened tools ──────────────────────────────────────────────────────────

$(OUT)/hexdump: hexdump/hexdump.c
	$(CC) $(CFLAGS) $(HARDENED_FLAGS) -o $@ $^
	@echo "  [+] Built: $@"

# ─── Vulnerable lab targets ───────────────────────────────────────────────────

$(OUT)/bof_demo: bof_demo/bof_demo.c
	$(CC) $(CFLAGS) $(VULN_FLAGS) -o $@ $^
	@echo "  [!] Built (VULNERABLE): $@"

$(OUT)/fmt_string: fmt_string/fmt_string.c
	$(CC) $(CFLAGS) $(VULN_FLAGS) -o $@ $^
	@echo "  [!] Built (VULNERABLE): $@"

$(OUT)/heap_demo: heap_demo/heap_demo.c
	$(CC) $(CFLAGS) $(VULN_FLAGS) -o $@ $^
	@echo "  [!] Built (VULNERABLE): $@"

$(OUT)/shellcode_runner: shellcode_runner/shellcode_runner.c
	$(CC) $(CFLAGS) $(VULN_FLAGS) -o $@ $^
	@echo "  [!] Built (VULNERABLE): $@"

# ─── ASAN debug builds ────────────────────────────────────────────────────────

asan: dirs
	$(CC) $(CFLAGS) -g -fsanitize=address -o $(OUT)/heap_demo_asan  heap_demo/heap_demo.c
	$(CC) $(CFLAGS) -g -fsanitize=address -o $(OUT)/bof_demo_asan   bof_demo/bof_demo.c
	$(CC) $(CFLAGS) -g -fsanitize=address -o $(OUT)/fmt_string_asan fmt_string/fmt_string.c
	@echo "  [+] ASAN builds in $(OUT)/*_asan"

# ─── Checksec all binaries ────────────────────────────────────────────────────

checksec:
	@which checksec >/dev/null 2>&1 || (echo "Install checksec: apt install checksec" && exit 1)
	@for b in $(OUT)/*; do \
	    echo ""; \
	    checksec --file=$$b; \
	done

clean:
	rm -rf $(OUT)
	@echo "  [+] Cleaned."

install: all
	install -m 755 $(OUT)/hexdump $(PREFIX)/hexdump
	@echo "  [+] Installed hexdump to $(PREFIX)/hexdump"
