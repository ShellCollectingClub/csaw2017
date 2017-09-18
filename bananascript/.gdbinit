b *0x4074f8
#ignore 1 0x50
#set print elements 0

define setvm
set $r0 = (char *)*((char **)($rsp+0x2e0))
set $r1 = (char *)*((char **)($rsp+0x2c0))
set $r2 = (char *)*((char **)($rsp+0x2a0))
set $r3 = (char *)*((char **)($rsp+0x280))
set $r4 = (char *)*((char **)($rsp+0x260))
set $r5 = (char *)*((char **)($rsp+0x240))
set $r6 = (char *)*((char **)($rsp+0x220))
set $r7 = (char *)*((char **)($rsp+0x200))

set $a0 = (char *)*((char **)($rsp+0x3e0))
set $a1 = (char *)*((char **)($rsp+0x3c0))
set $a2 = (char *)*((char **)($rsp+0x3a0))
set $a3 = (char *)*((char **)($rsp+0x380))
set $a4 = (char *)*((char **)($rsp+0x360))
set $a5 = (char *)*((char **)($rsp+0x340))
set $a6 = (char *)*((char **)($rsp+0x320))
set $a7 = (char *)*((char **)($rsp+0x300))
end

define getvm
echo \n

echo \ line: \ 
x/wx $rsp+0x30

echo \n

echo \ r0: \ 
x/s $r0
echo \ r1: \ 
x/s $r1
echo \ r2: \ 
x/s $r2
echo \ r3: \ 
x/s $r3
echo \ r4: \ 
x/s $r4
echo \ r5: \ 
x/s $r5
echo \ r6: \ 
x/s $r6
echo \ r7: \ 
x/s $r7

echo \n

echo \ a0: \ 
x/s $a0
echo \ a1: \ 
x/s $a1
echo \ a2: \ 
x/s $a2
echo \ a3: \ 
x/s $a3
echo \ a4: \ 
x/s $a4
echo \ a5: \ 
x/s $a5
echo \ a6: \ 
x/s $a6
echo \ a7: \ 
x/s $a7
end

commands 1
setvm
getvm
end

r banana.script
