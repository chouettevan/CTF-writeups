#  CSGAMES 2026 -- Filp Floppy 2


## The challenge
We receive a program named [floppy2](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/csgames2026/floppy2)
by using `file` on the binary,we are able to see that it is a boot sector

```bash
[I] ◆ floppy ❯❯❯ file floppy2
floppy2: DOS/MBR boot sector
```

# Elementary analysis
Since it is a boot sector, we need `qemu` to execute the file.
We run it via the following command:

```bash
qemu-system-i386 floppy2
```

When we run it, we reasize it is a snake game that hands us one flag byte every time
the player manages to hit the purple square without losing.When the player loses,
the program prints `CSGAME OVER!`.


# Static Analysis
We know that Boot sectors have no header, only 2 magic bytes 510 bytes into the file.
Threrefore,when opening it in radare2, we have to specify the load address manually to
be `0x7c00`, the architecture as `x86` and we specify it is a 16-bit architecture, 
since all x86 processors boot into 16-bit mode

```
[I] ◆ floppy ❯❯❯ r2 -m 0x7c00 floppy2
[0x00007c00]> -e asm.arch=x86
[0x00007c00]> -e asm.bits=16
[0000:7c00]> aaaaa
```

Without symbol names, We look for the `CSGAME OVER!` string in the binary,
so we can identify the function that makes the player lose: further analysis
reveals this function is located at `0x7c5e`

```bash
[0000:7c00]> / CSGAME OVER
0x00007df1 hit1_0 .&Ew& CSGAME OVER!U.
[0000:7c00]> s 0x7df1
[0000:7df1]> ax.
fcn.00007c5e 0x7c5e [DATA:r--] mov si, sub.hit0_0_7df1
[0000:7df1]>
```

Looking at the functions's callsites, we see it only has one: `fcn.00007cc3`

```bash
[0000:7c5e]> s fcn.00007c5e
[0000:7c5e]> ax.
fcn.00007cc3 0x7d26 [CALL:--x] call fcn.00007c5e
DATA 0x7df1 hit0_0
[0000:7c5e]>
```

This functions's callgraph looks as follows:
```bash
[0000:7cc3]> s fcn.00007cc3
[0000:7cc3]> agc
                          ┌────────────────────┐
                          │  fcn.00007cc3      │
                          └────────────────────┘
                                v
                                │
      ┌─────────────────────────│
      │                         └─────────────────────────┐
      │                         │                         │
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│  fcn.00007da6      │    │  fcn.00007d2a      │    │  fcn.00007c5e      │
└────────────────────┘    └────────────────────┘    └────────────────────┘
[0000:7cc3]>
```

It calls three functions: 
- The first one is a simple utility that prints characters to the screen
- The third one has you lose, as we have already identified

What about the second one? What if it made you win?

## Solving the challenge

we notice that if we run the floppy2 with `qemu-system-i386 -s -S floppy2`,
then use remote gdb to place a breakpoint at `0x7cc3`, the breakpoint is hit when we lose:nothing new

However,if at that moment, one runs `set $eip=0x7d2a`,thereby setting the program counter
to the address of the second function in the callgraph, 
the program displays a character from the flag on screen.

We can then repeat the following process to get the flag:
1. Run the game with the breakpoint
2. Lose the game to trigger the breakpoint
3. set the program counter to `0x7d2a`
4. Note the character that gets displayed on screen.
5. Repeat steps 2 through until the entire flag has been obtained



