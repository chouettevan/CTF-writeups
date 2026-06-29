# Des moustiques ou des abeilles ? — Firmware de la clôture 

## Introduction
In this challenge we are given an arm64 [binary](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/dci_summercamp2026/cloture):
```fish
[I] ✖ 255 DCI_Summer_CAMP ❯❯❯ file cloture
cloture: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=a0ca08e9ecbc351e85a0480b981ca8661b064c99, for GNU/Linux 3.7.0, not stripped
```

## Reverse engineering
When decompiling `main` with angr we see this: 
```c
unsigned int main(void)
{
    unsigned int v4;  // w0
    unsigned int v5;  // w0
    unsigned long long v6;  // x19
    void* v7;  // x0
    char *v0;  // [bp-0x60]
    unsigned long long v1;  // [bp-0x50]
    char v2[64];  // [bp-0x40]
    char v3;  // [bp+0x0]

    v0 = &v3;
    afficher_banner();
    puts("[SYSTEME] Initialisation firmware cloture...");
    puts("[SYSTEME] Secteurs actifs : NORD SUD EST OUEST");
    puts("[SYSTEME] Tension nominale : 220V\n");
    printf("[AUTH] Entrez le code d acces Arcturus : ");
    fflush(stdout);
    if (!fgets(&v2, 64, stdin))
    {
        puts("[ERREUR] Lecture echouee.");
        return 1;
    }
    v4 = strlen(&v2);
    if (v4 > 0)
    {
        v5 = v4 - 1;
        if (v2[v5] == 10)
            v2[v5] = 0;
    }
    if (!(unsigned int)verifier_mot_de_passe(&v2))
    {
        v1 = v6;
        v7 = decode_str(&str_denied, 37);
        printf("\n%s\n", v7);
        free(v7);
        puts("[SYSTEME] Tentative enregistree.");
        return 1;
    }
    afficher_succes();
    return 0;
}
```
The binary  reads some input, performs a check on it and if the
check succeeds if calls `afficher_succes`. This is an ideal task for `angr`.

## Solving
A quick look using radare2 show that `afficher_succes` ends at offset `0xc88`:
```radare2
[0x000008c0]> pdf @ sym.afficher_succes | tail
│           0x00000c64      03ffff97       bl sym.imp.free             ; void free(void *ptr)
│           0x00000c68      e00313aa       mov x0, x19                 ; void *ptr
│           0x00000c6c      01ffff97       bl sym.imp.free             ; void free(void *ptr)
│           0x00000c70      f35341a9       ldp x19, x20, [var_10h]
│           0x00000c74      f55b42a9       ldp x21, x22, [var_20h]
│           0x00000c78      f76343a9       ldp x23, x24, [var_30h]
│           0x00000c7c      f96b44a9       ldp x25, x26, [var_40h]
│           0x00000c80      fb2b40f9       ldr x27, [var_50h]
│           0x00000c84      fd7bc6a8       ldp x29, x30, [sp], 0x60
└           0x00000c88      c0035fd6       ret
```
we can therefore use the following script:
```python
import angr
p = angr.Project("./cloture")

win_addr = p.loader.main_object.min_addr + 0xc88

entry_state = p.factory.entry_state()
simgr = p.factory.simgr()

simgr.explore(find=win_addr)
for state in simgr.found:
    print(state.posix.dumps(0))
    print(state.posix.dumps(1))
```
total solve time: about 2 minutes
