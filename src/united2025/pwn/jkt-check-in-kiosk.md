# JKT Check-in KiosK



The challenge includes a [zip](https://github.com/chouettevan/CTF-writeups/blob/main/assets/united2025/pwn/src.zip) file containing a binary,as well as its libc and ld.so versions.

## 1 . Reverse engineering
using radare2, we can see the main challenge binary has the follwing functions:
```
[0x00401410]> afl
0x004010e0    1     11 sym.imp.puts
0x004010f0    1     11 sym.imp.fread
0x00401100    1     11 sym.imp.close
0x00401110    1     11 sym.imp.read
0x00401120    1     11 sym.imp.fgets
0x00401130    1     11 sym.imp.malloc
0x00401140    1     11 sym.imp.fflush
0x00401150    1     11 sym.imp.setvbuf
0x00401160    1     11 sym.imp.open
0x00401170    1     11 sym.imp.fopen
0x00401180    1     11 sym.imp.fwrite
0x00401410    1     46 entry0
0x00401450    4     31 sym.deregister_tm_clones
0x00401480    4     49 sym.register_tm_clones
0x004014c0    3     32 entry.fini0
0x004014f0    1      6 entry.init0
0x00401570    1      5 sym.__libc_csu_fini
0x00401578    1     13 sym._fini
0x00401500    4    101 sym.__libc_csu_init
0x00401440    1      5 sym._dl_relocate_static_pie
0x00401190   18    607 main
0x00401000    3     27 sym._init
0x00401030    2     28 fcn.00401030
0x00401040    1     15 fcn.00401040
0x00401050    1     15 fcn.00401050
0x00401060    1     15 fcn.00401060
0x00401070    1     15 fcn.00401070
0x00401080    1     15 fcn.00401080
0x00401090    1     15 fcn.00401090
0x004010a0    1     15 fcn.004010a0
0x004010b0    1     15 fcn.004010b0
0x004010c0    1     15 fcn.004010c0
0x004010d0    1     15 fcn.004010d0
```

Carefully reading main reveals that it is possible to ovewrite a FILE struct:
```
│ ────────> 0x00401358      488d35250f..   lea rsi, [0x00402284]       ; "r" ; const char *mode
│    ╎╎╎╎   0x0040135f      488d3d230f..   lea rdi, str._dev_null      ; 0x402289 ; "/dev/null" ; const char *filename
│    ╎╎╎╎   0x00401366      e805feffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
│    ╎╎╎╎   0x0040136b      bf00010000     mov edi, 0x100              ; 256 ; size_t size
│    ╎╎╎╎   0x00401370      4989c4         mov r12, rax
│    ╎╎╎╎   0x00401373      e8b8fdffff     call sym.imp.malloc         ;  void *malloc(size_t size)
│    ╎╎╎╎   0x00401378      488d3d390d..   lea rdi, str._Borne__Veuillez_insrer_votre_carte_dembarquement_: ; 0x4020b8 ; "[Borne] Veuillez ins\u00e9rer votre carte d\u2019embarquement :" ; const char *s
│    ╎╎╎╎   0x0040137f      4989c5         mov r13, rax
│    ╎╎╎╎   0x00401382      e859fdffff     call sym.imp.puts           ; int puts(const char *s)
│    ╎╎╎╎   0x00401387      4c89e6         mov rsi, r12                ; void *buf
│    ╎╎╎╎   0x0040138a      bae0010000     mov edx, 0x1e0              ; 480 ; size_t nbyte
│    ╎╎╎╎   0x0040138f      31ff           xor edi, edi                ; int fildes
│    ╎╎╎╎   0x00401391      e87afdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│    ╎╎╎╎   0x00401396      488d3d5b0d..   lea rdi, str._Imprimante__Impression_de_la_carte_dembarquement_en_cours... ; 0x4020f8 ; "[Imprimante] Impression de la carte d\u2019embarquement en cours..." ; const char *s
│    ╎╎╎╎   0x0040139d      e83efdffff     call sym.imp.puts           ; int puts(const char *s)
│    ╎╎╎╎   0x004013a2      4c89e1         mov rcx, r12                ; FILE *stream
│    ╎╎╎╎   0x004013a5      ba01000000     mov edx, 1                  ; size_t nmemb
│    ╎╎╎╎   0x004013aa      4c89ef         mov rdi, r13                ; void *ptr
│    ╎╎╎╎   0x004013ad      be01000000     mov esi, 1                  ; size_t size
│    ╎╎╎╎   0x004013b2      e839fdffff     call sym.imp.fread          ; size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
│    └────< 0x004013b7      e906feffff     jmp 0x4011c2
```
This code can be reached by selecting option number 1.
There are,however, other parts of the code which are even more interesting:\\
```
                              │ ; [0x404040:1]=0                    │
                                       ││                                                                                 │ movzx eax, byte [obj.is_premium]    │
                                       ││                                                                                 │ test al, al                         │
                                       ││                                                                                 │ je 0x4013e2                         │
                                       ││                                                                                 └─────────────────────────────────────┘
                                       ││                                                                                         f t
                                       ││                                                                                         │ │
                                       ││                                                                                         │ │
                                       ││                                                                                         │ │
                                       ││                                                                                         │ │
                                       ││                                                                                         │ │
                                       ││                                                                                         │ └───────────────┐
                                       ││         ┌───────────────────────────────────────────────────────────────────────────────┘                 │
                                       ││         │                                                                                                 │
                                       ││         │                                                                                                 │
                                       ││     ┌─────────────────────────────────────────────────────────────────────────────────────────────┐   ┌───────────────────────────────────────────────────────────────────
                                       ││     │  0x401261 [om]                                                                              │   │  0x4013e2 [oAb]
                                       ││     │ ; const char *s                                                                             │   │ ; const char *s
                                       ││     │ ; 0x402190                                                                                  │   │ ; CODE XREF from main @ 0x40125b(x)
                                       ││     │ ; "[Imprimante] Code de surclassement d\u00e9tect\u00e9 sur la carte d\u2019embarquement :" │   │ ; 0x402140
                                       ││     │ lea rdi, str._Imprimante__Code_de_surclassement_dtect_sur_la_carte_dembarquement_:          │   │ ; "[Imprimante] Classe \u00c9conomie uniquement \u2014 pas de surc
                                       ││     │ ; int puts(const char *s)                                                                   │   │ lea rdi, str._Imprimante__Classe_conomie_uniquement__pas_de_surcla
                                       ││     │ call sym.imp.puts;[oc]                                                                      │   │ ; int puts(const char *s)
                                       ││     │ ; int oflag                                                                                 │   │ call sym.imp.puts;[oc]
                                       ││     │ xor esi, esi                                                                                │   │ jmp 0x4011c2
                                       ││     │ ; const char *path                                                                          │   └───────────────────────────────────────────────────────────────────
                                       ││     │ ; 0x402293                                                                                  │       v
                                       ││     │ ; "/tmp/flag.txt"                                                                           │       │
                                       ││     │ lea rdi, str._tmp_flag.txt                                                                  │       │
                                       ││     │ xor eax, eax                                                                                │       │
                                       ││     │ ; int open(const char *path, int oflag)                                                     │       │
                                       ││     │ call sym.imp.open;[ol]                                                                      │       │
                                       ││     │ mov r12d, eax                                                                               │       │
                                       ││     │ test eax, eax                                                                               │       │
                                       ││     │ js 0x4013f3                                                                                 │       │
                                       ││     └─────────────────────────────────────────────────────────────────────────────────────────────┘       │
                                       ││             f t                                                                                           │
                                       ││             │ │                                                                                           │
                                       ││             │ └──────────────────────────────────────────────┐                                            │
                                       ││    ┌────────┘                                                │                                            │
                                       ││    │                                                         │                                            └───────────────────────────────────────────────────────────────
                                       ││    │                                                         │
                                       ││┌─────────────────────────────────────────────────────┐   ┌─────────────────────────────────────┐
                                       │││  0x401288 [op]                                      │   │  0x4013f3 [oAc]                     │
                                       │││ ; size_t nbyte                                      │   │ ; CODE XREF from main @ 0x401282(x) │
                                       │││ ; '\x7f'                                            │   │ ; [0x404060:8]=0x178000 rsp         │
                                       │││ ; 127                                               │   │ mov qword [obj.win], rbp            │
                                       │││ mov edx, 0x7f                                       │   │ ; 'e'                               │
                                       │││ ; void *buf                                         │   │ ; [0x404068:2]=101                  │
                                       │││ ; 0x404060                                          │   │ ; "e"                               │
                                       │││ lea rsi, obj.win                                    │   │ mov word [0x00404068], 0x65         │
                                       │││ ; int fildes                                        │   │ jmp 0x4011c2                        │
                                       │││ mov edi, eax                                        │   └─────────────────────────────────────┘
                                       │││ ; ssize_t read(int fildes, void *buf, size_t nbyte) │       v
                                       │││ call sym.imp.read;[on]                              │       │
```
for instance, this snippet of code, which is the code for option number 2, reads the flag into memory. however, it requires `obj.is_premimum` to be set to 1 to run

We then have the following code:
```
                                                           │ ; CODE XREF from main @ 0x40123a(x)                              │        │   │││││
                                                                 │ ; "w"                                                            │        │   │││││
                                                                 │ lea rsi, [0x004022a1]                                            │        │   │││││
                                                                 │ ; const char *filename                                           │        │   │││││
                                                                 │ ; 0x402289                                                       │        │   │││││
                                                                 │ ; "/dev/null"                                                    │        │   │││││
                                                                 │ lea rdi, str._dev_null                                           │        │   │││││
                                                                 │ ; file*fopen(const char *filename, const char *mode)             │        │   │││││
                                                                 │ call sym.imp.fopen;[os]                                          │        │   │││││
                                                                 │ ; size_t size                                                    │        │   │││││
                                                                 │ ; 256                                                            │        │   │││││
                                                                 │ mov edi, 0x100                                                   │        │   │││││
                                                                 │ mov r12, rax                                                     │        │   │││││
                                                                 │ ;  void *malloc(size_t size)                                     │        │   │││││
                                                                 │ call sym.imp.malloc;[ot]                                         │        │   │││││
                                                                 │ ; const char *s                                                  │        │   │││││
                                                                 │ ; 0x4021e0                                                       │        │   │││││
                                                                 │ ; "[Borne] Entrez le nombre de bagages enregistr\u00e9s :"       │        │   │││││
                                                                 │ lea rdi, str._Borne__Entrez_le_nombre_de_bagages_enregistrs_:    │        │   │││││
                                                                 │ mov r13, rax                                                     │        │   │││││
                                                                 │ ; int puts(const char *s)                                        │        │   │││││
                                                                 │ call sym.imp.puts;[oc]                                           │        │   │││││
                                                                 │ ; size_t nbyte                                                   │        │   │││││
                                                                 │ ; 480                                                            │        │   │││││
                                                                 │ mov edx, 0x1e0                                                   │        │   │││││
                                                                 │ ; void *buf                                                      │        │   │││││
                                                                 │ mov rsi, r12                                                     │        │   │││││
                                                                 │ ; int fildes                                                     │        │   │││││
                                                                 │ xor edi, edi                                                     │        │   │││││
                                                                 │ ; ssize_t read(int fildes, void *buf, size_t nbyte)              │        │   │││││
                                                                 │ call sym.imp.read;[on]                                           │        │   │││││
                                                                 │ ; [0x404040:1]=0                                                 │        │   │││││
                                                                 │ movzx eax, byte [obj.is_premium]                                 │        │   │││││
                                                                 │ test al, al                                                      │        │   │││││
                                                                 │ jne 0x4013bc                                                     │        │   │││││
                                                                 └──────────────────────────────────────────────────────────────────┘        │   │││││
                                                                       t f                                                                   │   │││││
                                                                       │ │                                                                   │   │││││
                                                                       │ │                                                                   │   │││││
                                                                       │ │                                                                   │   │││││
                                                               ┌───────┘ │                                                                   │   │││││
       ┌─────────────────────────────────────────────────────────────────┘                                                                   │   │││││
       │                                                       │                                                                             │   │││││
   ┌──────────────────────────────────────────────────┐    ┌────────────────────────────────────────────────────────────────────────────┐    │   │││││
   │  0x401325 [ov]                                   │    │  0x4013bc [oAa]                                                            │    │   │││││
   │ ; const char *s                                  │    │ ; const char *s                                                            │    │   │││││
   │ ; 0x402218                                       │    │ ; CODE XREF from main @ 0x40131f(x)                                        │    │   │││││
   │ ; "[Borne] Statut : Classe \u00c9conomie."       │    │ ; 0x402240                                                                 │    │   │││││
   │ lea rdi, str._Borne__Statut_:_Classe_conomie.    │    │ ; "[Imprimante] Impression des \u00e9tiquettes bagages Premium..."         │    │   │││││
   │ ; int puts(const char *s)                        │    │ lea rdi, str._Imprimante__Impression_des_tiquettes_bagages_Premium...      │    │   │││││
   │ call sym.imp.puts;[oc]                           │    │ ; int puts(const char *s)                                                  │    │   │││││
   │ jmp 0x4011c2                                     │    │ call sym.imp.puts;[oc]                                                     │    │   │││││
   └──────────────────────────────────────────────────┘    │ ; FILE *stream                                                             │    │   │││││
       v                                                   │ mov rcx, r12                                                               │    │   │││││
       │                                                   │ ; size_t nitems                                                            │    │   │││││
       │                                                   │ ; 256                                                                      │    │   │││││
       │                                                   │ mov edx, 0x100                                                             │    │   │││││
       │                                                   │ ; const void *ptr                                                          │    │   │││││
       │                                                   │ mov rdi, r13                                                               │    │   │││││
       │                                                   │ ; size_t size                                                              │    │   │││││
       │                                                   │ mov esi, 1                                                                 │    │   │││││
       │                                                   │ ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream) │    │   │││││
       │                                                   │ call sym.imp.fwrite;[oz]                                                   │    │   │││││
```
This allow us to overwrite a FILE struct, but unlike option 1, it then uses fwrite insteadof fread. it also requires `obj.is_premium` to be set to 1


