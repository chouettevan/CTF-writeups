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
```
looking at main and reading the assembly we have the following:
```
            ;-- section..text:
            ; ICOD XREF from entry0 @ 0x401431(r)
┌ 607: int main (int argc, char **argv, char **envp);
│ afv: vars(1:sp[0x30..0x30])
│           0x00401190      f30f1efa       endbr64                     ; [15] -r-x section size 997 named .text
│           0x00401194      4155           push r13
│           0x00401196      31c9           xor ecx, ecx                ; size_t size
│           0x00401198      ba02000000     mov edx, 2                  ; int mode
│           0x0040119d      31f6           xor esi, esi                ; char *buf
│           0x0040119f      4154           push r12
│           0x004011a1      55             push rbp
│           0x004011a2      48bd666c61..   movabs rbp, 0x6b61662d67616c66 ; 'flag-fak'
│           0x004011ac      53             push rbx
│           0x004011ad      4883ec18       sub rsp, 0x18
│           0x004011b1      488b3d682e..   mov rdi, qword [obj.stdout] ; obj.stdout__GLIBC_2.2.5
│                                                                      ; [0x404020:8]=0 ; FILE*stream
│           0x004011b8      488d5c2408     lea rbx, [var_8h]
│           0x004011bd      e88effffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
│           ; XREFS: CODE 0x004012ba  CODE 0x00401331  CODE 0x0040134c  CODE 0x004013b7  CODE 0x004013dd  CODE 0x004013ee  
│           ; XREFS: CODE 0x00401403  
│ ┌┌┌┌┌┌┌─> 0x004011c2      488d3d3f0e..   lea rdi, str._n_Borne_denregistrement__Aroport_Jakarta_ ; 0x402008 ; "\n=== Borne d\u2019enregistrement \u2014 A\u00e9roport Jakarta ===" ; const char *s
│ ╎╎╎╎╎╎╎   0x004011c9      e812ffffff     call sym.imp.puts           ; int puts(const char *s)
│ ╎╎╎╎╎╎╎   0x004011ce      488d3d6b0e..   lea rdi, str.1__Lire_la_carte_dembarquement ; 0x402040 ; "1) Lire la carte d\u2019embarquement" ; const char *s
│ ╎╎╎╎╎╎╎   0x004011d5      e806ffffff     call sym.imp.puts           ; int puts(const char *s)
│ ╎╎╎╎╎╎╎   0x004011da      488d3d870e..   lea rdi, str.2__Surclasser_la_carte_dembarquement ; 0x402068 ; "2) Surclasser la carte d\u2019embarquement" ; const char *s
│ ╎╎╎╎╎╎╎   0x004011e1      e8fafeffff     call sym.imp.puts           ; int puts(const char *s)
│ ╎╎╎╎╎╎╎   0x004011e6      488d3da30e..   lea rdi, str.3__Imprimer_les_tiquettes_bagages ; 0x402090 ; "3) Imprimer les \u00e9tiquettes bagages" ; const char *s
│ ╎╎╎╎╎╎╎   0x004011ed      e8eefeffff     call sym.imp.puts           ; int puts(const char *s)
│ ╎╎╎╎╎╎╎   0x004011f2      488d3d8210..   lea rdi, str.4__Quitter     ; 0x40227b ; "4) Quitter" ; const char *s
│ ╎╎╎╎╎╎╎   0x004011f9      e8e2feffff     call sym.imp.puts           ; int puts(const char *s)
│ ╎╎╎╎╎╎╎   0x004011fe      488d3d8110..   lea rdi, [0x00402286]       ; "> " ; const char *s
│ ╎╎╎╎╎╎╎   0x00401205      e8d6feffff     call sym.imp.puts           ; int puts(const char *s)
│ ╎╎╎╎╎╎╎   0x0040120a      488b3d0f2e..   mov rdi, qword [obj.stdout] ; obj.stdout__GLIBC_2.2.5
│ ╎╎╎╎╎╎╎                                                              ; [0x404020:8]=0 ; FILE *stream
│ ╎╎╎╎╎╎╎   0x00401211      e82affffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│ ╎╎╎╎╎╎╎   0x00401216      488b15132e..   mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│ ╎╎╎╎╎╎╎                                                              ; [0x404030:8]=0 ; FILE *stream
│ ╎╎╎╎╎╎╎   0x0040121d      be08000000     mov esi, 8                  ; int size
│ ╎╎╎╎╎╎╎   0x00401222      4889df         mov rdi, rbx                ; char *s
│ ╎╎╎╎╎╎╎   0x00401225      e8f6feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│ ╎╎╎╎╎╎╎   0x0040122a      4885c0         test rax, rax
│ ────────< 0x0040122d      0f8491000000   je 0x4012c4
│ ╎╎╎╎╎╎╎   0x00401233      0fb6442408     movzx eax, byte [var_8h]
│ ╎╎╎╎╎╎╎   0x00401238      3c33           cmp al, 0x33                ; '3' ; 51
│ ────────< 0x0040123a      0f8498000000   je 0x4012d8
│ ────────< 0x00401240      7f7e           jg 0x4012c0
│ ╎╎╎╎╎╎╎   0x00401242      3c31           cmp al, 0x31                ; '1' ; 49
│ ────────< 0x00401244      0f840e010000   je 0x401358
│ ╎╎╎╎╎╎╎   0x0040124a      3c32           cmp al, 0x32                ; '2' ; 50
│ ────────< 0x0040124c      0f85ee000000   jne 0x401340
│ ╎╎╎╎╎╎╎   0x00401252      0fb605e72d..   movzx eax, byte [obj.is_premium] ; [0x404040:1]=0
│ ╎╎╎╎╎╎╎   0x00401259      84c0           test al, al
│ ────────< 0x0040125b      0f8481010000   je 0x4013e2
│ ╎╎╎╎╎╎╎   0x00401261      488d3d280f..   lea rdi, str._Imprimante__Code_de_surclassement_dtect_sur_la_carte_dembarquement_: ; 0x402190 ; "[Imprimante] Code de surclassement d\u00e9tect\u00e9 sur la carte d\u2019embarquement :" ; const char *s
│ ╎╎╎╎╎╎╎   0x00401268      e873feffff     call sym.imp.puts           ; int puts(const char *s)
│ ╎╎╎╎╎╎╎   0x0040126d      31f6           xor esi, esi                ; int oflag
│ ╎╎╎╎╎╎╎   0x0040126f      488d3d1d10..   lea rdi, str._tmp_flag.txt  ; 0x402293 ; "/tmp/flag.txt" ; const char *path
│ ╎╎╎╎╎╎╎   0x00401276      31c0           xor eax, eax
│ ╎╎╎╎╎╎╎   0x00401278      e8e3feffff     call sym.imp.open           ; int open(const char *path, int oflag)
│ ╎╎╎╎╎╎╎   0x0040127d      4189c4         mov r12d, eax
│ ╎╎╎╎╎╎╎   0x00401280      85c0           test eax, eax
│ ────────< 0x00401282      0f886b010000   js 0x4013f3
│ ╎╎╎╎╎╎╎   0x00401288      ba7f000000     mov edx, 0x7f               ; '\x7f' ; 127 ; size_t nbyte
│ ╎╎╎╎╎╎╎   0x0040128d      488d35cc2d..   lea rsi, obj.win            ; 0x404060 ; void *buf
│ ╎╎╎╎╎╎╎   0x00401294      89c7           mov edi, eax                ; int fildes
│ ╎╎╎╎╎╎╎   0x00401296      e875feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│ ╎╎╎╎╎╎╎   0x0040129b      ba00000000     mov edx, 0
│ ╎╎╎╎╎╎╎   0x004012a0      4489e7         mov edi, r12d               ; int fildes
│ ╎╎╎╎╎╎╎   0x004012a3      4885c0         test rax, rax
│ ╎╎╎╎╎╎╎   0x004012a6      480f48c2       cmovs rax, rdx
│ ╎╎╎╎╎╎╎   0x004012aa      488d15af2d..   lea rdx, obj.win            ; 0x404060
│ ╎╎╎╎╎╎╎   0x004012b1      c6040200       mov byte [rdx + rax], 0
│ ╎╎╎╎╎╎╎   0x004012b5      e846feffff     call sym.imp.close          ; int close(int fildes)
│ └───────< 0x004012ba      e903ffffff     jmp 0x4011c2
..
│  ╎╎╎╎╎╎   ; CODE XREF from main @ 0x401240(x)
│ ────────> 0x004012c0      3c34           cmp al, 0x34                ; '4' ; 52
│ ┌───────< 0x004012c2      757c           jne 0x401340
│ │╎╎╎╎╎╎   ; CODE XREF from main @ 0x40122d(x)
│ ────────> 0x004012c4      4883c418       add rsp, 0x18
│ │╎╎╎╎╎╎   0x004012c8      31c0           xor eax, eax
│ │╎╎╎╎╎╎   0x004012ca      5b             pop rbx
│ │╎╎╎╎╎╎   0x004012cb      5d             pop rbp
│ │╎╎╎╎╎╎   0x004012cc      415c           pop r12
│ │╎╎╎╎╎╎   0x004012ce      415d           pop r13
│ │╎╎╎╎╎╎   0x004012d0      c3             ret
..
│ │╎╎╎╎╎╎   ; CODE XREF from main @ 0x40123a(x)
│ ────────> 0x004012d8      488d35c20f..   lea rsi, [0x004022a1]       ; "w" ; const char *mode
│ │╎╎╎╎╎╎   0x004012df      488d3da30f..   lea rdi, str._dev_null      ; 0x402289 ; "/dev/null" ; const char *filename
│ │╎╎╎╎╎╎   0x004012e6      e885feffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
│ │╎╎╎╎╎╎   0x004012eb      bf00010000     mov edi, 0x100              ; 256 ; size_t size
│ │╎╎╎╎╎╎   0x004012f0      4989c4         mov r12, rax
│ │╎╎╎╎╎╎   0x004012f3      e838feffff     call sym.imp.malloc         ;  void *malloc(size_t size)
│ │╎╎╎╎╎╎   0x004012f8      488d3de10e..   lea rdi, str._Borne__Entrez_le_nombre_de_bagages_enregistrs_: ; 0x4021e0 ; "[Borne] Entrez le nombre de bagages enregistr\u00e9s :" ; const char *s
│ │╎╎╎╎╎╎   0x004012ff      4989c5         mov r13, rax
│ │╎╎╎╎╎╎   0x00401302      e8d9fdffff     call sym.imp.puts           ; int puts(const char *s)
│ │╎╎╎╎╎╎   0x00401307      bae0010000     mov edx, 0x1e0              ; 480 ; size_t nbyte
│ │╎╎╎╎╎╎   0x0040130c      4c89e6         mov rsi, r12                ; void *buf
│ │╎╎╎╎╎╎   0x0040130f      31ff           xor edi, edi                ; int fildes
│ │╎╎╎╎╎╎   0x00401311      e8fafdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│ │╎╎╎╎╎╎   0x00401316      0fb605232d..   movzx eax, byte [obj.is_premium] ; [0x404040:1]=0
│ │╎╎╎╎╎╎   0x0040131d      84c0           test al, al
│ ────────< 0x0040131f      0f8597000000   jne 0x4013bc
│ │╎╎╎╎╎╎   0x00401325      488d3dec0e..   lea rdi, str._Borne__Statut_:_Classe_conomie. ; 0x402218 ; "[Borne] Statut : Classe \u00c9conomie." ; const char *s
│ │╎╎╎╎╎╎   0x0040132c      e8affdffff     call sym.imp.puts           ; int puts(const char *s)
│ │└──────< 0x00401331      e98cfeffff     jmp 0x4011c2
..
│ │ ╎╎╎╎╎   ; CODE XREFS from main @ 0x40124c(x), 0x4012c2(x)
│ └───────> 0x00401340      488d3d5c0f..   lea rdi, str.Choix_invalide. ; 0x4022a3 ; "Choix invalide." ; const char *s
│   ╎╎╎╎╎   0x00401347      e894fdffff     call sym.imp.puts           ; int puts(const char *s)
│   └─────< 0x0040134c      e971feffff     jmp 0x4011c2
..
│    ╎╎╎╎   ; CODE XREF from main @ 0x401244(x)
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
│     ╎╎╎   ; CODE XREF from main @ 0x40131f(x)
│ ────────> 0x004013bc      488d3d7d0e..   lea rdi, str._Imprimante__Impression_des_tiquettes_bagages_Premium... ; 0x402240 ; "[Imprimante] Impression des \u00e9tiquettes bagages Premium..." ; const char *s
│     ╎╎╎   0x004013c3      e818fdffff     call sym.imp.puts           ; int puts(const char *s)
│     ╎╎╎   0x004013c8      4c89e1         mov rcx, r12                ; FILE *stream
│     ╎╎╎   0x004013cb      ba00010000     mov edx, 0x100              ; 256 ; size_t nitems
│     ╎╎╎   0x004013d0      4c89ef         mov rdi, r13                ; const void *ptr
│     ╎╎╎   0x004013d3      be01000000     mov esi, 1                  ; size_t size
│     ╎╎╎   0x004013d8      e8a3fdffff     call sym.imp.fwrite         ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│     └───< 0x004013dd      e9e0fdffff     jmp 0x4011c2
│      ╎╎   ; CODE XREF from main @ 0x40125b(x)
│ ────────> 0x004013e2      488d3d570d..   lea rdi, str._Imprimante__Classe_conomie_uniquement__pas_de_surclassement_possible. ; 0x402140 ; "[Imprimante] Classe \u00c9conomie uniquement \u2014 pas de surclassement possible." ; const char *s
│      ╎╎   0x004013e9      e8f2fcffff     call sym.imp.puts           ; int puts(const char *s)
│      └──< 0x004013ee      e9cffdffff     jmp 0x4011c2
│       ╎   ; CODE XREF from main @ 0x401282(x)
│ ────────> 0x004013f3      48892d662c..   mov qword [obj.win], rbp    ; [0x404060:8]=0
│       ╎   0x004013fa      66c705652c..   mov word [0x00404068], 0x65 ; 'e'
│       ╎                                                              ; [0x404068:2]=0
└       └─< 0x00401403      e9bafdffff     jmp 0x4011c2
```
