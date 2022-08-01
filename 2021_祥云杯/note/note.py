from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']


# def command(index):
#     p.sendlineafter("Choice:\n",str(index))

def add(id,size,content):
    p.sendlineafter("Choice:\n",str(1))
    p.sendafter("Save:",(id))
    p.sendlineafter("Pwd:",str(size))
    p.sendafter("Pwd:",content)
def show(id):
    p.sendlineafter("Choice:\n",str(3))
    p.sendlineafter("Check:\n",str(id))
def delete(id):
    p.sendlineafter("Choice:\n",str(4))
    p.sendlineafter("Delete:\n",str(id))


p = process("./pwdFree")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

gdb.attach(p,"b *0x55555555594d")
#0x555555558060
raw_input()

add('a'*0x10,0x18,'b'*0x18)
# p.recvuntil("Save ID:")




p.interactive()