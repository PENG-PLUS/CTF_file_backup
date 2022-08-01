from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']


# p = process(["./ld.so.2", "./pwn"], env={"LD_PRELOAD":"./libc.so.6"})
p = process("./pwn")

# ===IO===
def add(idx,size,host):
    p.sendlineafter(">>",str(1))
    p.sendlineafter("idx:",str(idx))
    p.sendlineafter("len:",str(size))
    sleep(0.1)
    p.send(host)

add(0,0xf8-1,'a'*0xf7)

gdb.attach(p)
raw_input()






p.interactive()